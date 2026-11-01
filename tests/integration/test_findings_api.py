"""Integration: findings / reviewer-decision HTTP surface against real PostgreSQL.

Marker: ``integration``. Unlike the offline unit suite in
``tests/unit/test_findings_api.py`` (in-memory fakes), these tests build the
FastAPI app through ``create_app`` with the psycopg repositories over a real
connection pool, then drive it with an ``httpx.ASGITransport`` client.

Tenant isolation is the property under test: every request carries an
explicit ``tenant_id`` and a finding belonging to another tenant must be
indistinguishable from a missing one (404).

Durability: decisions are written to PostgreSQL, so rebuilding the app over
the same pool must still see them (no in-memory state).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import (
    PsycopgFindingRepository,
    PsycopgReviewDecisionRepository,
    RepositoryBundle,
)
from itsm_agent.api.app import create_app
from itsm_agent.api.routes.findings import configure_findings
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.events import IncidentCreated
from itsm_agent.domain.models import Finding, Severity

pytestmark = pytest.mark.integration

SECRET = "test-webhook-secret-0123456789abcdef"

Pool = AsyncConnectionPool[AsyncConnection]


# ---------------------------------------------------------------------------
# Fakes / helpers
# ---------------------------------------------------------------------------


class FakeSink:
    """Minimal ingestion sink; findings tests never post incidents."""

    async def accept_incident(self, event: IncidentCreated) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


def _settings() -> Settings:
    return Settings.model_validate(
        {
            "env": "test",
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "webhook_secret": SECRET,
            "webhook_max_body_bytes": 2048,
            "rate_limit_requests": 100,
            "rate_limit_window_seconds": 60.0,
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )


def _build_app(pool: Pool) -> FastAPI:
    """Compose the API over real psycopg repositories sharing one pool."""
    bundle = RepositoryBundle(pool)
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=bundle.findings,
        review_decisions_repo=bundle.review_decisions,
    )


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


def _finding(tenant_id: UUID, *, title: str) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        finding_type="EXCESSIVE_PRIVILEGE",
        severity=Severity.P1,
        status="OPEN",
        title=title,
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=90,
        outcome="VIOLATION",
    )


async def _seed(findings: PsycopgFindingRepository, tenant_id: UUID, *, title: str) -> Finding:
    """Insert a finding and return the row as stored (upsert may reuse an id)."""
    return await findings.upsert(_finding(tenant_id, title=title))


def _decision_payload(
    *,
    reviewer_id: str = "reviewer-1",
    decision: str = "CONFIRMED",
    rationale: str = "evidence supports the finding",
) -> dict[str, str]:
    return {
        "reviewer_id": reviewer_id,
        "decision": decision,
        "rationale": rationale,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_findings_deps() -> Iterator[None]:
    """Reset the module-level global around every test."""
    configure_findings(None)
    yield
    configure_findings(None)


@pytest.fixture
async def pool(pg_dsn: str) -> AsyncIterator[Pool]:
    """Open a real pool and truncate the tables these tests touch."""
    created = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await created.open()
    try:
        async with created.connection() as conn:
            await conn.execute("TRUNCATE findings, review_decisions CASCADE")
        yield created
    finally:
        await created.close()


# ---------------------------------------------------------------------------
# 1. Tenant-scoped listing
# ---------------------------------------------------------------------------


async def test_list_findings_returns_only_requested_tenant(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")
    a2 = await _seed(findings, tenant_a, title=f"a2-{uuid.uuid4().hex}")
    b1 = await _seed(findings, tenant_b, title=f"b1-{uuid.uuid4().hex}")

    async with _client(_build_app(pool)) as client:
        response = await client.get("/v1/findings", params={"tenant_id": str(tenant_a)})

    assert response.status_code == 200
    rows = response.json()
    assert isinstance(rows, list)
    assert len(rows) == 2
    assert {row["id"] for row in rows} == {str(a1.id), str(a2.id)}
    assert all(row["tenant_id"] == str(tenant_a) for row in rows)
    assert str(b1.id) not in {row["id"] for row in rows}


# ---------------------------------------------------------------------------
# 2. Detail includes an empty decision history
# ---------------------------------------------------------------------------


async def test_get_finding_returns_empty_review_decisions(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a = uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")

    async with _client(_build_app(pool)) as client:
        response = await client.get(f"/v1/findings/{a1.id}", params={"tenant_id": str(tenant_a)})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(a1.id)
    assert body["tenant_id"] == str(tenant_a)
    assert body["severity"] == "P1"
    assert body["outcome"] == "VIOLATION"
    assert body["review_decisions"] == []


# ---------------------------------------------------------------------------
# 3. Cross-tenant reads are 404 in both directions
# ---------------------------------------------------------------------------


async def test_cross_tenant_detail_returns_404(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")
    b1 = await _seed(findings, tenant_b, title=f"b1-{uuid.uuid4().hex}")

    async with _client(_build_app(pool)) as client:
        a_as_b = await client.get(f"/v1/findings/{a1.id}", params={"tenant_id": str(tenant_b)})
        b_as_a = await client.get(f"/v1/findings/{b1.id}", params={"tenant_id": str(tenant_a)})

    assert a_as_b.status_code == 404
    assert b_as_a.status_code == 404


# ---------------------------------------------------------------------------
# 4. Recorded decisions survive an app rebuild (durable, not in-memory)
# ---------------------------------------------------------------------------


async def test_recorded_decision_is_visible_after_app_restart(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a = uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")
    payload = _decision_payload(
        reviewer_id="alice",
        decision="CONFIRMED",
        rationale="evidence pack matches the control gap",
    )

    async with _client(_build_app(pool)) as client:
        posted = await client.post(
            f"/v1/findings/{a1.id}/decisions",
            params={"tenant_id": str(tenant_a)},
            json=payload,
        )
        listed = await client.get(
            f"/v1/findings/{a1.id}/decisions", params={"tenant_id": str(tenant_a)}
        )

    assert posted.status_code == 201
    assert posted.json()["status"] == "recorded"
    assert listed.status_code == 200
    decisions = listed.json()
    assert len(decisions) == 1
    assert decisions[0]["reviewer_id"] == payload["reviewer_id"]
    assert decisions[0]["decision"] == payload["decision"]
    assert decisions[0]["rationale"] == payload["rationale"]

    # Rebuild the app over the SAME pool: the decision must come from
    # PostgreSQL, not from any in-process cache on the first app object.
    async with _client(_build_app(pool)) as restarted:
        after_restart = await restarted.get(
            f"/v1/findings/{a1.id}/decisions", params={"tenant_id": str(tenant_a)}
        )

    assert after_restart.status_code == 200
    durable = after_restart.json()
    assert len(durable) == 1
    assert durable[0]["id"] == decisions[0]["id"]
    assert durable[0]["reviewer_id"] == payload["reviewer_id"]
    assert durable[0]["decision"] == payload["decision"]
    assert durable[0]["rationale"] == payload["rationale"]


# ---------------------------------------------------------------------------
# 5. Cross-tenant decision POST is 404 and writes nothing
# ---------------------------------------------------------------------------


async def test_post_decision_for_other_tenant_returns_404_and_writes_nothing(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")

    async with _client(_build_app(pool)) as client:
        response = await client.post(
            f"/v1/findings/{a1.id}/decisions",
            params={"tenant_id": str(tenant_b)},
            json=_decision_payload(rationale="cross-tenant attempt"),
        )

    assert response.status_code == 404
    decisions = PsycopgReviewDecisionRepository(pool)
    assert await decisions.list_for_finding(tenant_a, a1.id) == []


# ---------------------------------------------------------------------------
# 6. Tenant-scoped single-row reads at the repository boundary
# ---------------------------------------------------------------------------


async def test_repository_get_is_tenant_scoped(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")
    b1 = await _seed(findings, tenant_b, title=f"b1-{uuid.uuid4().hex}")

    assert await findings.get(tenant_a, b1.id) is None
    fetched = await findings.get(tenant_a, a1.id)
    assert fetched is not None
    assert fetched.id == a1.id
    assert fetched.tenant_id == tenant_a
    assert fetched.title == a1.title


# ---------------------------------------------------------------------------
# 7. Decisions are append-only: identical POSTs produce two rows
# ---------------------------------------------------------------------------


async def test_identical_decisions_append_without_dedup(pool: Pool) -> None:
    """Intended append-only behavior: no dedup, so two rows are recorded."""
    findings = PsycopgFindingRepository(pool)
    tenant_a = uuid.uuid4()
    a1 = await _seed(findings, tenant_a, title=f"a1-{uuid.uuid4().hex}")
    payload = _decision_payload()

    async with _client(_build_app(pool)) as client:
        first = await client.post(
            f"/v1/findings/{a1.id}/decisions",
            params={"tenant_id": str(tenant_a)},
            json=payload,
        )
        second = await client.post(
            f"/v1/findings/{a1.id}/decisions",
            params={"tenant_id": str(tenant_a)},
            json=payload,
        )

    assert first.status_code == 201
    assert second.status_code == 201
    decisions = PsycopgReviewDecisionRepository(pool)
    stored = await decisions.list_for_finding(tenant_a, a1.id)
    # Append-only: identical submissions are distinct audit records, not upserts.
    assert len(stored) == 2
    assert {d.reviewer_id for d in stored} == {payload["reviewer_id"]}
