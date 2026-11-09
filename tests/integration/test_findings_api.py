"""Integration: authenticated findings / reviewer-decision API on real PostgreSQL.

Unlike the offline unit suite, these tests build the app through ``create_app``
with psycopg repositories over a real pool and the real ``TokenAuthenticator``.
They cover tenant isolation, RBAC, actor provenance, durability across an app
rebuild, and append-only decision history.
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
from itsm_agent.api.auth import TokenAuthenticator, mint_token
from itsm_agent.api.routes.findings import FindingsDeps, configure_findings
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.events import IncidentCreated
from itsm_agent.domain.models import Finding, Severity

pytestmark = pytest.mark.integration

SECRET = "integration-reviewer-secret-0123456789"

Pool = AsyncConnectionPool[AsyncConnection]


class FakeSink:
    async def accept_incident(self, event: IncidentCreated) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


def _settings() -> Settings:
    return Settings.model_validate(
        {
            "env": "test",
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "webhook_secret": "test-webhook-secret-0123456789abcdef",
            "webhook_max_body_bytes": 2048,
            "rate_limit_requests": 100,
            "rate_limit_window_seconds": 60.0,
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )


async def _ensure_tenant(pool: Pool, tenant_id: UUID) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO tenants (id) VALUES (%s) ON CONFLICT DO NOTHING", (tenant_id,)
        )


async def _seed_evidence(
    pool: Pool, tenant_id: UUID, finding_id: UUID, *, excerpt: str | None = None
) -> UUID:
    from itsm_agent.adapters.persistence.tenant import tenant_transaction

    evidence_id = uuid.uuid4()
    async with tenant_transaction(pool, tenant_id) as conn:
        await conn.execute(
            """
            INSERT INTO evidence_references (
                id, tenant_id, finding_id, source_event_id,
                content_hash, excerpt, trust_level, collected_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, now())
            """,
            (
                evidence_id,
                tenant_id,
                finding_id,
                None,
                "e" * 64,
                excerpt,
                "SIMULATOR_OBSERVATION",
            ),
        )
    return evidence_id


def _build_app(pool: Pool) -> FastAPI:
    bundle = RepositoryBundle(pool)
    authenticator = TokenAuthenticator(secret=SECRET)
    configure_findings(
        FindingsDeps(
            findings_repo=bundle.findings,
            review_decisions_repo=bundle.review_decisions,
            evidence_references_repo=bundle.evidence_references,
            authenticator=authenticator,
        )
    )
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=bundle.findings,
        review_decisions_repo=bundle.review_decisions,
        evidence_references_repo=bundle.evidence_references,
        authenticator=authenticator,
    )


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


def _token(
    *,
    principal_id: str = "reviewer-1",
    tenants: tuple[UUID, ...] | None = None,
    roles: tuple[str, ...] = ("reviewer",),
    tenant_id: UUID | None = None,
) -> dict[str, str]:
    memberships = tenants if tenants is not None else (tenant_id or uuid.uuid4(),)
    token = mint_token(SECRET, principal_id=principal_id, tenant_ids=memberships, roles=roles)
    return {"Authorization": f"Bearer {token}"}


def _finding(tenant_id: UUID) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        finding_type="EXCESSIVE_PRIVILEGE",
        severity=Severity.P1,
        status="OPEN",
        title=f"finding-{uuid.uuid4().hex}",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=90,
        outcome="VIOLATION",
    )


def _decision_body(
    *, decision: str = "CONFIRMED", rationale: str = "evidence supports the finding"
) -> dict[str, str]:
    return {"decision": decision, "rationale": rationale}


@pytest.fixture(autouse=True)
def _reset_findings_deps() -> Iterator[None]:
    configure_findings(None)
    yield
    configure_findings(None)


@pytest.fixture
async def pool(pg_dsn: str) -> AsyncIterator[Pool]:
    created = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await created.open()
    try:
        async with created.connection() as conn:
            await conn.execute("TRUNCATE findings, review_decisions CASCADE")
        yield created
    finally:
        await created.close()


async def test_list_is_tenant_scoped_and_requires_membership(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _ensure_tenant(pool, tenant_a)
    await _ensure_tenant(pool, tenant_b)
    a1 = await findings.upsert(_finding(tenant_a))
    b1 = await findings.upsert(_finding(tenant_b))

    app = _build_app(pool)
    async with _client(app) as client:
        mine = await client.get(
            "/v1/findings", params={"tenant_id": str(tenant_a)}, headers=_token(tenant_id=tenant_a)
        )
        forbidden = await client.get(
            "/v1/findings", params={"tenant_id": str(tenant_b)}, headers=_token(tenant_id=tenant_a)
        )

    assert mine.status_code == 200
    assert {row["id"] for row in mine.json()} == {str(a1.id)}
    assert str(b1.id) not in {row["id"] for row in mine.json()}
    assert forbidden.status_code == 403


async def test_cross_tenant_detail_is_404_even_with_both_memberships(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _ensure_tenant(pool, tenant_a)
    await _ensure_tenant(pool, tenant_b)
    a1 = await findings.upsert(_finding(tenant_a))
    headers = _token(tenants=(tenant_a, tenant_b))

    app = _build_app(pool)
    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{a1.id}", params={"tenant_id": str(tenant_b)}, headers=headers
        )

    assert response.status_code == 404


async def test_decision_actor_comes_from_token_and_survives_restart(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant = uuid.uuid4()
    await _ensure_tenant(pool, tenant)
    finding = await findings.upsert(_finding(tenant))
    headers = _token(principal_id="secops.alice", tenant_id=tenant)

    async with _client(_build_app(pool)) as client:
        posted = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(tenant)},
            headers=headers,
            json=_decision_body(rationale="matches the exposed admin role"),
        )

    assert posted.status_code == 201

    # Rebuild the app over the SAME pool: the decision must come from PostgreSQL.
    async with _client(_build_app(pool)) as restarted:
        listed = await restarted.get(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(tenant)},
            headers=headers,
        )

    assert listed.status_code == 200
    decisions = listed.json()
    assert len(decisions) == 1
    assert decisions[0]["reviewer_id"] == "secops.alice"
    assert decisions[0]["decision"] == "CONFIRMED"


async def test_reader_role_cannot_record_decision(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant = uuid.uuid4()
    await _ensure_tenant(pool, tenant)
    finding = await findings.upsert(_finding(tenant))
    headers = _token(tenant_id=tenant, roles=("auditor",))

    async with _client(_build_app(pool)) as client:
        read = await client.get(
            f"/v1/findings/{finding.id}",
            params={"tenant_id": str(tenant)},
            headers=headers,
        )
        write = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(tenant)},
            headers=headers,
            json=_decision_body(),
        )

    assert read.status_code == 200
    assert write.status_code == 403
    assert await PsycopgReviewDecisionRepository(pool).list_for_finding(tenant, finding.id) == []


async def test_cross_tenant_decision_writes_nothing(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _ensure_tenant(pool, tenant_a)
    await _ensure_tenant(pool, tenant_b)
    finding = await findings.upsert(_finding(tenant_a))
    headers = _token(tenants=(tenant_a, tenant_b))

    async with _client(_build_app(pool)) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(tenant_b)},
            headers=headers,
            json=_decision_body(rationale="cross-tenant attempt"),
        )

    assert response.status_code == 404
    decisions = PsycopgReviewDecisionRepository(pool)
    assert await decisions.list_for_finding(tenant_a, finding.id) == []
    assert await decisions.list_for_finding(tenant_b, finding.id) == []


async def test_repository_get_is_tenant_scoped(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _ensure_tenant(pool, tenant_a)
    await _ensure_tenant(pool, tenant_b)
    a1 = await findings.upsert(_finding(tenant_a))
    b1 = await findings.upsert(_finding(tenant_b))

    assert await findings.get(tenant_a, b1.id) is None
    fetched = await findings.get(tenant_a, a1.id)
    assert fetched is not None and fetched.id == a1.id


async def test_identical_decisions_append_without_dedup(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant = uuid.uuid4()
    await _ensure_tenant(pool, tenant)
    finding = await findings.upsert(_finding(tenant))
    headers = _token(principal_id="secops.bob", tenant_id=tenant)
    body = _decision_body()

    async with _client(_build_app(pool)) as client:
        first = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(tenant)},
            headers=headers,
            json=body,
        )
        second = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(tenant)},
            headers=headers,
            json=body,
        )

    assert first.status_code == 201
    assert second.status_code == 201
    stored = await PsycopgReviewDecisionRepository(pool).list_for_finding(tenant, finding.id)
    assert len(stored) == 2


async def test_bundle_is_tenant_scoped_with_redacted_excerpts(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _ensure_tenant(pool, tenant_a)
    await _ensure_tenant(pool, tenant_b)
    a1 = await findings.upsert(_finding(tenant_a))
    await _seed_evidence(pool, tenant_a, a1.id, excerpt="Bearer abc123def")
    headers = _token(principal_id="secops.carol", tenant_id=tenant_a)
    body = _decision_body(rationale="matches the exposed admin role")

    async with _client(_build_app(pool)) as client:
        posted = await client.post(
            f"/v1/findings/{a1.id}/decisions",
            params={"tenant_id": str(tenant_a)},
            headers=headers,
            json=body,
        )
        bundle = await client.get(
            f"/v1/findings/{a1.id}/bundle",
            params={"tenant_id": str(tenant_a)},
            headers=headers,
        )
        cross = await client.get(
            f"/v1/findings/{a1.id}/bundle",
            params={"tenant_id": str(tenant_b)},
            headers=_token(tenants=(tenant_a, tenant_b)),
        )

    assert posted.status_code == 201
    assert bundle.status_code == 200
    payload = bundle.json()
    assert payload["finding"]["id"] == str(a1.id)
    assert payload["finding"]["outcome"] == "VIOLATION"
    assert len(payload["evidence"]) == 1
    assert payload["evidence"][0]["excerpt"] == "Bearer [REDACTED]"
    assert [d["reviewer_id"] for d in payload["review_decisions"]] == ["secops.carol"]
    assert payload["limitations"]
    assert len(payload["bundle_hash"]) == 64
    # Cross-tenant read over the same token is a 404, never a leak.
    assert cross.status_code == 404


async def test_bundle_hash_is_deterministic_and_survives_a_rebuild(pool: Pool) -> None:
    findings = PsycopgFindingRepository(pool)
    tenant = uuid.uuid4()
    await _ensure_tenant(pool, tenant)
    finding = await findings.upsert(_finding(tenant))
    await _seed_evidence(pool, tenant, finding.id, excerpt="request included api_key=secret123")
    headers = _token(tenant_id=tenant)

    async with _client(_build_app(pool)) as first_app:
        first = await first_app.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(tenant)},
            headers=headers,
        )
    async with _client(_build_app(pool)) as second_app:
        second = await second_app.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(tenant)},
            headers=headers,
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["bundle_hash"] == second.json()["bundle_hash"]
    joined = " ".join(e["excerpt"] or "" for e in second.json()["evidence"])
    assert "api_key=[REDACTED]" in joined
    assert "secret123" not in joined
