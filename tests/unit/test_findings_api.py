"""Offline unit tests for the findings / reviewer-decision HTTP surface.

Marker: ``unit``. The route module declares its dependencies as narrow
structural protocols (``FindingsReader`` / ``DecisionsStore``), so these
tests wire in-memory fakes and an ``httpx.ASGITransport`` client. No
PostgreSQL, NATS, network, or Docker is touched.

Isolation note: ``configure_findings`` mutates a module-level global. The
autouse fixture resets it around every test so state never leaks between
tests (or into other modules).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from itsm_agent.api.app import create_app
from itsm_agent.api.routes.findings import FindingsDeps, configure_findings
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.models import Finding, ReviewDecision, Severity

pytestmark = pytest.mark.unit

SECRET = "test-webhook-secret-0123456789abcdef"
TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")

DecisionValue = Literal["CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "NEEDS_MORE_EVIDENCE"]


# ---------------------------------------------------------------------------
# Fakes (structural implementations of the route protocols)
# ---------------------------------------------------------------------------


class FakeSink:
    """Minimal ingestion sink; findings tests never post incidents."""

    async def accept_incident(self, event: Any) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


class FakeFindingsRepo:
    """In-memory ``FindingsReader`` with tenant-scoped lookups."""

    def __init__(self) -> None:
        self._findings: dict[UUID, Finding] = {}

    def add(self, *findings: Finding) -> None:
        for finding in findings:
            self._findings[finding.id] = finding

    async def get(self, tenant_id: UUID, finding_id: UUID) -> Finding | None:
        finding = self._findings.get(finding_id)
        if finding is None or finding.tenant_id != tenant_id:
            return None
        return finding

    async def list_for_tenant(self, tenant_id: UUID) -> list[Finding]:
        return [f for f in self._findings.values() if f.tenant_id == tenant_id]


class FakeDecisionsStore:
    """In-memory, append-only ``DecisionsStore``."""

    def __init__(self) -> None:
        self.decisions: list[ReviewDecision] = []

    async def record(self, decision: ReviewDecision) -> ReviewDecision:
        self.decisions.append(decision)
        return decision

    async def list_for_finding(self, tenant_id: UUID, finding_id: UUID) -> list[ReviewDecision]:
        return [
            d for d in self.decisions if d.tenant_id == tenant_id and d.finding_id == finding_id
        ]


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


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


def _build_app(findings_repo: FakeFindingsRepo, decisions_repo: FakeDecisionsStore) -> FastAPI:
    configure_findings(
        FindingsDeps(
            findings_repo=findings_repo,
            review_decisions_repo=decisions_repo,
        )
    )
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=findings_repo,
        review_decisions_repo=decisions_repo,
    )


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


def _finding(
    *,
    tenant_id: UUID = TENANT,
    severity: Severity = Severity.P2,
    finding_type: str = "PRIVILEGE_ESCALATION",
    title: str = "Suspicious role assumption",
    status: str = "OPEN",
    risk_score: int = 70,
    outcome: str = "VIOLATION",
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        finding_type=finding_type,
        severity=severity,
        status=status,
        title=title,
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=risk_score,
        outcome=outcome,
    )


def _decision(
    finding: Finding,
    *,
    reviewer_id: str = "reviewer-1",
    decision: DecisionValue = "CONFIRMED",
    rationale: str = "evidence supports the finding",
) -> ReviewDecision:
    return ReviewDecision(
        tenant_id=finding.tenant_id,
        finding_id=finding.id,
        reviewer_id=reviewer_id,
        decision=decision,
        rationale=rationale,
    )


@pytest.fixture(autouse=True)
def _reset_findings_deps() -> Iterator[None]:
    """Reset the module-level global before and after every test."""
    configure_findings(None)
    yield
    configure_findings(None)


# ---------------------------------------------------------------------------
# 1. Tenant-scoped listing + JSON shape
# ---------------------------------------------------------------------------


async def test_list_findings_returns_only_tenant_with_expected_shape() -> None:
    repo = FakeFindingsRepo()
    p1 = _finding(severity=Severity.P1, risk_score=95, outcome="VIOLATION")
    p3 = _finding(severity=Severity.P3, risk_score=30, outcome="SUSPICIOUS")
    other = _finding(tenant_id=OTHER_TENANT, severity=Severity.P2)
    repo.add(p1, p3, other)
    app = _build_app(repo, FakeDecisionsStore())

    async with _client(app) as client:
        response = await client.get("/v1/findings", params={"tenant_id": str(TENANT)})

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert {row["id"] for row in body} == {str(p1.id), str(p3.id)}
    assert {row["severity"] for row in body} == {"P1", "P3"}
    assert {row["risk_score"] for row in body} == {95, 30}
    expected_keys = {
        "id",
        "tenant_id",
        "finding_type",
        "severity",
        "status",
        "title",
        "detected_at",
        "risk_score",
        "outcome",
    }
    for row in body:
        assert expected_keys <= set(row)
        assert row["tenant_id"] == str(TENANT)
        assert row["status"] == "OPEN"
        assert row["severity"] in {"P1", "P2", "P3", "P4"}


# ---------------------------------------------------------------------------
# 2. Detail includes review decisions
# ---------------------------------------------------------------------------


async def test_get_finding_returns_finding_and_review_decisions() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    decision = _decision(finding, reviewer_id="alice")
    await store.record(decision)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.get(f"/v1/findings/{finding.id}", params={"tenant_id": str(TENANT)})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(finding.id)
    assert body["tenant_id"] == str(TENANT)
    assert body["severity"] == "P2"
    assert isinstance(body["review_decisions"], list)
    assert len(body["review_decisions"]) == 1
    stored = body["review_decisions"][0]
    assert stored["id"] == str(decision.id)
    assert stored["reviewer_id"] == "alice"
    assert stored["decision"] == "CONFIRMED"


# ---------------------------------------------------------------------------
# 3. Cross-tenant detail is a 404
# ---------------------------------------------------------------------------


async def test_get_finding_from_other_tenant_returns_404() -> None:
    repo = FakeFindingsRepo()
    finding = _finding(tenant_id=TENANT)
    repo.add(finding)
    app = _build_app(repo, FakeDecisionsStore())

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}", params={"tenant_id": str(OTHER_TENANT)}
        )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 4. Non-existent finding is a 404
# ---------------------------------------------------------------------------


async def test_get_missing_finding_returns_404() -> None:
    app = _build_app(FakeFindingsRepo(), FakeDecisionsStore())

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{uuid.uuid4()}", params={"tenant_id": str(TENANT)}
        )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 5. Valid decision is recorded
# ---------------------------------------------------------------------------


async def test_post_decision_records_reviewer_decision() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            json={
                "reviewer_id": "rev-1",
                "decision": "CONFIRMED",
                "rationale": "evidence supports the finding",
            },
        )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "recorded"
    assert len(store.decisions) == 1
    stored = store.decisions[0]
    assert body["id"] == str(stored.id)
    assert stored.tenant_id == TENANT
    assert stored.finding_id == finding.id
    assert stored.reviewer_id == "rev-1"
    assert stored.decision == "CONFIRMED"
    assert stored.rationale == "evidence supports the finding"


# ---------------------------------------------------------------------------
# 6. Invalid payloads are rejected by validation
# ---------------------------------------------------------------------------


async def test_post_decision_rejects_invalid_value_and_empty_rationale() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        invalid_value = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            json={
                "reviewer_id": "rev-1",
                "decision": "MAYBE",
                "rationale": "not a valid decision",
            },
        )
        empty_rationale = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            json={
                "reviewer_id": "rev-1",
                "decision": "CONFIRMED",
                "rationale": "",
            },
        )

    assert invalid_value.status_code == 422
    assert empty_rationale.status_code == 422
    assert store.decisions == []


# ---------------------------------------------------------------------------
# 7. Cross-tenant decision is a 404 and writes nothing
# ---------------------------------------------------------------------------


async def test_post_decision_for_other_tenant_returns_404_and_writes_nothing() -> None:
    repo = FakeFindingsRepo()
    finding = _finding(tenant_id=TENANT)
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(OTHER_TENANT)},
            json={
                "reviewer_id": "rev-1",
                "decision": "CONFIRMED",
                "rationale": "cross-tenant attempt",
            },
        )

    assert response.status_code == 404
    assert store.decisions == []


# ---------------------------------------------------------------------------
# 8. Listing decisions + cross-tenant isolation
# ---------------------------------------------------------------------------


async def test_list_decisions_returns_recorded_and_hides_cross_tenant() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        post = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            json={
                "reviewer_id": "rev-2",
                "decision": "FALSE_POSITIVE",
                "rationale": "benign maintenance window",
            },
        )
        assert post.status_code == 201

        listed = await client.get(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
        )
        cross_tenant = await client.get(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(OTHER_TENANT)},
        )

    assert listed.status_code == 200
    decisions = listed.json()
    assert len(decisions) == 1
    assert decisions[0]["reviewer_id"] == "rev-2"
    assert decisions[0]["decision"] == "FALSE_POSITIVE"
    assert cross_tenant.status_code == 404


# ---------------------------------------------------------------------------
# 9. Unconfigured dependencies fail closed with 503
# ---------------------------------------------------------------------------


async def test_list_findings_unconfigured_returns_503() -> None:
    # Build the app with the router mounted, then clear the global so the
    # route hits the "store not configured" branch.
    app = _build_app(FakeFindingsRepo(), FakeDecisionsStore())
    configure_findings(None)

    async with _client(app) as client:
        response = await client.get("/v1/findings", params={"tenant_id": str(TENANT)})

    assert response.status_code == 503


# ---------------------------------------------------------------------------
# 10. Decisions are append-only
# ---------------------------------------------------------------------------


async def test_repeated_decisions_append_without_overwriting() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        first = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            json={
                "reviewer_id": "rev-a",
                "decision": "NEEDS_MORE_EVIDENCE",
                "rationale": "initial review",
            },
        )
        second = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            json={
                "reviewer_id": "rev-b",
                "decision": "CONFIRMED",
                "rationale": "follow-up review",
            },
        )
        listed = await client.get(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
        )

    assert first.status_code == 201
    assert second.status_code == 201
    assert len(store.decisions) == 2
    decisions = listed.json()
    assert len(decisions) == 2
    assert [d["reviewer_id"] for d in decisions] == ["rev-a", "rev-b"]
