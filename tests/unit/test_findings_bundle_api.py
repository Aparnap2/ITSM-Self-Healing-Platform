"""Offline unit tests for the evidence-bundle endpoint.

Marker: ``unit``. Fakes plus the real ``TokenAuthenticator``; no PostgreSQL,
NATS, network, or Docker. The redaction gate is asserted end-to-end here: a
secret-bearing excerpt must be redacted before the bundle is hashed, and the
hash must remain deterministic.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from itsm_agent.api.app import create_app
from itsm_agent.api.auth import TokenAuthenticator, mint_token
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.models import EvidenceReference, Finding, ReviewDecision, Severity

pytestmark = pytest.mark.unit

SECRET = "unit-test-reviewer-secret-0123456789"
TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")


class FakeSink:
    async def accept_incident(self, event: Any) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


class FakeFindingsRepo:
    def __init__(self, *findings: Finding) -> None:
        self._findings = {f.id: f for f in findings}

    async def get(self, tenant_id: UUID, finding_id: UUID) -> Finding | None:
        finding = self._findings.get(finding_id)
        if finding is None or finding.tenant_id != tenant_id:
            return None
        return finding

    async def list_for_tenant(self, tenant_id: UUID) -> list[Finding]:
        return [f for f in self._findings.values() if f.tenant_id == tenant_id]


class FakeDecisionsStore:
    def __init__(self, *decisions: ReviewDecision) -> None:
        self._decisions = decisions

    async def record(self, decision: ReviewDecision) -> ReviewDecision:
        raise NotImplementedError("bundle route never records")

    async def list_for_finding(self, tenant_id: UUID, finding_id: UUID) -> list[ReviewDecision]:
        return [
            d for d in self._decisions if d.tenant_id == tenant_id and d.finding_id == finding_id
        ]


class FakeEvidenceRepo:
    def __init__(self, *references: EvidenceReference) -> None:
        self._references = references

    async def list_for_tenant_finding(
        self, tenant_id: UUID, finding_id: UUID
    ) -> list[EvidenceReference]:
        return [r for r in self._references if r.finding_id == finding_id]


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


def _token(
    *,
    principal_id: str = "reviewer-1",
    tenants: tuple[UUID, ...] = (TENANT,),
    roles: tuple[str, ...] = ("reviewer",),
) -> str:
    return mint_token(
        SECRET,
        principal_id=principal_id,
        tenant_ids=tenants,
        roles=roles,
        ttl_seconds=900,
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _finding(*, tenant_id: UUID = TENANT) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        finding_type="PRIVILEGE_ESCALATION",
        severity=Severity.P2,
        status="OPEN",
        title="Suspicious role assumption",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=70,
        outcome="VIOLATION",
    )


def _evidence(finding: Finding, *, excerpt: str | None = None) -> EvidenceReference:
    return EvidenceReference(
        id=uuid.uuid4(),
        finding_id=finding.id,
        source_event_id=uuid.uuid4(),
        content_hash="a" * 64,
        excerpt=excerpt,
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=datetime.now(UTC),
    )


def _decision(finding: Finding) -> ReviewDecision:
    return ReviewDecision(
        id=uuid.uuid4(),
        tenant_id=finding.tenant_id,
        finding_id=finding.id,
        reviewer_id="secops.alice",
        decision="CONFIRMED",
        rationale="evidence supports the finding",
    )


def _build_app(
    repo: FakeFindingsRepo | None = None,
    *,
    evidence_repo: FakeEvidenceRepo | None = None,
) -> FastAPI:
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=repo if repo is not None else FakeFindingsRepo(),
        review_decisions_repo=FakeDecisionsStore(),
        evidence_references_repo=evidence_repo,
        authenticator=TokenAuthenticator(secret=SECRET),
    )


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


# ---------------------------------------------------------------------------
# Bundle endpoint
# ---------------------------------------------------------------------------


async def test_bundle_contains_finding_evidence_decisions_and_limitations() -> None:
    finding = _finding()
    decision = _decision(finding)
    repo = FakeFindingsRepo(finding)
    store = FakeDecisionsStore(decision)
    evidence = FakeEvidenceRepo(_evidence(finding))
    app = create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=repo,
        review_decisions_repo=store,
        evidence_references_repo=evidence,
        authenticator=TokenAuthenticator(secret=SECRET),
    )

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["finding"]["id"] == str(finding.id)
    assert body["finding"]["outcome"] == "VIOLATION"
    assert len(body["evidence"]) == 1
    assert body["review_decisions"][0]["decision"] == "CONFIRMED"
    assert body["limitations"]  # reports always carry the limitations list
    assert len(body["bundle_hash"]) == 64


async def test_bundle_excerpts_are_redacted_in_the_response() -> None:
    finding = _finding()
    repo = FakeFindingsRepo(finding)
    evidence = FakeEvidenceRepo(
        _evidence(finding, excerpt="Bearer abc123def"),
        _evidence(finding, excerpt="request included api_key=secret123"),
    )
    app = _build_app(repo, evidence_repo=evidence)

    async with _client(app) as client:
        first = await client.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
        )
        second = await client.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
        )

    assert first.status_code == 200
    body = first.json()
    joined = " ".join(e["excerpt"] or "" for e in body["evidence"])
    assert "Bearer [REDACTED]" in joined
    assert any("api_key=[REDACTED]" in (e["excerpt"] or "") for e in body["evidence"])
    assert "abc123def" not in joined
    assert "secret123" not in joined
    # Redaction happens before hashing: identical input -> identical bundle hash.
    assert first.json()["bundle_hash"] == second.json()["bundle_hash"]


async def test_bundle_for_unknown_finding_is_404() -> None:
    app = _build_app(FakeFindingsRepo(), evidence_repo=FakeEvidenceRepo())

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{uuid.uuid4()}/bundle",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"


async def test_cross_tenant_finding_bundles_is_404() -> None:
    theirs = _finding(tenant_id=OTHER_TENANT)
    repo = FakeFindingsRepo(theirs)
    store = FakeDecisionsStore()
    evidence = FakeEvidenceRepo(_evidence(theirs))
    # Principal belongs to both tenants: isolation must come from the store.
    two_tenant_token = _token(tenants=(TENANT, OTHER_TENANT))
    app = create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=repo,
        review_decisions_repo=store,
        evidence_references_repo=evidence,
        authenticator=TokenAuthenticator(secret=SECRET),
    )

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{theirs.id}/bundle",
            params={"tenant_id": str(TENANT)},
            headers=_auth(two_tenant_token),
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"


async def test_tenant_outside_principal_membership_is_403() -> None:
    finding = _finding(tenant_id=OTHER_TENANT)
    repo = FakeFindingsRepo(finding)
    app = _build_app(repo, evidence_repo=FakeEvidenceRepo(_evidence(finding)))

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(OTHER_TENANT)},
            headers=_auth(_token()),
        )

    assert response.status_code == 403


async def test_bundle_without_evidence_store_is_fail_closed_503() -> None:
    finding = _finding()
    repo = FakeFindingsRepo(finding)
    app = _build_app(repo, evidence_repo=None)

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
        )

    assert response.status_code == 503
    assert "evidence" in response.json()["detail"].lower()


async def test_bundle_requires_a_credential() -> None:
    finding = _finding()
    repo = FakeFindingsRepo(finding)
    app = _build_app(repo, evidence_repo=FakeEvidenceRepo())

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}/bundle",
            params={"tenant_id": str(TENANT)},
        )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
