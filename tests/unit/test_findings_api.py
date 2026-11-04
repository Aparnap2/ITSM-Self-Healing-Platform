"""Offline unit tests for the authenticated findings / reviewer-decision API.

Marker: ``unit``. The route module declares its dependencies as narrow
structural protocols, so these tests wire in-memory fakes plus the real
``TokenAuthenticator`` and minted bearer tokens. No PostgreSQL, NATS, network,
or Docker is touched.

The authentication and authorization tests deliberately use the production
authenticator: a test-only bypass would not prove that a missing, expired,
forged, or under-privileged credential is rejected.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from itsm_agent.api.app import create_app
from itsm_agent.api.auth import TokenAuthenticator, mint_token
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.models import Finding, ReviewDecision, Severity

pytestmark = pytest.mark.unit

SECRET = "unit-test-reviewer-secret-0123456789"
TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeSink:
    async def accept_incident(self, event: Any) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


class FakeFindingsRepo:
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
# Helpers
# ---------------------------------------------------------------------------


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
    ttl_seconds: int = 900,
) -> str:
    return mint_token(
        SECRET,
        principal_id=principal_id,
        tenant_ids=tenants,
        roles=roles,
        ttl_seconds=ttl_seconds,
    )


def _build_app(
    findings_repo: FakeFindingsRepo | None = None,
    decisions_repo: FakeDecisionsStore | None = None,
    *,
    authenticator: TokenAuthenticator | None = None,
) -> FastAPI:
    repo = findings_repo if findings_repo is not None else FakeFindingsRepo()
    store = decisions_repo if decisions_repo is not None else FakeDecisionsStore()
    authenticate = authenticator or TokenAuthenticator(secret=SECRET)
    # Composition is instance-scoped (app.state); no shared global exists.
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=repo,
        review_decisions_repo=store,
        authenticator=authenticate,
    )


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _finding(*, tenant_id: UUID = TENANT, **overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "finding_type": "PRIVILEGE_ESCALATION",
        "severity": Severity.P2,
        "status": "OPEN",
        "title": "Suspicious role assumption",
        "description": "detected by deterministic rule",
        "detected_at": datetime.now(UTC),
        "rule_version": "rule-v1",
        "risk_score": 70,
        "outcome": "VIOLATION",
    }
    values.update(overrides)
    return Finding(**values)


def _decision_body(
    *, decision: str = "CONFIRMED", rationale: str = "evidence supports the finding"
) -> dict[str, str]:
    return {"decision": decision, "rationale": rationale}


@pytest.fixture(autouse=True)
def _app_instances_are_independent() -> Iterator[None]:
    yield


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def test_missing_credential_is_401() -> None:
    app = _build_app()
    async with _client(app) as client:
        response = await client.get("/v1/findings", params={"tenant_id": str(TENANT)})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    # No existence leak in the rejection body.
    assert "finding" not in response.json()["detail"].lower()


async def test_forged_and_expired_credentials_are_401() -> None:
    app = _build_app()
    expired = mint_token(
        SECRET,
        principal_id="reviewer-1",
        tenant_ids=[TENANT],
        roles=["reviewer"],
        issued_at=datetime.now(UTC) - timedelta(hours=2),
        ttl_seconds=60,
    )
    forged = _token().rsplit(".", 1)[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    async with _client(app) as client:
        expired_response = await client.get(
            "/v1/findings", params={"tenant_id": str(TENANT)}, headers=_auth(expired)
        )
        forged_response = await client.get(
            "/v1/findings", params={"tenant_id": str(TENANT)}, headers=_auth(forged)
        )
        wrong_scheme = await client.get(
            "/v1/findings",
            params={"tenant_id": str(TENANT)},
            headers={"Authorization": f"Basic {_token()}"},
        )
    assert expired_response.status_code == 401
    assert forged_response.status_code == 401
    assert wrong_scheme.status_code == 401


async def test_token_signed_with_another_secret_is_rejected() -> None:
    other_secret_token = mint_token(
        "a-different-secret-value-0123456789",
        principal_id="reviewer-1",
        tenant_ids=[TENANT],
        roles=["reviewer"],
    )
    app = _build_app()
    async with _client(app) as client:
        response = await client.get(
            "/v1/findings", params={"tenant_id": str(TENANT)}, headers=_auth(other_secret_token)
        )
    assert response.status_code == 401


def test_unconfigured_authenticator_is_fail_closed_503() -> None:
    # Composition root that forgot authentication: router mounted, authenticator=None.
    # Dependencies live on app.state (the deprecated global shim is intentionally
    # not used here). Assertion is unchanged: must fail closed with 503.
    app = create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=FakeFindingsRepo(),
        review_decisions_repo=FakeDecisionsStore(),
        authenticator=None,
    )
    import asyncio

    async def call() -> int:
        async with _client(app) as client:
            response = await client.get(
                "/v1/findings", params={"tenant_id": str(TENANT)}, headers=_auth(_token())
            )
        return response.status_code

    assert asyncio.run(call()) == 503


# ---------------------------------------------------------------------------
# Tenant scope derives from the principal
# ---------------------------------------------------------------------------


async def test_tenant_outside_principal_membership_is_403() -> None:
    repo = FakeFindingsRepo()
    other = _finding(tenant_id=OTHER_TENANT)
    repo.add(other)
    app = _build_app(repo)

    async with _client(app) as client:
        granted = await client.get(
            "/v1/findings", params={"tenant_id": str(TENANT)}, headers=_auth(_token())
        )
        denied = await client.get(
            "/v1/findings",
            params={"tenant_id": str(OTHER_TENANT)},
            headers=_auth(_token()),
        )

    assert granted.status_code == 200
    assert granted.json() == []
    assert denied.status_code == 403


async def test_list_returns_only_principal_tenant_findings() -> None:
    repo = FakeFindingsRepo()
    mine = _finding(severity=Severity.P1, risk_score=95)
    theirs = _finding(tenant_id=OTHER_TENANT)
    repo.add(mine, theirs)
    app = _build_app(repo)

    async with _client(app) as client:
        response = await client.get(
            "/v1/findings", params={"tenant_id": str(TENANT)}, headers=_auth(_token())
        )

    assert response.status_code == 200
    body = response.json()
    assert {row["id"] for row in body} == {str(mine.id)}
    assert body[0]["severity"] == "P1"
    assert body[0]["tenant_id"] == str(TENANT)


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


async def test_read_only_auditor_cannot_submit_decision() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        readable = await client.get(
            f"/v1/findings/{finding.id}",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token(roles=("auditor",))),
        )
        denied = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token(roles=("auditor",))),
            json=_decision_body(),
        )

    assert readable.status_code == 200
    assert denied.status_code == 403
    assert store.decisions == []


async def test_analyst_cannot_submit_confirm_but_can_request_more_evidence() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)
    analyst = _auth(_token(roles=("analyst",)))

    async with _client(app) as client:
        prohibited = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=analyst,
            json=_decision_body(decision="CONFIRMED"),
        )
        allowed = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=analyst,
            json=_decision_body(decision="NEEDS_MORE_EVIDENCE", rationale="need the ticket"),
        )

    assert prohibited.status_code == 403
    assert allowed.status_code == 201
    assert [d.decision for d in store.decisions] == ["NEEDS_MORE_EVIDENCE"]


async def test_reviewer_records_decision_with_authenticated_actor() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token(principal_id="secops.alice")),
            json=_decision_body(),
        )

    assert response.status_code == 201
    assert response.json()["status"] == "recorded"
    assert len(store.decisions) == 1
    stored = store.decisions[0]
    # Actor comes from the credential, not from the request body.
    assert stored.reviewer_id == "secops.alice"
    assert stored.tenant_id == TENANT
    assert stored.finding_id == finding.id


async def test_spoofed_reviewer_id_in_body_is_rejected() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token(principal_id="real.reviewer")),
            json={**_decision_body(), "reviewer_id": "someone.else"},
        )

    assert response.status_code == 422
    assert store.decisions == []


async def test_unknown_decision_type_is_403_before_any_write() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
            json={"decision": "APPROVED", "rationale": "not an allowed decision"},
        )

    # The request schema rejects it first (allowlist mirrors the RBAC map).
    assert response.status_code in {403, 422}
    assert store.decisions == []


async def test_cross_tenant_decision_is_404_and_writes_nothing() -> None:
    repo = FakeFindingsRepo()
    finding = _finding(tenant_id=OTHER_TENANT)
    repo.add(finding)
    store = FakeDecisionsStore()
    # Principal belongs to both tenants, so isolation is the control under test.
    app = _build_app(repo, store)
    two_tenant_token = _token(tenants=(TENANT, OTHER_TENANT))

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(two_tenant_token),
            json=_decision_body(),
        )

    assert response.status_code == 404
    assert store.decisions == []


async def test_decision_history_is_append_only_and_ordered() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)
    reviewer = _auth(_token(principal_id="secops.bob"))

    async with _client(app) as client:
        first = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=reviewer,
            json=_decision_body(decision="NEEDS_MORE_EVIDENCE", rationale="initial"),
        )
        second = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=reviewer,
            json=_decision_body(decision="CONFIRMED", rationale="follow-up"),
        )
        listed = await client.get(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=reviewer,
        )

    assert first.status_code == 201
    assert second.status_code == 201
    decisions = listed.json()
    assert [d["decision"] for d in decisions] == ["NEEDS_MORE_EVIDENCE", "CONFIRMED"]
    assert {d["reviewer_id"] for d in decisions} == {"secops.bob"}


async def test_missing_rationale_is_422() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeDecisionsStore()
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/decisions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
            json={"decision": "CONFIRMED", "rationale": ""},
        )

    assert response.status_code == 422
    assert store.decisions == []
