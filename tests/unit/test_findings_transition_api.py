"""Offline unit tests for the authenticated finding-lifecycle transition API.

Marker: ``unit``. No PostgreSQL, NATS, network, or Docker is touched: the
route module declares narrow structural protocols, so an in-memory ledger
fake — backed by the *real* domain state machine — is wired in alongside the
production ``TokenAuthenticator`` and minted bearer tokens.

The fake is deliberately not a stub that always succeeds: it applies the same
``validate_transition`` / ``assert_verifier_independent`` policy the durable
repository applies, so the route's error mapping is exercised for real.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response

from itsm_agent.api.app import create_app
from itsm_agent.api.auth import TokenAuthenticator, mint_token
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.finding_lifecycle import (
    FindingStatus,
    FindingTransition,
    assert_verifier_independent,
    validate_transition,
)
from itsm_agent.domain.models import Finding, ReviewDecision, Severity

pytestmark = pytest.mark.unit

SECRET = "unit-test-transition-secret-0123456789"
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

    def replace(self, finding: Finding) -> None:
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


class FakeTransitionsStore:
    """In-memory stand-in for ``PsycopgFindingTransitionRepository``.

    Mirrors the durable contract: the domain state machine owns the edge, the
    verifier must be independent of the actor that closed the finding out, the
    ledger is append-only, and a finding that is not visible for the tenant
    yields ``None`` (the route maps that to a 404).
    """

    def __init__(self, findings_repo: FakeFindingsRepo) -> None:
        self._findings = findings_repo
        self.transitions: list[FindingTransition] = []

    async def apply_transition(
        self,
        tenant_id: UUID,
        finding_id: UUID,
        to_status: str,
        *,
        actor_id: str,
        reason: str,
        verifier_id: str | None = None,
    ) -> Finding | None:
        finding = await self._findings.get(tenant_id, finding_id)
        if finding is None:
            return None
        current_status = finding.status
        validate_transition(current_status, to_status, reason=reason)
        if to_status == FindingStatus.VERIFIED:
            assert_verifier_independent(verifier_id, self._resolver_actor(finding_id))
        record = FindingTransition(
            tenant_id=tenant_id,
            finding_id=finding_id,
            from_status=current_status,
            to_status=to_status,
            actor_id=actor_id,
            verifier_id=verifier_id,
            reason=reason,
            # Strictly increasing so "newest first" is deterministic.
            transitioned_at=datetime.now(UTC) + timedelta(microseconds=len(self.transitions)),
        )
        self.transitions.append(record)
        updated = finding.model_copy(update={"status": to_status})
        self._findings.replace(updated)
        return updated

    def _resolver_actor(self, finding_id: UUID) -> str | None:
        """Actor of the most recent RESOLVED transition, or ``None``."""
        for record in reversed(self.transitions):
            if record.finding_id == finding_id and record.to_status == FindingStatus.RESOLVED:
                return record.actor_id
        return None

    async def list_for_finding(self, tenant_id: UUID, finding_id: UUID) -> list[FindingTransition]:
        return [
            t for t in self.transitions if t.tenant_id == tenant_id and t.finding_id == finding_id
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _build_app(
    findings_repo: FakeFindingsRepo | None = None,
    transitions: FakeTransitionsStore | None = None,
    *,
    authenticator: TokenAuthenticator | None = None,
    wire_transitions: bool = True,
) -> FastAPI:
    repo = findings_repo if findings_repo is not None else FakeFindingsRepo()
    store = transitions if transitions is not None else FakeTransitionsStore(repo)
    authenticate = authenticator or TokenAuthenticator(secret=SECRET)
    # Composition is instance-scoped (app.state); no shared global exists.
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=repo,
        review_decisions_repo=FakeDecisionsStore(),
        finding_transitions=store if wire_transitions else None,
        authenticator=authenticate,
    )


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


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


async def _post_transition(
    client: AsyncClient,
    finding_id: UUID,
    *,
    to_status: str = "ACKNOWLEDGED",
    reason: str = "triaged by the on-call reviewer",
    tenant_id: UUID = TENANT,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> Response:
    payload = body if body is not None else {"to_status": to_status, "reason": reason}
    return await client.post(
        f"/v1/findings/{finding_id}/transition",
        params={"tenant_id": str(tenant_id)},
        headers=headers if headers is not None else _auth(_token()),
        json=payload,
    )


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


async def test_transition_updates_status_and_records_the_credential_actor() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(
            client,
            finding.id,
            headers=_auth(_token(principal_id="secops.alice")),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(finding.id)
    assert body["status"] == "ACKNOWLEDGED"
    assert body["tenant_id"] == str(TENANT)

    # The ledger records one append-only row, attributed to the credential.
    assert len(store.transitions) == 1
    record = store.transitions[0]
    assert record.actor_id == "secops.alice"
    assert record.from_status == "OPEN"
    assert record.to_status == "ACKNOWLEDGED"
    assert record.verifier_id is None
    assert record.reason == "triaged by the on-call reviewer"

    # The finding itself moved.
    stored = await repo.get(TENANT, finding.id)
    assert stored is not None
    assert stored.status == "ACKNOWLEDGED"


async def test_verified_records_the_credential_as_the_verifier() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        resolved = await _post_transition(
            client,
            finding.id,
            to_status="RESOLVED",
            headers=_auth(_token(principal_id="secops.alice")),
        )
        verified = await _post_transition(
            client,
            finding.id,
            to_status="VERIFIED",
            reason="postcondition re-checked independently",
            headers=_auth(_token(principal_id="secops.bob")),
        )

    assert resolved.status_code == 200
    assert verified.status_code == 200
    assert verified.json()["status"] == "VERIFIED"
    assert store.transitions[-1].verifier_id == "secops.bob"
    assert store.transitions[-1].actor_id == "secops.bob"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def test_missing_credential_is_401() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.post(
            f"/v1/findings/{finding.id}/transition",
            params={"tenant_id": str(TENANT)},
            json={"to_status": "ACKNOWLEDGED", "reason": "no credential"},
        )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    # No existence leak in the rejection body, and nothing was written.
    assert "finding" not in response.json()["detail"].lower()
    assert store.transitions == []


# ---------------------------------------------------------------------------
# Tenant scoping
# ---------------------------------------------------------------------------


async def test_tenant_outside_principal_membership_is_403() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(
            client,
            finding.id,
            tenant_id=OTHER_TENANT,
            headers=_auth(_token()),
        )

    assert response.status_code == 403
    assert store.transitions == []


async def test_cross_tenant_finding_is_404_and_writes_nothing() -> None:
    repo = FakeFindingsRepo()
    finding = _finding(tenant_id=OTHER_TENANT)
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)
    # The principal belongs to both tenants, so isolation is the control.
    two_tenant_token = _auth(_token(tenants=(TENANT, OTHER_TENANT)))

    async with _client(app) as client:
        response = await _post_transition(client, finding.id, headers=two_tenant_token)

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"
    assert store.transitions == []


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["auditor", "analyst"])
async def test_roles_without_transition_permission_are_403(role: str) -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(
            client,
            finding.id,
            headers=_auth(_token(roles=(role,))),
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "missing permission: finding:transition"
    assert store.transitions == []


async def test_verified_needs_the_separate_verify_permission() -> None:
    """``VERIFIED`` is a stronger authority than an ordinary transition."""
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)
    auditor = _auth(_token(roles=("auditor",)))

    async with _client(app) as client:
        ordinary = await _post_transition(client, finding.id, headers=auditor)
        verified = await _post_transition(client, finding.id, to_status="VERIFIED", headers=auditor)

    assert ordinary.status_code == 403
    assert ordinary.json()["detail"] == "missing permission: finding:transition"
    assert verified.status_code == 403
    assert verified.json()["detail"] == "missing permission: finding:verify"
    assert store.transitions == []


# ---------------------------------------------------------------------------
# Existence
# ---------------------------------------------------------------------------


async def test_unknown_finding_is_404() -> None:
    repo = FakeFindingsRepo()
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(client, uuid.uuid4())

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"
    assert store.transitions == []


# ---------------------------------------------------------------------------
# Domain policy surfaced through the API
# ---------------------------------------------------------------------------


async def test_invalid_transition_is_409_with_a_code() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        # OPEN -> VERIFIED is not an edge of the lifecycle graph.
        response = await _post_transition(client, finding.id, to_status="VERIFIED")

    assert response.status_code == 409
    body = response.json()
    assert body["code"] == "INVALID_TRANSITION"
    assert body["detail"]
    assert store.transitions == []
    stored = await repo.get(TENANT, finding.id)
    assert stored is not None
    assert stored.status == "OPEN"


async def test_terminal_state_cannot_transition() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        escalated = await _post_transition(client, finding.id, to_status="ESCALATED")
        rejected = await _post_transition(client, finding.id, to_status="ACKNOWLEDGED")

    assert escalated.status_code == 200
    assert rejected.status_code == 409
    assert rejected.json()["code"] == "TERMINAL_STATE"


async def test_verifier_may_not_be_the_actor_that_closed_the_finding() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)
    alice = _auth(_token(principal_id="secops.alice"))

    async with _client(app) as client:
        resolved = await _post_transition(client, finding.id, to_status="RESOLVED", headers=alice)
        rejected = await _post_transition(client, finding.id, to_status="VERIFIED", headers=alice)

    assert resolved.status_code == 200
    assert rejected.status_code == 409
    assert rejected.json()["code"] == "VERIFIER_NOT_INDEPENDENT"
    # The finding did not move and no ledger row was appended.
    assert len(store.transitions) == 1
    stored = await repo.get(TENANT, finding.id)
    assert stored is not None
    assert stored.status == "RESOLVED"


async def test_resolved_finding_without_history_fails_closed() -> None:
    """A legacy RESOLVED finding has no recorded close-out actor."""
    repo = FakeFindingsRepo()
    finding = _finding(status="RESOLVED")
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(client, finding.id, to_status="VERIFIED")

    assert response.status_code == 409
    assert response.json()["code"] == "VERIFIER_NOT_INDEPENDENT"
    assert store.transitions == []


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("actor_field", ["actor_id", "reviewer_id", "principal_id", "verifier_id"])
async def test_actor_field_in_body_is_rejected_without_a_write(actor_field: str) -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(
            client,
            finding.id,
            body={"to_status": "ACKNOWLEDGED", "reason": "spoofed", actor_field: "someone.else"},
        )

    assert response.status_code == 422
    assert store.transitions == []
    stored = await repo.get(TENANT, finding.id)
    assert stored is not None
    assert stored.status == "OPEN"


@pytest.mark.parametrize("reason", ["", "   "])
async def test_blank_reason_is_422_without_a_write(reason: str) -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(client, finding.id, reason=reason)

    assert response.status_code == 422
    assert store.transitions == []


async def test_over_long_reason_is_422_without_a_write() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(client, finding.id, reason="x" * 1001)

    assert response.status_code == 422
    assert store.transitions == []


async def test_unknown_target_status_is_422_without_a_write() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await _post_transition(client, finding.id, to_status="APPROVED")

    assert response.status_code == 422
    assert store.transitions == []


# ---------------------------------------------------------------------------
# Fail-closed configuration
# ---------------------------------------------------------------------------


async def test_missing_transition_store_is_503() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    app = _build_app(repo, wire_transitions=False)

    async with _client(app) as client:
        response = await _post_transition(client, finding.id)

    assert response.status_code == 503
    stored = await repo.get(TENANT, finding.id)
    assert stored is not None
    assert stored.status == "OPEN"


# ---------------------------------------------------------------------------
# Ledger read
# ---------------------------------------------------------------------------


async def test_transition_ledger_is_newest_first() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        await _post_transition(client, finding.id, to_status="ACKNOWLEDGED")
        await _post_transition(client, finding.id, to_status="INVESTIGATING")
        listed = await client.get(
            f"/v1/findings/{finding.id}/transitions",
            params={"tenant_id": str(TENANT)},
            headers=_auth(_token()),
        )

    assert listed.status_code == 200
    rows = listed.json()
    assert [row["to_status"] for row in rows] == ["INVESTIGATING", "ACKNOWLEDGED"]
    assert rows[0]["actor_id"] == "reviewer-1"
    assert rows[0]["from_status"] == "ACKNOWLEDGED"


async def test_transition_ledger_is_404_for_another_tenant() -> None:
    repo = FakeFindingsRepo()
    finding = _finding(tenant_id=OTHER_TENANT)
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)
    two_tenant_token = _auth(_token(tenants=(TENANT, OTHER_TENANT)))

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}/transitions",
            params={"tenant_id": str(TENANT)},
            headers=two_tenant_token,
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"


async def test_transition_ledger_requires_tenant_membership() -> None:
    repo = FakeFindingsRepo()
    finding = _finding()
    repo.add(finding)
    store = FakeTransitionsStore(repo)
    app = _build_app(repo, store)

    async with _client(app) as client:
        response = await client.get(
            f"/v1/findings/{finding.id}/transitions",
            params={"tenant_id": str(OTHER_TENANT)},
            headers=_auth(_token()),
        )

    assert response.status_code == 403
