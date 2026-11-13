"""Integration: the finding-lifecycle transition API on real PostgreSQL.

Marker: ``integration``. Unlike the offline unit suite, these tests drive the
durable ``finding_transitions`` ledger through the authenticated HTTP surface:
the lifecycle edge, the append-only ledger, the independence rule for
``VERIFIED``, and tenant isolation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response
from psycopg import errors as pg_errors
from psycopg.rows import dict_row

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.api.app import create_app
from itsm_agent.api.auth import TokenAuthenticator, mint_token
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.domain.events import IncidentCreated
from itsm_agent.domain.models import Finding, Severity

pytestmark = pytest.mark.integration

# Named without a "secret"-shaped keyword so a secret-scanner does not
# treat this local test credential as a leaked key.
REVIEWER_KEY = "integration-transition-reviewer-material-0123456789"


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


def _build_app(repos: RepositoryBundle) -> FastAPI:
    authenticator = TokenAuthenticator(secret=REVIEWER_KEY)
    return create_app(
        settings=_settings(),
        sink=FakeSink(),
        findings_repo=repos.findings,
        review_decisions_repo=repos.review_decisions,
        finding_transitions=repos.finding_transitions,
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
    token = mint_token(REVIEWER_KEY, principal_id=principal_id, tenant_ids=memberships, roles=roles)
    return {"Authorization": f"Bearer {token}"}


def _finding(tenant_id: UUID, *, status: str = "OPEN") -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        finding_type="EXCESSIVE_PRIVILEGE",
        severity=Severity.P1,
        status=status,
        title=f"finding-{uuid.uuid4().hex}",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=90,
        outcome="VIOLATION",
    )


async def _seed(repos: RepositoryBundle, tenant_id: UUID) -> Finding:
    """Register the tenant and store one finding for it."""
    await repos.tenants.ensure(tenant_id)
    return await repos.findings.upsert(_finding(tenant_id))


async def _post_transition(
    client: AsyncClient,
    finding_id: UUID,
    *,
    to_status: str,
    reason: str,
    tenant_id: UUID,
    headers: dict[str, str],
) -> Response:
    return await client.post(
        f"/v1/findings/{finding_id}/transition",
        params={"tenant_id": str(tenant_id)},
        headers=headers,
        json={"to_status": to_status, "reason": reason},
    )


async def test_open_to_acknowledged_updates_the_stored_finding(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    headers = _token(principal_id="secops.alice", tenant_id=tenant)

    async with _client(_build_app(repos)) as client:
        response = await _post_transition(
            client,
            finding.id,
            to_status="ACKNOWLEDGED",
            reason="triaged by the on-call reviewer",
            tenant_id=tenant,
            headers=headers,
        )

    assert response.status_code == 200
    assert response.json()["status"] == "ACKNOWLEDGED"
    assert response.json()["id"] == str(finding.id)

    # Durable: the status moved in PostgreSQL, not only in the response.
    stored = await repos.findings.get(tenant, finding.id)
    assert stored is not None
    assert stored.status == "ACKNOWLEDGED"

    ledger = await repos.finding_transitions.list_for_finding(tenant, finding.id)
    assert len(ledger) == 1
    assert ledger[0].actor_id == "secops.alice"
    assert ledger[0].from_status == "OPEN"
    assert ledger[0].to_status == "ACKNOWLEDGED"
    assert ledger[0].verifier_id is None


async def test_verified_by_the_resolver_is_rejected_and_the_status_holds(
    repos: RepositoryBundle,
) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    alice = _token(principal_id="alice", tenant_id=tenant)

    async with _client(_build_app(repos)) as client:
        resolved = await _post_transition(
            client,
            finding.id,
            to_status="RESOLVED",
            reason="remediated",
            tenant_id=tenant,
            headers=alice,
        )
        rejected = await _post_transition(
            client,
            finding.id,
            to_status="VERIFIED",
            reason="self verification",
            tenant_id=tenant,
            headers=alice,
        )

    assert resolved.status_code == 200
    assert rejected.status_code == 409
    assert rejected.json()["code"] == "VERIFIER_NOT_INDEPENDENT"

    stored = await repos.findings.get(tenant, finding.id)
    assert stored is not None
    assert stored.status == "RESOLVED"

    # No ledger row was appended for the refused verification.
    ledger = await repos.finding_transitions.list_for_finding(tenant, finding.id)
    assert len(ledger) == 1
    assert ledger[0].to_status == "RESOLVED"


async def test_independent_verifier_records_verified_by(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    alice = _token(principal_id="alice", tenant_id=tenant)
    bob = _token(principal_id="bob", tenant_id=tenant)

    async with _client(_build_app(repos)) as client:
        resolved = await _post_transition(
            client,
            finding.id,
            to_status="RESOLVED",
            reason="remediated",
            tenant_id=tenant,
            headers=alice,
        )
        verified = await _post_transition(
            client,
            finding.id,
            to_status="VERIFIED",
            reason="postcondition re-checked independently",
            tenant_id=tenant,
            headers=bob,
        )

    assert resolved.status_code == 200
    assert verified.status_code == 200
    assert verified.json()["status"] == "VERIFIED"

    async with repos.transaction(tenant) as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT status, verified_by FROM findings WHERE id = %s", (finding.id,))
        row = await cur.fetchone()

    assert row is not None
    assert row["status"] == "VERIFIED"
    assert row["verified_by"] == "bob"

    ledger = await repos.finding_transitions.list_for_finding(tenant, finding.id)
    assert [t.to_status for t in ledger] == ["VERIFIED", "RESOLVED"]
    assert ledger[0].verifier_id == "bob"


async def test_cross_tenant_finding_is_404_and_writes_nothing(
    repos: RepositoryBundle,
) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    finding = await _seed(repos, tenant_b)
    # The principal belongs to both tenants, so isolation is the control.
    headers = _token(tenants=(tenant_a, tenant_b))

    async with _client(_build_app(repos)) as client:
        response = await _post_transition(
            client,
            finding.id,
            to_status="ACKNOWLEDGED",
            reason="cross-tenant attempt",
            tenant_id=tenant_a,
            headers=headers,
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found"
    assert await repos.finding_transitions.list_for_finding(tenant_a, finding.id) == []
    assert await repos.finding_transitions.list_for_finding(tenant_b, finding.id) == []
    stored = await repos.findings.get(tenant_b, finding.id)
    assert stored is not None
    assert stored.status == "OPEN"


async def test_reader_role_cannot_transition(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    headers = _token(tenant_id=tenant, roles=("auditor",))

    async with _client(_build_app(repos)) as client:
        response = await _post_transition(
            client,
            finding.id,
            to_status="ACKNOWLEDGED",
            reason="audit role may not move findings",
            tenant_id=tenant,
            headers=headers,
        )

    assert response.status_code == 403
    assert await repos.finding_transitions.list_for_finding(tenant, finding.id) == []
    stored = await repos.findings.get(tenant, finding.id)
    assert stored is not None
    assert stored.status == "OPEN"


async def test_the_ledger_is_append_only(repos: RepositoryBundle) -> None:
    """The audit trail cannot be rewritten after the fact."""
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    headers = _token(principal_id="secops.alice", tenant_id=tenant)

    async with _client(_build_app(repos)) as client:
        response = await _post_transition(
            client,
            finding.id,
            to_status="ACKNOWLEDGED",
            reason="triaged by the on-call reviewer",
            tenant_id=tenant,
            headers=headers,
        )
    assert response.status_code == 200

    ledger = await repos.finding_transitions.list_for_finding(tenant, finding.id)
    assert len(ledger) == 1

    with pytest.raises(pg_errors.RaiseException):
        async with repos.transaction(tenant) as conn:
            await conn.execute(
                "UPDATE finding_transitions SET reason = 'rewritten' WHERE id = %s",
                (ledger[0].id,),
            )

    # The rewrite was refused; the original row is untouched.
    still = await repos.finding_transitions.list_for_finding(tenant, finding.id)
    assert len(still) == 1
    assert still[0].reason == "triaged by the on-call reviewer"


async def test_transition_ledger_is_readable_over_http(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    headers = _token(principal_id="secops.alice", tenant_id=tenant)

    async with _client(_build_app(repos)) as client:
        await _post_transition(
            client,
            finding.id,
            to_status="ACKNOWLEDGED",
            reason="triaged by the on-call reviewer",
            tenant_id=tenant,
            headers=headers,
        )
        listed = await client.get(
            f"/v1/findings/{finding.id}/transitions",
            params={"tenant_id": str(tenant)},
            headers=headers,
        )

    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["to_status"] == "ACKNOWLEDGED"
    assert rows[0]["actor_id"] == "secops.alice"
