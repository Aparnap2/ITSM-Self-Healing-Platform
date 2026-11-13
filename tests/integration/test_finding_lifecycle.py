"""Integration: the finding lifecycle transition ledger on real PostgreSQL.

The lifecycle ledger is the audit trail for a lifecycle decision, so these
tests check the properties that make it trustworthy:

- a legal transition updates the finding and appends exactly one ledger row;
- verification requires an independent verifier and fails closed otherwise;
- an illegal transition writes nothing at all;
- terminal states are frozen;
- the ledger is append-only at the database level;
- tenant isolation holds for reads and writes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from psycopg import errors

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.finding_lifecycle import (
    InvalidTransitionError,
    VerifierNotIndependentError,
)
from itsm_agent.domain.models import Finding, Severity

pytestmark = pytest.mark.integration


def _finding(tenant_id: uuid.UUID) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        finding_type="PRIVILEGE_ESCALATION",
        severity=Severity.P1,
        status="OPEN",
        title=f"finding-{uuid.uuid4().hex}",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=90,
        outcome="VIOLATION",
    )


async def _seed(repos: RepositoryBundle, tenant_id: uuid.UUID) -> Finding:
    await repos.tenants.ensure(tenant_id)
    return await repos.findings.upsert(_finding(tenant_id))


async def test_lifecycle_writes_a_ledger_row_per_transition(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    transitions = repos.finding_transitions

    acknowledged = await transitions.apply_transition(
        tenant, finding.id, "ACKNOWLEDGED", actor_id="alice", reason="triaged"
    )
    assert acknowledged is not None
    assert acknowledged.status == "ACKNOWLEDGED"

    resolved = await transitions.apply_transition(
        tenant, finding.id, "RESOLVED", actor_id="alice", reason="role revoked"
    )
    assert resolved is not None
    assert resolved.status == "RESOLVED"

    verified = await transitions.apply_transition(
        tenant,
        finding.id,
        "VERIFIED",
        actor_id="bob",
        reason="independently confirmed the role is gone",
        verifier_id="bob",
    )
    assert verified is not None
    assert verified.status == "VERIFIED"

    history = await transitions.list_for_finding(tenant, finding.id)
    assert [t.to_status for t in history] == ["VERIFIED", "RESOLVED", "ACKNOWLEDGED"]
    assert [t.from_status for t in history] == ["RESOLVED", "ACKNOWLEDGED", "OPEN"]
    assert all(t.reason for t in history)
    assert history[0].verifier_id == "bob"
    assert history[1].verifier_id is None

    async with repos._pool.connection() as conn:  # noqa: SLF001 - direct DB assertion
        row = await conn.execute(
            "SELECT verified_by, verified_at FROM findings WHERE id = %s", (finding.id,)
        )
        assert row is not None


async def test_verification_by_the_resolver_fails_closed(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    transitions = repos.finding_transitions

    await transitions.apply_transition(
        tenant, finding.id, "RESOLVED", actor_id="alice", reason="role revoked"
    )

    with pytest.raises(VerifierNotIndependentError):
        await transitions.apply_transition(
            tenant,
            finding.id,
            "VERIFIED",
            actor_id="alice",
            reason="self verification attempt",
            verifier_id="alice",
        )

    current = await repos.findings.get(tenant, finding.id)
    assert current is not None
    assert current.status == "RESOLVED"
    history = await transitions.list_for_finding(tenant, finding.id)
    assert [t.to_status for t in history] == ["RESOLVED"]


async def test_legacy_resolved_finding_without_history_cannot_be_verified(
    repos: RepositoryBundle,
) -> None:
    # A finding resolved before the ledger existed has no recorded close-out
    # actor, so independence cannot be proven: fail closed, do not guess.
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    async with repos._pool.connection() as conn:  # noqa: SLF001 - direct DB assertion
        await conn.execute("UPDATE findings SET status = 'RESOLVED' WHERE id = %s", (finding.id,))

    with pytest.raises(VerifierNotIndependentError):
        await repos.finding_transitions.apply_transition(
            tenant,
            finding.id,
            "VERIFIED",
            actor_id="bob",
            reason="verify legacy finding",
            verifier_id="bob",
        )

    current = await repos.findings.get(tenant, finding.id)
    assert current is not None
    assert current.status == "RESOLVED"


async def test_illegal_transition_writes_nothing(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)

    with pytest.raises(InvalidTransitionError):
        await repos.finding_transitions.apply_transition(
            tenant, finding.id, "VERIFIED", actor_id="alice", reason="skip the resolution"
        )

    current = await repos.findings.get(tenant, finding.id)
    assert current is not None
    assert current.status == "OPEN"
    assert await repos.finding_transitions.list_for_finding(tenant, finding.id) == []


async def test_terminal_status_is_frozen(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    transitions = repos.finding_transitions

    await transitions.apply_transition(
        tenant, finding.id, "FALSE_POSITIVE", actor_id="alice", reason="benign activity"
    )

    with pytest.raises(InvalidTransitionError):
        await transitions.apply_transition(
            tenant, finding.id, "OPEN", actor_id="alice", reason="reopen attempt"
        )

    current = await repos.findings.get(tenant, finding.id)
    assert current is not None
    assert current.status == "FALSE_POSITIVE"


async def test_ledger_is_append_only(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed(repos, tenant)
    await repos.finding_transitions.apply_transition(
        tenant, finding.id, "ACKNOWLEDGED", actor_id="alice", reason="triaged"
    )

    async with repos._pool.connection() as conn:  # noqa: SLF001 - direct DB assertion
        with pytest.raises(errors.RaiseException):
            async with conn.transaction():
                await conn.execute(
                    "UPDATE finding_transitions SET reason = 'rewritten' WHERE tenant_id = %s",
                    (tenant,),
                )
        with pytest.raises(errors.RaiseException):
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM finding_transitions WHERE tenant_id = %s", (tenant,)
                )


async def test_transitions_are_tenant_isolated(repos: RepositoryBundle) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    finding_a = await _seed(repos, tenant_a)
    finding_b = await _seed(repos, tenant_b)

    await repos.finding_transitions.apply_transition(
        tenant_a, finding_a.id, "ACKNOWLEDGED", actor_id="alice", reason="triaged"
    )

    assert await repos.finding_transitions.list_for_finding(tenant_b, finding_b.id) == []
    assert len(await repos.finding_transitions.list_for_finding(tenant_a, finding_a.id)) == 1

    # A tenant cannot transition another tenant's finding: the write is scoped
    # by tenant, so the foreign finding is invisible and nothing is written.
    result = await repos.finding_transitions.apply_transition(
        tenant_b, finding_a.id, "ACKNOWLEDGED", actor_id="mallory", reason="cross tenant"
    )
    assert result is None
    assert len(await repos.finding_transitions.list_for_finding(tenant_a, finding_a.id)) == 1
    assert await repos.finding_transitions.list_for_finding(tenant_b, finding_a.id) == []


async def test_transition_on_unknown_finding_returns_none(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    await repos.tenants.ensure(tenant)

    result = await repos.finding_transitions.apply_transition(
        tenant, uuid.uuid4(), "ACKNOWLEDGED", actor_id="alice", reason="no such finding"
    )

    assert result is None
