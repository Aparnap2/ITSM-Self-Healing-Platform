"""Integration: append-only review decisions with tenant isolation (Task 14).

Since migration 007 a decision is bound to its finding by a *tenant-composite*
foreign key ``(tenant_id, finding_id) -> findings(tenant_id, id)``: a decision
cannot reference a finding that belongs to another tenant, even if the
application filter is bypassed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from psycopg import errors

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.models import Finding, ReviewDecision, Severity

pytestmark = pytest.mark.integration


async def _seed_finding(repos: RepositoryBundle, tenant: uuid.UUID) -> uuid.UUID:
    finding = Finding(
        id=uuid.uuid4(),
        tenant_id=tenant,
        finding_type="PRIVILEGE_ESCALATION",
        severity=Severity.P2,
        status="OPEN",
        title=f"finding-{uuid.uuid4().hex}",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=60,
        outcome="VIOLATION",
    )
    stored = await repos.findings.upsert(finding)
    return stored.id


async def test_record_and_list_review_decision(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed_finding(repos, tenant)
    d = ReviewDecision(
        tenant_id=tenant,
        finding_id=finding,
        reviewer_id="analyst-1",
        decision="CONFIRMED",
        rationale="evidence supports",
    )
    await repos.review_decisions.record(d)
    listed = await repos.review_decisions.list_for_finding(tenant, finding)
    assert len(listed) == 1
    assert listed[0].decision == "CONFIRMED"
    assert listed[0].rationale == "evidence supports"


async def test_review_decisions_tenant_isolated(repos: RepositoryBundle) -> None:
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    finding_1 = await _seed_finding(repos, t1)
    finding_2 = await _seed_finding(repos, t2)
    await repos.review_decisions.record(
        ReviewDecision(
            tenant_id=t1,
            finding_id=finding_1,
            reviewer_id="a",
            decision="CONFIRMED",
            rationale="r1",
        )
    )
    await repos.review_decisions.record(
        ReviewDecision(
            tenant_id=t2,
            finding_id=finding_2,
            reviewer_id="b",
            decision="FALSE_POSITIVE",
            rationale="r2",
        )
    )
    assert len(await repos.review_decisions.list_for_finding(t1, finding_1)) == 1
    assert len(await repos.review_decisions.list_for_finding(t2, finding_2)) == 1
    # A tenant cannot read another tenant's finding history.
    assert await repos.review_decisions.list_for_finding(t1, finding_2) == []
    assert await repos.review_decisions.list_for_finding(t2, finding_1) == []


async def test_cross_tenant_decision_reference_is_rejected(repos: RepositoryBundle) -> None:
    owner, intruder = uuid.uuid4(), uuid.uuid4()
    finding = await _seed_finding(repos, owner)
    with pytest.raises(errors.ForeignKeyViolation):
        await repos.review_decisions.record(
            ReviewDecision(
                tenant_id=intruder,
                finding_id=finding,
                reviewer_id="mallory",
                decision="FALSE_POSITIVE",
                rationale="cross-tenant reference",
            )
        )


async def test_review_decisions_append_only(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed_finding(repos, tenant)
    d1 = ReviewDecision(
        tenant_id=tenant,
        finding_id=finding,
        reviewer_id="a",
        decision="CONFIRMED",
        rationale="first",
    )
    d2 = ReviewDecision(
        tenant_id=tenant,
        finding_id=finding,
        reviewer_id="b",
        decision="FALSE_POSITIVE",
        rationale="second",
    )
    await repos.review_decisions.record(d1)
    await repos.review_decisions.record(d2)
    listed = await repos.review_decisions.list_for_finding(tenant, finding)
    assert len(listed) == 2
    assert [d.decision for d in listed] == ["CONFIRMED", "FALSE_POSITIVE"]

    # History is readable and unchanged after attempted mutations.
    assert [d.rationale for d in listed] == ["first", "second"]


async def test_review_decisions_cannot_be_updated_or_deleted(
    repos: RepositoryBundle, pg_dsn: str
) -> None:
    """A reviewer decision is audit history: UPDATE/DELETE must fail at the DB.

    The trigger rejects the statement even for a privileged connection, and
    the runtime role lacks the privilege entirely. History stays readable.
    """
    import psycopg
    from psycopg import sql

    tenant = uuid.uuid4()
    finding = await _seed_finding(repos, tenant)
    d = ReviewDecision(
        tenant_id=tenant,
        finding_id=finding,
        reviewer_id="a",
        decision="CONFIRMED",
        rationale="original",
    )
    await repos.review_decisions.record(d)

    admin = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
    try:
        # Trigger must reject UPDATE.
        with pytest.raises(psycopg.errors.RaiseException):
            await admin.execute(
                sql.SQL("UPDATE review_decisions SET rationale = %s WHERE id = %s"),
                ("tampered", d.id),
            )
        # Trigger must reject DELETE.
        with pytest.raises(psycopg.errors.RaiseException):
            await admin.execute(
                sql.SQL("DELETE FROM review_decisions WHERE id = %s"),
                (d.id,),
            )
    finally:
        await admin.close()

    # History is unchanged and still readable.
    listed = await repos.review_decisions.list_for_finding(tenant, finding)
    assert len(listed) == 1
    assert listed[0].rationale == "original"


async def test_review_decisions_runtime_role_cannot_mutate(pg_dsn: str, runtime_dsn: str) -> None:
    """itsm_app lacks UPDATE/DELETE/TRUNCATE on review_decisions."""
    import psycopg

    # Seed a decision as the admin role so the runtime role has a row to target.
    tenant = uuid.uuid4()
    finding_id = uuid.uuid4()
    decision_id = uuid.uuid4()
    admin = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
    try:
        await admin.execute(
            "INSERT INTO findings (id, tenant_id, finding_type, severity, status, "
            "title, description, detected_at, rule_version, risk_score, outcome) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, now(), %s, %s, %s)",
            (
                finding_id,
                tenant,
                "PRIVILEGE_ESCALATION",
                "P2",
                "OPEN",
                "t",
                "d",
                "rule-v1",
                60,
                "VIOLATION",
            ),
        )
        await admin.execute(
            "INSERT INTO review_decisions (id, tenant_id, finding_id, reviewer_id, "
            "decision, rationale) VALUES (%s, %s, %s, %s, %s, %s)",
            (decision_id, tenant, finding_id, "a", "CONFIRMED", "r"),
        )
    finally:
        await admin.close()

    runtime = await psycopg.AsyncConnection.connect(runtime_dsn, autocommit=True)
    try:
        await runtime.execute("SELECT set_config('itsm.tenant_id', %s, false)", (str(tenant),))
        # SELECT works.
        cur = await runtime.execute("SELECT id FROM review_decisions WHERE id = %s", (decision_id,))
        assert await cur.fetchone() is not None
        # INSERT works.
        new_id = uuid.uuid4()
        await runtime.execute(
            "INSERT INTO review_decisions (id, tenant_id, finding_id, reviewer_id, "
            "decision, rationale) VALUES (%s, %s, %s, %s, %s, %s)",
            (new_id, tenant, finding_id, "b", "CONFIRMED", "r2"),
        )
        # UPDATE is denied (privilege).
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await runtime.execute(
                "UPDATE review_decisions SET rationale = %s WHERE id = %s",
                ("x", decision_id),
            )
        # DELETE is denied (privilege).
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await runtime.execute("DELETE FROM review_decisions WHERE id = %s", (decision_id,))
        # TRUNCATE is denied (privilege).
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await runtime.execute("TRUNCATE review_decisions")
    finally:
        await runtime.close()

    # Cleanup as admin. TRUNCATE bypasses row-level triggers (which would
    # otherwise reject DELETE on append-only tables) and CASCADE handles FKs.
    admin = await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)
    try:
        await admin.execute("TRUNCATE review_decisions, findings CASCADE")
    finally:
        await admin.close()
