"""Integration: the investigation ledger on real PostgreSQL.

The ledger is the audit trail of the optional agentic stage, so these tests
check the properties that make it trustworthy:

* a selected finding produces exactly one request row and no proposal row
  when no model is configured (deterministic, offline);
* an unselected finding (coverage gap) produces nothing at all;
* the ledger is tenant-isolated at the SQL level, not just in the application;
* the ledger is append-only at the database level;
* request/proposal counts stay consistent with the selected findings.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from psycopg import errors

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.events import InvestigationProposal
from itsm_agent.domain.investigation_policy import should_investigate
from itsm_agent.domain.models import Finding, Severity
from itsm_agent.investigations.service import InvestigationService

pytestmark = pytest.mark.integration


async def _seed_finding(
    repos: RepositoryBundle,
    tenant: uuid.UUID,
    *,
    severity: Severity = Severity.P1,
    outcome: str = "VIOLATION",
    risk_score: int = 70,
) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        tenant_id=tenant,
        finding_type="PRIVILEGE_ESCALATION",
        severity=severity,
        status="OPEN",
        title=f"finding-{uuid.uuid4().hex}",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=risk_score,
        outcome=outcome,
    )
    return await repos.findings.upsert(finding)


async def _investigate(repos: RepositoryBundle, tenant: uuid.UUID, finding: Finding) -> str:
    service = InvestigationService(repos.investigation, model=None)
    return await service.investigate_finding(
        tenant_id=tenant,
        finding=finding,
        evidence_snapshot_ids=[],
        requested_by="integration-test",
    )


async def test_selected_finding_records_one_skipped_request(
    repos: RepositoryBundle,
) -> None:
    tenant = uuid.uuid4()
    selected = await _seed_finding(repos, tenant)
    gap = await _seed_finding(
        repos, tenant, severity=Severity.P4, outcome="COVERAGE_GAP", risk_score=5
    )

    assert should_investigate(selected, enabled=True)
    assert not should_investigate(gap, enabled=True)

    status = await _investigate(repos, tenant, selected)
    assert status == "SKIPPED"

    requests = await repos.investigation.list_requests_for_finding(tenant, selected.id)
    assert len(requests) == 1
    assert requests[0].status == "SKIPPED"
    assert requests[0].tenant_id == tenant
    assert requests[0].finding_id == selected.id
    assert requests[0].requested_by == "integration-test"
    assert requests[0].max_tool_calls == 5
    assert requests[0].max_model_calls == 2

    assert await repos.investigation.list_proposals_for_finding(tenant, selected.id) == []
    # An unselected finding produces nothing.
    assert await repos.investigation.list_requests_for_finding(tenant, gap.id) == []
    assert await repos.investigation.list_proposals_for_finding(tenant, gap.id) == []


async def test_investigation_does_not_change_the_finding_status(
    repos: RepositoryBundle,
) -> None:
    tenant = uuid.uuid4()
    finding = await _seed_finding(repos, tenant)

    await _investigate(repos, tenant, finding)

    stored = await repos.findings.get(tenant, finding.id)
    assert stored is not None
    assert stored.status == "OPEN"


async def test_request_count_matches_the_number_of_selected_findings(
    repos: RepositoryBundle,
) -> None:
    tenant = uuid.uuid4()
    selected = [await _seed_finding(repos, tenant) for _ in range(3)]
    unselected = [
        await _seed_finding(repos, tenant, severity=Severity.P4, outcome="COVERAGE_GAP")
        for _ in range(2)
    ]

    for finding in selected:
        assert await _investigate(repos, tenant, finding) == "SKIPPED"

    total_requests = 0
    for finding in selected:
        rows = await repos.investigation.list_requests_for_finding(tenant, finding.id)
        total_requests += len(rows)
        assert len(rows) == 1
    for finding in unselected:
        assert await repos.investigation.list_requests_for_finding(tenant, finding.id) == []

    assert total_requests == len(selected)
    assert len(await repos.investigation.list_proposals_for_finding(tenant, selected[0].id)) == 0


async def test_ledger_is_tenant_isolated(repos: RepositoryBundle) -> None:
    owner, intruder = uuid.uuid4(), uuid.uuid4()
    finding = await _seed_finding(repos, owner)

    await _investigate(repos, owner, finding)

    # The intruder cannot read another tenant's ledger rows.
    assert await repos.investigation.list_requests_for_finding(intruder, finding.id) == []
    assert await repos.investigation.list_proposals_for_finding(intruder, finding.id) == []


async def test_cross_tenant_proposal_reference_is_rejected(
    repos: RepositoryBundle,
) -> None:
    owner, intruder = uuid.uuid4(), uuid.uuid4()
    finding = await _seed_finding(repos, owner)
    await _investigate(repos, owner, finding)
    requests = await repos.investigation.list_requests_for_finding(owner, finding.id)
    assert len(requests) == 1

    proposal = InvestigationProposal(
        investigation_id=requests[0].id,
        hypothesis="cross-tenant proposal attempt",
        supporting_evidence=[],
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="high",
        recommended_disposition="CONFIRM",
        model_version="m1",
        prompt_version="p1",
    )
    with pytest.raises(errors.ForeignKeyViolation):
        await repos.investigation.record_proposal(
            proposal,
            tenant_id=intruder,
            request_id=requests[0].id,
            finding_id=finding.id,
            model_calls_used=1,
        )


async def test_ledger_is_append_only(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = await _seed_finding(repos, tenant)
    await _investigate(repos, tenant, finding)

    async with repos._pool.connection() as conn:  # noqa: SLF001 - direct DB assertion
        with pytest.raises(errors.RaiseException):
            async with conn.transaction():
                await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(tenant),))
                await conn.execute(
                    "UPDATE investigation_requests SET question = 'rewritten' WHERE tenant_id = %s",
                    (tenant,),
                )
        with pytest.raises(errors.RaiseException):
            async with conn.transaction():
                await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(tenant),))
                await conn.execute(
                    "DELETE FROM investigation_requests WHERE tenant_id = %s", (tenant,)
                )

    # The row survived the rejected mutation.
    requests = await repos.investigation.list_requests_for_finding(tenant, finding.id)
    assert len(requests) == 1
    assert requests[0].status == "SKIPPED"
