"""Integration: append-only review decisions with tenant isolation (Task 14)."""

from __future__ import annotations

import uuid

import pytest

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.models import ReviewDecision

pytestmark = pytest.mark.integration


async def test_record_and_list_review_decision(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = uuid.uuid4()
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
    finding = uuid.uuid4()
    await repos.review_decisions.record(
        ReviewDecision(tenant_id=t1, finding_id=finding, reviewer_id="a", decision="CONFIRMED", rationale="r1")
    )
    await repos.review_decisions.record(
        ReviewDecision(tenant_id=t2, finding_id=finding, reviewer_id="b", decision="FALSE_POSITIVE", rationale="r2")
    )
    assert len(await repos.review_decisions.list_for_finding(t1, finding)) == 1
    assert len(await repos.review_decisions.list_for_finding(t2, finding)) == 1
    assert (await repos.review_decisions.list_for_finding(t1, finding))[0].decision == "CONFIRMED"


async def test_review_decisions_append_only(repos: RepositoryBundle) -> None:
    tenant = uuid.uuid4()
    finding = uuid.uuid4()
    d1 = ReviewDecision(tenant_id=tenant, finding_id=finding, reviewer_id="a", decision="CONFIRMED", rationale="first")
    d2 = ReviewDecision(tenant_id=tenant, finding_id=finding, reviewer_id="b", decision="FALSE_POSITIVE", rationale="second")
    await repos.review_decisions.record(d1)
    await repos.review_decisions.record(d2)
    listed = await repos.review_decisions.list_for_finding(tenant, finding)
    assert len(listed) == 2
    assert [d.decision for d in listed] == ["CONFIRMED", "FALSE_POSITIVE"]