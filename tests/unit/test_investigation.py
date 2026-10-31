"""Unit tests for selective investigation (no LLM)."""

from __future__ import annotations

import uuid

import pytest

from itsm_agent.domain.events import InvestigationProposal, InvestigationRequest
from itsm_agent.investigations.orchestrator import (
    InvestigationBudgetExceeded,
    run_investigation,
)


def _req(evidence_ids: list[uuid.UUID]) -> InvestigationRequest:
    return InvestigationRequest(
        investigation_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        evidence_snapshot_ids=evidence_ids,
        question="Why did this happen?",
        max_tool_calls=5,
        max_model_calls=2,
    )


class FakeModel:
    def __init__(self, proposal: InvestigationProposal) -> None:
        self.proposal = proposal
        self.calls = 0

    async def investigate(
        self, request: InvestigationRequest, evidence: dict[uuid.UUID, str]
    ) -> InvestigationProposal:
        self.calls += 1
        return self.proposal


@pytest.mark.asyncio
async def test_valid_proposal_accepted() -> None:
    eid = uuid.uuid4()
    req = _req([eid])
    prop = InvestigationProposal(
        investigation_id=req.investigation_id,
        hypothesis="test hypothesis",
        supporting_evidence=[eid],
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="low",
        recommended_disposition="CONFIRM",
        model_version="m1",
        prompt_version="p1",
    )
    model = FakeModel(prop)

    async def fetcher(ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        return {i: "redacted summary" for i in ids}

    result = await run_investigation(req, fetch_evidence=fetcher, model=model)
    assert result.hypothesis == "test hypothesis"
    assert model.calls == 1


@pytest.mark.asyncio
async def test_invalid_evidence_reference_rejected() -> None:
    eid = uuid.uuid4()
    bad = uuid.uuid4()
    req = _req([eid])
    prop = InvestigationProposal(
        investigation_id=req.investigation_id,
        hypothesis="h",
        supporting_evidence=[bad],  # not in snapshot
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="u",
        recommended_disposition="CONFIRM",
        model_version="m1",
        prompt_version="p1",
    )
    model = FakeModel(prop)

    async def fetcher(ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        return {i: "s" for i in ids}

    with pytest.raises(ValueError):
        await run_investigation(req, fetch_evidence=fetcher, model=model)


@pytest.mark.asyncio
async def test_budget_exhausted() -> None:
    eid = uuid.uuid4()
    req = _req([eid])
    prop = InvestigationProposal(
        investigation_id=req.investigation_id,
        hypothesis="h",
        supporting_evidence=[],
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="u",
        recommended_disposition="CONFIRM",
        model_version="m1",
        prompt_version="p1",
    )
    model = FakeModel(prop)

    async def fetcher(ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        return {}

    with pytest.raises(InvestigationBudgetExceeded):
        await run_investigation(req, fetch_evidence=fetcher, model=model, model_calls_used=2)


@pytest.mark.asyncio
async def test_investigation_id_mismatch_rejected() -> None:
    eid = uuid.uuid4()
    req = _req([eid])
    prop = InvestigationProposal(
        investigation_id=uuid.uuid4(),  # mismatch
        hypothesis="h",
        supporting_evidence=[],
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="u",
        recommended_disposition="CONFIRM",
        model_version="m1",
        prompt_version="p1",
    )
    model = FakeModel(prop)

    async def fetcher(ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        return {}

    with pytest.raises(ValueError):
        await run_investigation(req, fetch_evidence=fetcher, model=model)


pytestmark = pytest.mark.unit
