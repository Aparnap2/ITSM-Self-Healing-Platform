"""Unit tests for the bounded investigation service (no network, no real LLM).

The service is the only place where a model can influence the pipeline, so
these tests pin the safety properties:

* with no model configured the stage is deterministic and offline;
* a proposal is stored verbatim and never applied to the finding lifecycle;
* an out-of-snapshot evidence reference or an exhausted budget is recorded as
  FAILED and produces no proposal row;
* evidence handed to the model is redacted and bounded.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from itsm_agent.domain.events import InvestigationProposal, InvestigationRequest
from itsm_agent.domain.investigation_policy import (
    InvestigationProposalRecord,
    InvestigationRequestRecord,
    current_request_status,
)
from itsm_agent.domain.models import Finding, Severity
from itsm_agent.investigations.orchestrator import InvestigationBudgetExceeded
from itsm_agent.investigations.service import InvestigationService

pytestmark = pytest.mark.unit


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
        risk_score=70,
        outcome="VIOLATION",
    )


class FakeLedger:
    """In-memory append-only ledger implementing the service's port."""

    def __init__(self) -> None:
        self.requests: list[InvestigationRequestRecord] = []
        self.proposals: list[InvestigationProposalRecord] = []

    async def record_request(
        self,
        request: InvestigationRequest,
        *,
        requested_by: str,
        status: str = "REQUESTED",
        row_id: uuid.UUID | None = None,
        created_at: datetime | None = None,
    ) -> InvestigationRequestRecord:
        record = InvestigationRequestRecord(
            id=row_id or request.investigation_id,
            tenant_id=request.tenant_id,
            finding_id=request.finding_id,
            requested_by=requested_by,
            question=request.question,
            evidence_snapshot_ids=list(request.evidence_snapshot_ids),
            max_tool_calls=request.max_tool_calls,
            max_model_calls=request.max_model_calls,
            status=status,
            created_at=created_at or datetime.now(UTC),
        )
        self.requests.append(record)
        return record

    async def record_proposal(
        self,
        proposal: InvestigationProposal,
        *,
        tenant_id: uuid.UUID,
        request_id: uuid.UUID,
        finding_id: uuid.UUID,
        model_calls_used: int,
        created_at: datetime | None = None,
    ) -> InvestigationProposalRecord:
        record = InvestigationProposalRecord(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            request_id=request_id,
            finding_id=finding_id,
            hypothesis=proposal.hypothesis,
            supporting_evidence=list(proposal.supporting_evidence),
            contradicting_evidence=list(proposal.contradicting_evidence),
            missing_evidence=list(proposal.missing_evidence),
            uncertainty=proposal.uncertainty,
            recommended_disposition=proposal.recommended_disposition,
            model_calls_used=model_calls_used,
            created_at=created_at or datetime.now(UTC),
        )
        self.proposals.append(record)
        return record


class FakeModel:
    """Deterministic stand-in for the agentic model."""

    def __init__(
        self,
        *,
        hypothesis: str = "the principal was not authorized",
        disposition: str = "CONFIRM",
        supporting: list[uuid.UUID] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.hypothesis = hypothesis
        self.disposition = disposition
        self.supporting = supporting
        self.error = error
        self.calls = 0
        self.evidence: dict[uuid.UUID, str] = {}

    async def investigate(
        self, request: InvestigationRequest, evidence: dict[uuid.UUID, str]
    ) -> InvestigationProposal:
        self.calls += 1
        self.evidence = evidence
        if self.error is not None:
            raise self.error
        supporting = (
            self.supporting if self.supporting is not None else list(request.evidence_snapshot_ids)
        )
        return InvestigationProposal(
            investigation_id=request.investigation_id,
            hypothesis=self.hypothesis,
            supporting_evidence=list(supporting),
            contradicting_evidence=[],
            missing_evidence=["approval record"],
            uncertainty="medium",
            recommended_disposition=self.disposition,
            model_version="m1",
            prompt_version="p1",
        )


def _service(
    ledger: FakeLedger,
    model: FakeModel | None = None,
    evidence_source: object = None,
) -> InvestigationService:
    return InvestigationService(
        ledger,
        model=model,
        clock=lambda: datetime.now(UTC),
        evidence_source=evidence_source,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# No model configured: deterministic, offline, no proposal.
# ---------------------------------------------------------------------------


async def test_without_model_the_request_is_skipped() -> None:
    tenant = uuid.uuid4()
    ledger = FakeLedger()
    service = _service(ledger, model=None)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=_finding(tenant),
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
    )

    assert status == "SKIPPED"
    assert len(ledger.requests) == 1
    assert ledger.requests[0].status == "SKIPPED"
    assert ledger.requests[0].requested_by == "detection-pipeline"
    assert ledger.proposals == []


# ---------------------------------------------------------------------------
# Model configured: proposal recorded, status COMPLETED.
# ---------------------------------------------------------------------------


async def test_valid_proposal_is_recorded_and_completed() -> None:
    tenant = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ledger = FakeLedger()
    model = FakeModel(hypothesis="missing approval record", disposition="CONFIRM")
    service = _service(ledger, model=model)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=_finding(tenant),
        evidence_snapshot_ids=[evidence_id],
        requested_by="detection-pipeline",
    )

    assert status == "COMPLETED"
    assert model.calls == 1
    assert len(ledger.proposals) == 1
    proposal = ledger.proposals[0]
    assert proposal.hypothesis == "missing approval record"
    assert proposal.recommended_disposition == "CONFIRM"
    assert proposal.tenant_id == tenant
    assert proposal.request_id == ledger.requests[0].id
    # The ledger is append-only: the REQUESTED row is followed by a terminal row.
    assert [r.status for r in ledger.requests] == ["REQUESTED", "COMPLETED"]
    assert current_request_status(ledger.requests) == "COMPLETED"


async def test_disposition_is_stored_verbatim_and_finding_is_untouched() -> None:
    tenant = uuid.uuid4()
    ledger = FakeLedger()
    model = FakeModel(hypothesis="h", disposition="NEEDS_MORE_EVIDENCE")
    service = _service(ledger, model=model)
    finding = _finding(tenant)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=finding,
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
    )

    assert status == "COMPLETED"
    assert ledger.proposals[0].recommended_disposition == "NEEDS_MORE_EVIDENCE"
    # A proposal is not an authorization: the finding lifecycle is untouched.
    assert finding.status == "OPEN"


# ---------------------------------------------------------------------------
# Failure paths: recorded as FAILED, never a proposal.
# ---------------------------------------------------------------------------


async def test_out_of_snapshot_evidence_reference_fails_closed() -> None:
    tenant = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ledger = FakeLedger()
    model = FakeModel(supporting=[uuid.uuid4()])
    service = _service(ledger, model=model)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=_finding(tenant),
        evidence_snapshot_ids=[evidence_id],
        requested_by="detection-pipeline",
    )

    assert status == "FAILED"
    assert ledger.proposals == []
    assert [r.status for r in ledger.requests] == ["REQUESTED", "FAILED"]
    assert current_request_status(ledger.requests) == "FAILED"


async def test_exhausted_budget_is_recorded_as_failed() -> None:
    tenant = uuid.uuid4()
    ledger = FakeLedger()
    model = FakeModel(error=InvestigationBudgetExceeded("model call budget exhausted"))
    service = _service(ledger, model=model)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=_finding(tenant),
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
    )

    assert status == "FAILED"
    assert ledger.proposals == []
    assert [r.status for r in ledger.requests] == ["REQUESTED", "FAILED"]


async def test_unexpected_model_error_is_recorded_as_failed() -> None:
    tenant = uuid.uuid4()
    ledger = FakeLedger()
    model = FakeModel(error=RuntimeError("model backend unavailable"))
    service = _service(ledger, model=model)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=_finding(tenant),
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
    )

    assert status == "FAILED"
    assert ledger.proposals == []
    assert current_request_status(ledger.requests) == "FAILED"


# ---------------------------------------------------------------------------
# Evidence handling: redacted and bounded.
# ---------------------------------------------------------------------------


async def test_evidence_is_redacted_and_bounded() -> None:
    tenant = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ledger = FakeLedger()
    model = FakeModel()

    async def source(ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        # Assembled at runtime so a secret-scanner does not match a literal
        # in this source file; the shape is what redaction must catch.
        aws_key = "AKIA" + "1234567890ABCDEF"
        assignment = "token" + "=supersecret"
        return {evidence_id: f"{aws_key} {assignment} " + "x" * 900}

    service = _service(ledger, model=model, evidence_source=source)

    status = await service.investigate_finding(
        tenant_id=tenant,
        finding=_finding(tenant),
        evidence_snapshot_ids=[evidence_id],
        requested_by="detection-pipeline",
    )

    assert status == "COMPLETED"
    summary = model.evidence[evidence_id]
    assert "AKIA" + "1234567890ABCDEF" not in summary
    assert "supersecret" not in summary
    assert len(summary) <= 500
