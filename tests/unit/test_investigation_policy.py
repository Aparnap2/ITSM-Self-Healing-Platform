"""Unit tests for the deterministic investigation selection policy (no LLM).

The selection decision is the security-relevant part of the agentic stage:
it decides which findings are worth an agentic pass at all. It must stay
deterministic, conservative and completely independent of any model.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from itsm_agent.domain.investigation_policy import (
    DEADLINE_SECONDS,
    INVESTIGATION_QUESTION,
    MAX_EVIDENCE_SNAPSHOT_IDS,
    MAX_MODEL_CALLS,
    MAX_TOOL_CALLS,
    MIN_RISK_SCORE,
    InvestigationRequestRecord,
    build_investigation_request,
    current_request_status,
    should_investigate,
)
from itsm_agent.domain.models import Finding, Severity

pytestmark = pytest.mark.unit


def _finding(
    *,
    severity: Severity = Severity.P1,
    outcome: str = "VIOLATION",
    risk_score: int = 70,
    tenant_id: uuid.UUID | None = None,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
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


# ---------------------------------------------------------------------------
# Selection matrix
# ---------------------------------------------------------------------------


def test_p1_violation_is_selected() -> None:
    assert should_investigate(_finding(severity=Severity.P1, outcome="VIOLATION"), enabled=True)


def test_p2_suspicious_is_selected() -> None:
    assert should_investigate(
        _finding(severity=Severity.P2, outcome="SUSPICIOUS", risk_score=MIN_RISK_SCORE),
        enabled=True,
    )


def test_p3_suspicious_is_not_selected() -> None:
    assert not should_investigate(
        _finding(severity=Severity.P3, outcome="SUSPICIOUS"), enabled=True
    )


def test_p4_violation_is_not_selected() -> None:
    assert not should_investigate(_finding(severity=Severity.P4, outcome="VIOLATION"), enabled=True)


def test_coverage_gap_is_never_selected() -> None:
    """A coverage gap is uncertainty, not a suspected violation."""
    assert not should_investigate(
        _finding(severity=Severity.P1, outcome="COVERAGE_GAP", risk_score=100), enabled=True
    )


def test_inconclusive_is_never_selected() -> None:
    assert not should_investigate(
        _finding(severity=Severity.P1, outcome="INCONCLUSIVE", risk_score=100), enabled=True
    )


def test_disabled_selects_nothing() -> None:
    assert not should_investigate(
        _finding(severity=Severity.P1, outcome="VIOLATION", risk_score=100), enabled=False
    )


def test_risk_score_threshold_is_inclusive() -> None:
    assert not should_investigate(_finding(risk_score=MIN_RISK_SCORE - 1), enabled=True)
    assert should_investigate(_finding(risk_score=MIN_RISK_SCORE), enabled=True)


def test_selection_requires_every_criterion() -> None:
    """A finding must satisfy outcome AND severity AND risk score."""
    assert not should_investigate(
        _finding(severity=Severity.P1, outcome="VIOLATION", risk_score=MIN_RISK_SCORE - 1),
        enabled=True,
    )
    assert not should_investigate(
        _finding(severity=Severity.P3, outcome="VIOLATION", risk_score=100), enabled=True
    )
    assert not should_investigate(
        _finding(severity=Severity.P1, outcome="COVERAGE_GAP", risk_score=100), enabled=True
    )


# ---------------------------------------------------------------------------
# Request bounds
# ---------------------------------------------------------------------------


def test_request_is_bounded() -> None:
    tenant = uuid.uuid4()
    finding = _finding(tenant_id=tenant)
    request = build_investigation_request(
        finding,
        tenant_id=tenant,
        evidence_snapshot_ids=[uuid.uuid4() for _ in range(3)],
        requested_by="detection-pipeline",
        now=datetime.now(UTC),
    )
    assert request.max_tool_calls == MAX_TOOL_CALLS
    assert request.max_model_calls == MAX_MODEL_CALLS
    assert request.deadline_seconds == DEADLINE_SECONDS
    assert 1 <= request.max_tool_calls <= 20
    assert 1 <= request.max_model_calls <= 5
    assert request.tenant_id == tenant
    assert request.finding_id == finding.id
    assert len(request.evidence_snapshot_ids) == 3


def test_request_question_is_fixed_and_short() -> None:
    tenant = uuid.uuid4()
    request = build_investigation_request(
        _finding(tenant_id=tenant),
        tenant_id=tenant,
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
        now=datetime.now(UTC),
    )
    assert request.question == INVESTIGATION_QUESTION
    assert len(request.question) <= 1000
    assert request.question == request.question.strip()


def test_request_truncates_evidence_snapshot() -> None:
    tenant = uuid.uuid4()
    ids = [uuid.uuid4() for _ in range(MAX_EVIDENCE_SNAPSHOT_IDS + 25)]
    request = build_investigation_request(
        _finding(tenant_id=tenant),
        tenant_id=tenant,
        evidence_snapshot_ids=ids,
        requested_by="detection-pipeline",
        now=datetime.now(UTC),
    )
    assert len(request.evidence_snapshot_ids) == MAX_EVIDENCE_SNAPSHOT_IDS
    assert request.evidence_snapshot_ids == ids[:MAX_EVIDENCE_SNAPSHOT_IDS]


def test_request_is_deterministic_for_the_same_inputs() -> None:
    tenant = uuid.uuid4()
    finding = _finding(tenant_id=tenant)
    now = datetime.now(UTC)
    first = build_investigation_request(
        finding,
        tenant_id=tenant,
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
        now=now,
    )
    second = build_investigation_request(
        finding,
        tenant_id=tenant,
        evidence_snapshot_ids=[],
        requested_by="detection-pipeline",
        now=now,
    )
    assert first.investigation_id == second.investigation_id
    assert first.model_dump() == second.model_dump()


def test_request_rejects_cross_tenant_findings() -> None:
    finding = _finding()
    with pytest.raises(ValueError, match="tenant mismatch"):
        build_investigation_request(
            finding,
            tenant_id=uuid.uuid4(),
            evidence_snapshot_ids=[],
            requested_by="detection-pipeline",
            now=datetime.now(UTC),
        )


def test_request_rejects_empty_requester() -> None:
    tenant = uuid.uuid4()
    with pytest.raises(ValueError, match="requested_by"):
        build_investigation_request(
            _finding(tenant_id=tenant),
            tenant_id=tenant,
            evidence_snapshot_ids=[],
            requested_by="   ",
            now=datetime.now(UTC),
        )


def test_request_rejects_overlong_requester() -> None:
    tenant = uuid.uuid4()
    with pytest.raises(ValueError, match="requested_by"):
        build_investigation_request(
            _finding(tenant_id=tenant),
            tenant_id=tenant,
            evidence_snapshot_ids=[],
            requested_by="x" * 200,
            now=datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# Ledger status helper
# ---------------------------------------------------------------------------


def _record(status: str) -> InvestigationRequestRecord:
    return InvestigationRequestRecord(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        requested_by="detection-pipeline",
        question=INVESTIGATION_QUESTION,
        evidence_snapshot_ids=[],
        max_tool_calls=MAX_TOOL_CALLS,
        max_model_calls=MAX_MODEL_CALLS,
        status=status,
        created_at=datetime.now(UTC),
    )


def test_current_status_prefers_the_terminal_row() -> None:
    assert current_request_status([_record("REQUESTED"), _record("COMPLETED")]) == "COMPLETED"
    assert current_request_status([_record("REQUESTED"), _record("FAILED")]) == "FAILED"
    assert current_request_status([_record("REQUESTED")]) == "REQUESTED"
    assert current_request_status([]) == "REQUESTED"
