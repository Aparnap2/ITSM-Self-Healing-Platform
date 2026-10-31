"""Unit tests for approval-evidence detection (Task 12.8, no I/O)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.detection.engine import (
    detect_approval_violation,
    run_detection,
)
from itsm_agent.domain.events import SourceEvent
from itsm_agent.domain.models import ApprovalEvidence

TENANT = uuid.uuid4()
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA",
            "arn": "arn:aws:iam::123:user/alice",
            "accountId": "123",
            "userName": "alice",
        },
        "eventTime": "2026-01-01T12:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/Admin"},
        "requestID": "req-1",
        "eventID": "evt-1",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    base.update(overrides)
    return base


def _approval(**overrides: object) -> ApprovalEvidence:
    base = dict(
        tenant_id=TENANT,
        approver="bob",
        action="AssumeRole",
        resource_id="arn:aws:iam::123:role/Admin",
        status="APPROVED",
        valid_from=NOW - timedelta(hours=1),
        valid_to=NOW + timedelta(hours=1),
    )
    base.update(overrides)
    return ApprovalEvidence(**base)


def _ev() -> SourceEvent:
    return normalize_record(_record(), TENANT)


def test_valid_matching_approval_suppresses_finding() -> None:
    ev = _ev()
    ap = _approval()
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert findings == []


def test_missing_approval_full_coverage_is_suspicious() -> None:
    ev = _ev()
    findings = detect_approval_violation([ev], [], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "MISSING_APPROVAL"
    assert findings[0].outcome == "SUSPICIOUS"


def test_expired_approval_is_violation() -> None:
    ev = _ev()
    ap = _approval(valid_to=NOW - timedelta(days=1))
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "EXPIRED_APPROVAL"
    assert findings[0].outcome == "VIOLATION"


def test_denied_approval_is_violation() -> None:
    ev = _ev()
    ap = _approval(status="REJECTED")
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "DENIED_APPROVAL"
    assert findings[0].outcome == "VIOLATION"


def test_revoked_approval_is_violation() -> None:
    ev = _ev()
    ap = _approval(status="REVOKED")
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "REVOKED_APPROVAL"
    assert findings[0].outcome == "VIOLATION"


def test_mismatched_resource_is_violation() -> None:
    ev = _ev()
    ap = _approval(resource_id="arn:aws:iam::123:role/Other")
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "APPROVAL_MISMATCH"
    assert findings[0].outcome == "VIOLATION"


def test_incomplete_coverage_is_coverage_gap_not_violation() -> None:
    ev = _ev()
    findings = detect_approval_violation([ev], [], covered_sources=set())
    assert len(findings) == 1
    assert findings[0].finding_type == "COVERAGE_GAP"
    assert findings[0].outcome == "COVERAGE_GAP"


def test_unknown_identity_is_inconclusive() -> None:
    rec = _record(userIdentity={})
    ev = normalize_record(rec, TENANT)
    findings = detect_approval_violation([ev], [], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "UNRESOLVED_IDENTITY"
    assert findings[0].outcome == "INCONCLUSIVE"


def test_cross_tenant_approval_does_not_satisfy() -> None:
    ev = _ev()
    ap = _approval(tenant_id=uuid.uuid4())
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "MISSING_APPROVAL"


def test_timezone_validity_boundary() -> None:
    ev = _ev()
    # approval valid_from exactly at event time -> valid
    ap = _approval(valid_from=NOW, valid_to=NOW + timedelta(hours=1))
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert findings == []


def test_run_detection_backward_compat() -> None:
    ev = _ev()
    assert len(run_detection([ev])) == 1  # privilege escalation only


def test_run_detection_with_approvals() -> None:
    ev = _ev()
    ap = _approval()
    findings = run_detection([ev], [ap], covered_sources={"cloudtrail"})
    # privilege escalation + no approval finding (valid approval suppresses)
    assert all(f.finding_type != "MISSING_APPROVAL" for f in findings)


def test_approval_dict_input() -> None:
    ev = _ev()
    ap_dict = {
        "tenant_id": TENANT,
        "approver": "bob",
        "action": "AssumeRole",
        "resource_id": "arn:aws:iam::123:role/Admin",
        "status": "APPROVED",
        "valid_from": NOW - timedelta(hours=1),
        "valid_to": NOW + timedelta(hours=1),
    }
    findings = detect_approval_violation([ev], [ap_dict], covered_sources={"cloudtrail"})
    assert findings == []


def test_source_coverage_dict_input() -> None:
    ev = _ev()
    findings = detect_approval_violation([ev], [], source_coverage={"cloudtrail": False})
    assert len(findings) == 1
    assert findings[0].finding_type == "COVERAGE_GAP"


def test_mismatched_actor_is_violation() -> None:
    ev = _ev()
    ap = _approval(actor_id="arn:aws:iam::123:user/mallory")
    findings = detect_approval_violation([ev], [ap], covered_sources={"cloudtrail"})
    assert len(findings) == 1
    assert findings[0].finding_type == "APPROVAL_MISMATCH"


def test_aliases_callable() -> None:
    from itsm_agent.detection import engine

    ev = _ev()
    for name in (
        "detect_missing_approval",
        "detect_approval_mismatch",
        "detect_unapproved_privileged_activity",
        "detect_unapproved_activity",
        "detect_approval_evidence",
        "detect_approval_gap",
    ):
        fn = getattr(engine, name)
        assert callable(fn)
        fn([ev], [], covered_sources={"cloudtrail"})


pytestmark = pytest.mark.unit
