"""Unit tests for the detection allowlists and approval-aware suppression.

Marker: ``unit``. Pure domain logic, no I/O.

These tests pin the semantics that the pilot measurement exposed as wrong:

- privilege escalation is decided by an explicit action allowlist, so an
  unrelated operation that merely contains "attach" is not an escalation;
- a valid, matching, unexpired approval suppresses the generic escalation
  finding, while a denied, revoked, expired, mismatched or cross-tenant
  approval does not;
- one event produces at most one escalation-family finding for the same fact.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.detection.engine import (
    PRIVILEGE_ESCALATION_ACTIONS,
    PRIVILEGED_ACTIONS,
    detect_privilege_escalation,
    run_detection,
)

pytestmark = pytest.mark.unit

TENANT = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()
EVENT_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
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


def _event(**overrides: Any) -> Any:
    return normalize_record(_record(**overrides), TENANT)


def _approval(**overrides: Any) -> dict[str, Any]:
    approval: dict[str, Any] = {
        "id": "approval-1",
        "tenant_id": TENANT,
        "approver_id": "secops.lead",
        "action": "AssumeRole",
        "resource_id": "arn:aws:iam::123:role/Admin",
        "status": "APPROVED",
        "valid_from": EVENT_TIME - timedelta(hours=1),
        "valid_to": EVENT_TIME + timedelta(hours=1),
    }
    approval.update(overrides)
    return approval


# ---------------------------------------------------------------------------
# Allowlist semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    ["AttachVolume", "GetObject", "ListBuckets", "RunInstances", "DescribeInstances"],
)
def test_unprivileged_actions_are_not_escalations(action: str) -> None:
    # "AttachVolume" contains "attach": the old substring rule flagged it.
    ev = _event(eventName=action, eventSource="ec2.amazonaws.com")
    assert detect_privilege_escalation([ev]) == []


@pytest.mark.parametrize("action", sorted(PRIVILEGE_ESCALATION_ACTIONS))
def test_allowlisted_actions_are_escalations(action: str) -> None:
    ev = _event(eventName=action, eventSource="iam.amazonaws.com")
    findings = detect_privilege_escalation([ev])
    assert len(findings) == 1
    assert findings[0].finding_type == "PRIVILEGE_ESCALATION"
    assert findings[0].outcome == "SUSPICIOUS"
    assert findings[0].severity == "P2"
    assert findings[0].risk_score == 70


def test_service_prefixed_action_names_are_matched() -> None:
    ev = _event(eventName="iam:AttachUserPolicy", eventSource="iam.amazonaws.com")
    assert len(detect_privilege_escalation([ev])) == 1


def test_privileged_actions_include_the_escalation_set() -> None:
    assert PRIVILEGE_ESCALATION_ACTIONS <= PRIVILEGED_ACTIONS
    # Destructive and credential actions need approval evidence even though
    # they are not themselves an escalation.
    assert "DeleteUser" in PRIVILEGED_ACTIONS
    assert "CreateAccessKey" in PRIVILEGED_ACTIONS


# ---------------------------------------------------------------------------
# Approval-aware suppression
# ---------------------------------------------------------------------------


def test_valid_matching_approval_suppresses_the_escalation() -> None:
    ev = _event()
    findings = detect_privilege_escalation([ev], [_approval()])
    assert findings == []


def test_approval_outside_its_validity_window_does_not_suppress() -> None:
    ev = _event()
    expired = _approval(valid_to=EVENT_TIME - timedelta(minutes=1))
    revoked = _approval(status="REVOKED")
    denied = _approval(status="DENIED")
    for approval in (expired, revoked, denied):
        findings = detect_privilege_escalation([ev], [approval])
        assert len(findings) == 1, approval


def test_approval_for_another_tenant_never_suppresses() -> None:
    ev = _event()
    findings = detect_privilege_escalation([ev], [_approval(tenant_id=OTHER_TENANT)])
    assert len(findings) == 1


def test_approval_with_mismatched_dimensions_does_not_suppress() -> None:
    ev = _event()
    other_resource = _approval(resource_id="arn:aws:iam::123:role/Other")
    other_actor = _approval(actor_id="someone.else")
    for approval in (other_resource, other_actor):
        findings = detect_privilege_escalation([ev], [approval])
        assert len(findings) == 1, approval


def test_approval_is_evaluated_at_event_time_not_wall_clock() -> None:
    # The approval window is valid at the event time; a wall-clock evaluation
    # would wrongly report the event as unauthorized years later.
    ev = _event()
    findings = detect_privilege_escalation(
        [ev], [_approval()], now=EVENT_TIME + timedelta(days=365)
    )
    assert findings == []


# ---------------------------------------------------------------------------
# One escalation-family finding per event
# ---------------------------------------------------------------------------


def test_unauthorized_escalation_yields_one_escalation_family_finding() -> None:
    ev = _event()
    findings = run_detection([ev], [], covered_sources={"cloudtrail"})
    escalation_family = [
        f for f in findings if f.finding_type in ("PRIVILEGE_ESCALATION", "MISSING_APPROVAL")
    ]
    assert len(escalation_family) == 1
    assert escalation_family[0].finding_type == "MISSING_APPROVAL"


def test_authorized_escalation_yields_no_finding() -> None:
    ev = _event()
    findings = run_detection([ev], [_approval()], covered_sources={"cloudtrail"})
    assert findings == []


def test_coverage_gap_keeps_the_classification_finding() -> None:
    # A coverage gap is an uncertainty answer, not a definitive one: the
    # classification finding still stands beside it.
    ev = _event()
    findings = run_detection([ev], [], covered_sources=set())
    types = {f.finding_type for f in findings}
    assert "COVERAGE_GAP" in types
    assert "PRIVILEGE_ESCALATION" in types
