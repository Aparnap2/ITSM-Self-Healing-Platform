"""Unit tests for deterministic detection engine (no I/O)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.detection.engine import (
    detect_coverage_gap,
    detect_failed_access,
    detect_privilege_escalation,
    run_detection,
)

TENANT = uuid.uuid4()


def _record(**overrides: object) -> dict[str, object]:
    base = {
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


def test_privilege_escalation() -> None:
    ev = normalize_record(_record(), TENANT)
    findings = detect_privilege_escalation([ev])
    assert len(findings) == 1
    assert findings[0].finding_type == "PRIVILEGE_ESCALATION"
    assert findings[0].outcome == "SUSPICIOUS"


def test_failed_access() -> None:
    ev = normalize_record(_record(errorCode="AccessDenied"), TENANT)
    findings = detect_failed_access([ev])
    assert len(findings) == 1
    assert findings[0].finding_type == "FAILED_ACCESS"


def test_coverage_gap_silent() -> None:
    now = datetime.now(UTC)
    last = now - __import__("datetime").timedelta(days=2)
    f = detect_coverage_gap("cloudtrail", TENANT, last, 3600, now=now)
    assert f is not None
    assert f.outcome == "COVERAGE_GAP"


def test_coverage_healthy() -> None:
    now = datetime.now(UTC)
    f = detect_coverage_gap("cloudtrail", TENANT, now, 3600, now=now)
    assert f is None


def test_run_detection() -> None:
    ev = normalize_record(_record(), TENANT)
    findings = run_detection([ev])
    assert len(findings) >= 1
