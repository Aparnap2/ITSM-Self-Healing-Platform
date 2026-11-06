"""Pilot scenario: multi-source ingestion + detection + investigation + report."""

from __future__ import annotations

import uuid

import pytest

from itsm_agent.collectors.aws.cloudtrail import normalize_record as ct_norm
from itsm_agent.detection.engine import run_detection
from itsm_agent.reporting.evidence_bundle import build_evidence_bundle

pytestmark = pytest.mark.e2e


def test_pilot_scenario_end_to_end() -> None:
    tenant = uuid.uuid4()
    # suspicious: AssumeRole
    ct_rec = {
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
        "requestID": "r1",
        "eventID": "e-pilot-1",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    events = [ct_norm(ct_rec, tenant)]
    findings = run_detection(events)
    assert len(findings) >= 1
    assert any(f.outcome == "SUSPICIOUS" for f in findings)
    bundle = build_evidence_bundle(findings[0], [])
    assert "bundle_hash" in bundle
