"""E2E: multi-source ingestion -> detection -> evidence bundle (offline)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from itsm_agent.collectors.aws.cloudtrail import normalize_record as ct_norm
from itsm_agent.collectors.github.audit_log import normalize_record as gh_norm
from itsm_agent.collectors.postgresql.pgaudit import normalize_record as pg_norm
from itsm_agent.collectors.postgresql.pgaudit import parse_pgaudit_line
from itsm_agent.detection.engine import run_detection
from itsm_agent.domain.models import EvidenceReference
from itsm_agent.reporting.evidence_bundle import build_evidence_bundle

pytestmark = pytest.mark.e2e


def test_multi_source_detection_and_bundle() -> None:
    tenant = uuid.uuid4()
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
        "eventID": "e1",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    ct_ev = ct_norm(ct_rec, tenant)

    pg_line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,1,1,READ,SELECT,"
        "TABLE,public.users,select * from users"
    )
    pg_rec = parse_pgaudit_line(pg_line)
    assert pg_rec is not None
    pg_ev = pg_norm(pg_rec, tenant)

    gh_rec = {
        "_document_id": "g1",
        "@timestamp": 1735689600000,
        "action": "org.add_member",
        "actor": "alice",
        "user": "bob",
        "org": "myorg",
    }
    gh_ev = gh_norm(gh_rec, tenant)

    events = [ct_ev, pg_ev, gh_ev]
    findings = run_detection(events)
    assert len(findings) >= 1

    # build evidence bundle for first finding
    finding = findings[0]
    evref = EvidenceReference(
        id=uuid.uuid4(),
        finding_id=finding.id,
        source_event_id=ct_ev.event_id,
        content_hash=ct_ev.payload_hash,
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=datetime.now(UTC),
    )
    bundle = build_evidence_bundle(finding, [evref])
    assert "bundle_hash" in bundle
    assert len(bundle["evidence"]) == 1
