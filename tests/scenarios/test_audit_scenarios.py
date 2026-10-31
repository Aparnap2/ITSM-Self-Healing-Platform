"""Deterministic multi-source audit scenarios (offline pipeline).

Ingests small synthetic source records through the three collectors
(aws cloudtrail, postgresql pgaudit, github audit_log), runs the
deterministic detection engine, and asserts exact results.

Engine API note: ``run_detection`` covers privilege escalation, failed access
and (when approval evidence is supplied) approval-evidence detection
(Task 12.8). The legacy ``test_activity_without_matching_approval_evidence``
asserts the pre-12.8 behavior for ``run_detection`` without approvals.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from itsm_agent.collectors.aws.cloudtrail import normalize_record as ct_norm
from itsm_agent.collectors.github.audit_log import normalize_record as gh_norm
from itsm_agent.collectors.postgresql.pgaudit import normalize_record as pg_norm
from itsm_agent.collectors.postgresql.pgaudit import parse_pgaudit_line
from itsm_agent.detection.engine import (
    RULE_VERSION,
    detect_approval_violation,
    detect_coverage_gap,
    run_detection,
)
from itsm_agent.domain.events import InvestigationProposal, InvestigationRequest, SourceEvent
from itsm_agent.domain.models import ApprovalEvidence, EvidenceReference, Severity
from itsm_agent.investigations.orchestrator import run_investigation
from itsm_agent.reporting.evidence_bundle import build_evidence_bundle

pytestmark = pytest.mark.scenarios

#: Fixed wall-clock instant used for every timestamp this file computes.
SCENARIO_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _ct_record(**overrides: Any) -> dict[str, Any]:
    """Benign-by-default CloudTrail record (mirrors the e2e test records)."""
    base: dict[str, Any] = {
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA",
            "arn": "arn:aws:iam::123:user/alice",
            "accountId": "123",
            "userName": "alice",
        },
        "eventTime": "2026-01-01T12:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "ListUsers",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "requestParameters": {},
        "requestID": "r1",
        "eventID": "e-ct-1",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    base.update(overrides)
    return base


def _pg_event(tenant: UUID, user: str = "alice", stmt: str = "1") -> SourceEvent:
    """Normalize one benign pgAudit SELECT record for ``tenant``."""
    line = (
        f"2026-01-01 12:00:00 UTC:{user}@db:LOG:  AUDIT: SESSION,{stmt},1,READ,SELECT,"
        "TABLE,public.users,select * from users"
    )
    rec = parse_pgaudit_line(line)
    assert rec is not None
    return pg_norm(rec, tenant)


def _gh_record(**overrides: Any) -> dict[str, Any]:
    """Benign-by-default GitHub audit-log record (mirrors the e2e test records)."""
    base: dict[str, Any] = {
        "_document_id": "g1",
        "@timestamp": 1767225600000,
        "action": "org.update_member",
        "actor": "alice",
        "org": "myorg",
    }
    base.update(overrides)
    return base


def _build_events(
    tenant: UUID, ct_rec: dict[str, Any] | None, gh_rec: dict[str, Any] | None
) -> list[SourceEvent]:
    """Build the pg event plus optional cloudtrail/github events for ``tenant``."""
    events = [_pg_event(tenant, stmt="1")]
    if ct_rec is not None:
        events.append(ct_norm(ct_rec, tenant))
    if gh_rec is not None:
        events.append(gh_norm(gh_rec, tenant))
    return events


def test_benign_activity_across_three_sources_has_zero_findings() -> None:
    tenant = uuid4()
    events = _build_events(tenant, _ct_record(eventID="e-benign-1"), _gh_record())
    findings = run_detection(events)
    assert findings == []
    for ev in events:
        assert ev.tenant_id == tenant
        assert ev.outcome == "success"


def test_privilege_escalation_finding_has_expected_severity_and_classification() -> None:
    tenant = uuid4()
    events = _build_events(
        tenant,
        # AssumeRole Admin is the same suspicious pattern the e2e tests use.
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-esc-1",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        _gh_record(),
    )
    findings = run_detection(events)
    assert len(findings) == 1  # pg SELECT and the missing/benign github event are clean.
    f = findings[0]
    assert f.finding_type == "PRIVILEGE_ESCALATION"
    assert f.severity == Severity.P2
    assert f.outcome == "SUSPICIOUS"
    assert f.status == "OPEN"
    assert f.risk_score == 70
    assert f.rule_version == RULE_VERSION
    assert f.tenant_id == tenant
    assert f.title == "Privileged action: AssumeRole"


def test_activity_without_matching_approval_evidence() -> None:
    """Engine limitation documented: no approval-evidence rule exists.

    ``run_detection`` aggregates only ``detect_privilege_escalation`` and
    ``detect_failed_access``; neither consults approval evidence, and the engine
    exposes no per-approval rule. Current true behavior asserted precisely:
    (a) benign successful activity without approval evidence is not flagged,
    (b) privileged activity without approval evidence surfaces as a
    PRIVILEGE_ESCALATION finding classified SUSPICIOUS -- never VIOLATION,
    because approval linkage is not yet an engine concept.
    """
    tenant = uuid4()
    benign = _build_events(tenant, _ct_record(eventID="e-noapr-1"), None)
    assert run_detection(benign) == []

    privileged = _build_events(
        tenant,
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-noapr-2",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        _gh_record(),
    )
    findings = run_detection(privileged)
    assert len(findings) == 1
    assert findings[0].finding_type == "PRIVILEGE_ESCALATION"
    assert findings[0].outcome == "SUSPICIOUS"


def test_failed_access_pattern_produces_failed_access_finding() -> None:
    tenant = uuid4()
    events = _build_events(
        tenant,
        _ct_record(
            eventSource="s3.amazonaws.com",
            eventName="GetObject",
            eventID="e-fail-1",
            readOnly=True,
            requestParameters={"bucketName": "audit-logs"},
            errorCode="AccessDenied",
        ),
        _gh_record(),
    )
    findings = run_detection(events)
    assert len(findings) == 1  # pg SELECT is successful; github benign.
    f = findings[0]
    assert f.finding_type == "FAILED_ACCESS"
    assert f.severity == Severity.P3
    assert f.outcome == "SUSPICIOUS"
    assert f.risk_score == 40
    assert f.rule_version == RULE_VERSION
    assert f.title == "Failed/denied action: GetObject"
    # CloudTrail errorCode normalizes the outcome to failure, which is the
    # engine's only trigger for FAILED_ACCESS.
    assert events[1].outcome == "failure"


def test_detect_coverage_gap_for_silent_source() -> None:
    """``detect_coverage_gap`` is deterministic when ``now`` is passed in."""
    tenant = uuid4()
    silent = detect_coverage_gap("cloudtrail", tenant, None, 3600, now=SCENARIO_NOW)
    assert silent is not None
    assert silent.finding_type == "COVERAGE_GAP"
    assert silent.severity == Severity.P3
    assert silent.outcome == "COVERAGE_GAP"
    assert silent.risk_score == 30
    assert silent.tenant_id == tenant
    assert silent.title == "No events from cloudtrail"

    stale = detect_coverage_gap(
        "pgaudit",
        tenant,
        SCENARIO_NOW.replace(hour=10),  # 2h stale against a 1h cadence.
        3600,
        now=SCENARIO_NOW,
    )
    assert stale is not None
    assert stale.finding_type == "COVERAGE_GAP"
    assert stale.title == "Source pgaudit silent"

    healthy = detect_coverage_gap(
        "github",
        tenant,
        SCENARIO_NOW.replace(minute=55),  # 5 minutes old, well within cadence.
        3600,
        now=SCENARIO_NOW,
    )
    assert healthy is None

    findings = run_detection(_build_events(tenant, _ct_record(), _gh_record()))
    healthy_events = [f for f in findings if f.outcome == "COVERAGE_GAP"]
    assert healthy_events == []


def test_findings_resolve_to_real_normalized_event_ids_in_evidence_bundle() -> None:
    tenant = uuid4()
    events = _build_events(
        tenant,
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-e2e-1",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        _gh_record(action="org.add_member", user="bob"),
    )
    event_ids = {str(ev.event_id) for ev in events}
    findings = run_detection(events)
    assert len(findings) == 1  # Only the AssumeRole action is flagged.
    finding = findings[0]

    ref = EvidenceReference(
        id=uuid4(),
        finding_id=finding.id,
        source_event_id=events[1].event_id,
        content_hash=events[1].payload_hash,
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=SCENARIO_NOW,
    )
    bundle = build_evidence_bundle(finding, [ref])
    assert isinstance(bundle["bundle_hash"], str)
    assert len(bundle["bundle_hash"]) == 64
    assert len(bundle["evidence"]) == 1
    entry = bundle["evidence"][0]
    # Every bundle evidence reference resolves into a real normalized event.
    assert entry["source_event_id"] in event_ids
    assert entry["source_event_id"] == str(events[1].event_id)
    assert entry["content_hash"] == events[1].payload_hash
    assert entry["trust_level"] == "SIMULATOR_OBSERVATION"


def test_approval_evidence_end_to_end_scenario() -> None:
    """End-to-end: approval evidence changes classification of a privileged action.

    A privileged AssumeRole with a valid, matching approval is not flagged;
    the same action with no approval evidence surfaces as MISSING_APPROVAL.
    Source coverage is complete, so the missing case is a suspicious activity,
    not a silent coverage gap.
    """
    tenant = uuid4()
    ct_rec = _ct_record(
        eventSource="sts.amazonaws.com",
        eventName="AssumeRole",
        eventID="e-approval-1",
        readOnly=False,
        requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
    )
    events = _build_events(tenant, ct_rec, _gh_record())
    privileged = [
        ev
        for ev in events
        if "assumerole" in ev.event_type.lower() or "assumerole" in ev.action.lower()
    ]
    assert privileged, "expected one privileged event"

    resource = privileged[0].resource_id
    valid_approval = ApprovalEvidence(
        tenant_id=tenant,
        approver="security-lead",
        action="AssumeRole",
        resource_id=resource,
        status="APPROVED",
        valid_from=SCENARIO_NOW - timedelta(hours=1),
        valid_to=SCENARIO_NOW + timedelta(hours=1),
    )
    # Valid approval -> no approval finding.
    approved_findings = detect_approval_violation(
        privileged, [valid_approval], covered_sources={"cloudtrail"}
    )
    assert approved_findings == []

    # No approval evidence -> MISSING_APPROVAL (suspicious, not a coverage gap).
    missing_findings = detect_approval_violation(privileged, [], covered_sources={"cloudtrail"})
    assert len(missing_findings) == 1
    assert missing_findings[0].finding_type == "MISSING_APPROVAL"
    assert missing_findings[0].outcome == "SUSPICIOUS"
    # Tenant isolation: the finding belongs to this tenant.
    assert missing_findings[0].tenant_id == tenant


@pytest.mark.asyncio
async def test_end_to_end_investigation_and_reviewer_decision() -> None:
    """End-to-end: detection -> bounded investigation -> evidence bundle -> review.

    Offline (FakeModel): a privileged event is detected, investigated with a
    bounded read-only evidence fetch, validated against the evidence snapshot,
    and folded into a reproducible evidence bundle carrying a reviewer decision.
    """
    tenant = uuid4()
    ct_rec = _ct_record(
        eventSource="sts.amazonaws.com",
        eventName="AssumeRole",
        eventID="e-e2e-inv-1",
        readOnly=False,
        requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
    )
    events = _build_events(tenant, ct_rec, _gh_record())
    findings = run_detection(events)
    assert len(findings) == 1
    finding = findings[0]

    evidence_ids = [events[1].event_id]
    request = InvestigationRequest(
        investigation_id=uuid4(),
        tenant_id=tenant,
        finding_id=finding.id,
        evidence_snapshot_ids=evidence_ids,
        question="Why did this privileged action occur?",
        max_tool_calls=3,
        max_model_calls=1,
        deadline_seconds=10.0,
    )
    proposal = InvestigationProposal(
        investigation_id=request.investigation_id,
        hypothesis="Privileged AssumeRole without matching approval evidence.",
        supporting_evidence=evidence_ids,
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="low",
        recommended_disposition="CONFIRM",
        model_version="test-model-v1",
        prompt_version="test-prompt-v1",
    )

    class FakeModel:
        def __init__(self, p: InvestigationProposal) -> None:
            self.p = p
            self.calls = 0

        async def investigate(
            self, req: InvestigationRequest, evidence: dict[UUID, str]
        ) -> InvestigationProposal:
            self.calls += 1
            return self.p

    model = FakeModel(proposal)

    async def fetcher(ids: list[UUID]) -> dict[UUID, str]:
        return {i: "redacted cloudtrail excerpt" for i in ids}

    result = await run_investigation(request, fetch_evidence=fetcher, model=model)
    assert result.recommended_disposition == "CONFIRM"
    assert model.calls == 1
    # Evidence references must resolve against the snapshot.
    assert all(r in request.evidence_snapshot_ids for r in result.supporting_evidence)

    ref = EvidenceReference(
        id=uuid4(),
        finding_id=finding.id,
        source_event_id=events[1].event_id,
        content_hash=events[1].payload_hash,
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=SCENARIO_NOW,
    )
    bundle = build_evidence_bundle(
        finding,
        [ref],
        review_decisions=[
            {
                "reviewer": "analyst-1",
                "decision": "ACCEPT",
                "rationale": "Confirmed by investigation " + str(result.investigation_id),
                "decided_at": SCENARIO_NOW.isoformat(),
            }
        ],
    )
    assert len(bundle["bundle_hash"]) == 64
    assert bundle["evidence"][0]["source_event_id"] == str(events[1].event_id)
    assert bundle["review_decisions"][0]["decision"] == "ACCEPT"
    # Reproducibility: re-running with the same inputs yields the same hash.
    bundle2 = build_evidence_bundle(finding, [ref], review_decisions=bundle["review_decisions"])
    assert bundle2["bundle_hash"] == bundle["bundle_hash"]
