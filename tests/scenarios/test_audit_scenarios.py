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
from itsm_agent.domain.models import ApprovalEvidence, EvidenceReference, Finding, Severity
from itsm_agent.investigations.orchestrator import run_investigation
from itsm_agent.privacy.redaction import redact_secrets
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


# ---------------------------------------------------------------------------
# Additional 16 deterministic scenarios (matrix coverage, tests 9-24)
# ---------------------------------------------------------------------------


def test_benign_multi_record_cloudtrail_baseline_has_no_findings() -> None:
    """Benign baseline: multiple benign CloudTrail calls plus pg/GitHub are clean.

    Several read-only CloudTrail management calls across two services, a benign
    pgAudit SELECT and a benign GitHub audit record must all normalize to
    successful outcomes and produce zero findings.
    """
    tenant = uuid4()
    events = [
        _pg_event(tenant, stmt="1"),
        ct_norm(_ct_record(eventID="e-benign-a"), tenant),
        ct_norm(
            _ct_record(
                eventSource="ec2.amazonaws.com",
                eventName="DescribeInstances",
                eventID="e-benign-b",
                readOnly=True,
            ),
            tenant,
        ),
        gh_norm(_gh_record(), tenant),
    ]
    assert run_detection(events) == []
    assert {ev.source for ev in events} == {"pgaudit", "cloudtrail", "github"}
    assert all(ev.outcome == "success" for ev in events)


def test_cloudtrail_createuser_and_attach_policy_are_privilege_escalation() -> None:
    """Privilege escalation: CreateUser and AttachRolePolicy are both flagged.

    CloudTrail event-name matching catches ``createuser`` and ``attach`` and
    emits one P2 / risk-70 PRIVILEGE_ESCALATION finding per privileged event.
    """
    tenant = uuid4()
    events = [
        _pg_event(tenant, stmt="1"),
        ct_norm(
            _ct_record(
                eventSource="iam.amazonaws.com",
                eventName="CreateUser",
                eventID="e-priv-create",
                readOnly=False,
                requestParameters={"userName": "mallory"},
            ),
            tenant,
        ),
        ct_norm(
            _ct_record(
                eventSource="iam.amazonaws.com",
                eventName="AttachRolePolicy",
                eventID="e-priv-attach",
                readOnly=False,
            ),
            tenant,
        ),
        gh_norm(_gh_record(), tenant),
    ]
    findings = run_detection(events)
    assert len(findings) == 2
    assert {f.finding_type for f in findings} == {"PRIVILEGE_ESCALATION"}
    assert {f.title for f in findings} == {
        "Privileged action: CreateUser",
        "Privileged action: AttachRolePolicy",
    }
    assert all(f.severity == Severity.P2 for f in findings)
    assert all(f.outcome == "SUSPICIOUS" for f in findings)
    assert all(f.risk_score == 70 for f in findings)


def test_github_role_change_and_pgaudit_superuser_grant_are_not_privilege_escalation() -> None:
    """Current limitation: only CloudTrail-style event names trigger escalation.

    The privilege-escalation rule matches substrings of the normalized
    ``event_type``. A GitHub org role change (``org.update_member``) and a
    pgAudit superuser ``GRANT`` normalize successfully but are not classified
    as PRIVILEGE_ESCALATION by the current engine.
    """
    tenant = uuid4()
    gh_event = gh_norm(
        _gh_record(action="org.update_member", actor="alice", user="bob", role="admin"),
        tenant,
    )
    line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,1,1,WRITE,GRANT,"
        "TABLE,public.users,grant all on users to bob"
    )
    grant_rec = parse_pgaudit_line(line)
    assert grant_rec is not None
    pg_grant = pg_norm(grant_rec, tenant)

    findings = run_detection([gh_event, pg_grant])
    assert findings == []
    assert gh_event.event_type == "org.update_member"
    assert pg_grant.event_type == "GRANT"
    assert gh_event.outcome == "success"
    assert pg_grant.outcome == "success"


def test_github_authentication_failure_is_not_classified_as_failed_access() -> None:
    """Current limitation: GitHub normalization always reports success.

    The GitHub collector hard-codes ``outcome="success"`` for every audit
    record, so an authentication-failure action never satisfies the
    FAILED_ACCESS trigger (``outcome`` is ``failure`` or ``denied``).
    """
    tenant = uuid4()
    gh_event = gh_norm(
        _gh_record(action="authentication_failure", actor="mallory"),
        tenant,
    )
    findings = run_detection([gh_event])
    assert findings == []
    assert gh_event.outcome == "success"
    assert gh_event.event_type == "authentication_failure"


def test_pgaudit_permission_denied_is_not_classified_as_failed_access() -> None:
    """Current limitation: pgAudit parsing does not carry a denial outcome.

    pgAudit records normalize with ``outcome="success"`` regardless of the SQL
    text, so a permission-denied statement is not classified as FAILED_ACCESS.
    """
    tenant = uuid4()
    line = (
        "2026-01-01 12:00:00 UTC:mallory@db:LOG:  AUDIT: SESSION,9,1,READ,SELECT,"
        "TABLE,public.secrets,select * from secrets"
    )
    denied_rec = parse_pgaudit_line(line)
    assert denied_rec is not None
    pg_event = pg_norm(denied_rec, tenant)

    findings = run_detection([pg_event])
    assert findings == []
    assert pg_event.outcome == "success"
    assert pg_event.event_type == "SELECT"


def test_partial_source_coverage_for_privileged_event_is_coverage_gap() -> None:
    """Coverage gap: incomplete source coverage downgrades a privileged event.

    With ``source_coverage={"cloudtrail": False}`` the privileged AssumeRole is
    still flagged as PRIVILEGE_ESCALATION, and approval detection emits a
    COVERAGE_GAP (P3, risk 30) rather than a confirmed violation.
    """
    tenant = uuid4()
    event = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-partial-coverage",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    findings = run_detection(
        [event],
        approvals=[],
        source_coverage={"cloudtrail": False},
    )
    assert len(findings) == 2
    by_type = {f.finding_type: f for f in findings}
    assert set(by_type) == {"PRIVILEGE_ESCALATION", "COVERAGE_GAP"}
    gap = by_type["COVERAGE_GAP"]
    assert gap.outcome == "COVERAGE_GAP"
    assert gap.severity == Severity.P3
    assert gap.risk_score == 30
    assert gap.title == "Approval coverage gap: AssumeRole"
    assert gap.tenant_id == tenant


def test_expired_and_revoked_approvals_are_violations() -> None:
    """Approval evidence: expired and revoked approvals are VIOLATIONs.

    An APPROVED approval whose validity window has passed yields
    EXPIRED_APPROVAL, and a REVOKED approval yields REVOKED_APPROVAL; both are
    P2 / risk-70 VIOLATION findings.
    """
    tenant = uuid4()
    event = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-approval-expiry",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    resource = event.resource_id
    assert resource is not None

    expired = ApprovalEvidence(
        tenant_id=tenant,
        approver="security-lead",
        action="AssumeRole",
        resource_id=resource,
        status="APPROVED",
        valid_from=SCENARIO_NOW - timedelta(days=2),
        valid_to=SCENARIO_NOW - timedelta(days=1),
    )
    expired_findings = detect_approval_violation([event], [expired], covered_sources={"cloudtrail"})
    assert len(expired_findings) == 1
    assert expired_findings[0].finding_type == "EXPIRED_APPROVAL"
    assert expired_findings[0].outcome == "VIOLATION"
    assert expired_findings[0].severity == Severity.P2
    assert expired_findings[0].risk_score == 70

    revoked = ApprovalEvidence(
        tenant_id=tenant,
        approver="security-lead",
        action="AssumeRole",
        resource_id=resource,
        status="REVOKED",
        valid_from=SCENARIO_NOW - timedelta(hours=1),
        valid_to=SCENARIO_NOW + timedelta(hours=1),
    )
    revoked_findings = detect_approval_violation([event], [revoked], covered_sources={"cloudtrail"})
    assert len(revoked_findings) == 1
    assert revoked_findings[0].finding_type == "REVOKED_APPROVAL"
    assert revoked_findings[0].outcome == "VIOLATION"
    assert revoked_findings[0].severity == Severity.P2
    assert revoked_findings[0].risk_score == 70


def test_wrong_action_and_cross_tenant_approvals_are_treated_as_missing() -> None:
    """Approval evidence: wrong-action and cross-tenant approvals do not satisfy.

    Current engine limitation: neither case is classified APPROVAL_MISMATCH.
    A wrong-action approval is excluded from ``same_action_nonmatching``, and a
    cross-tenant approval is filtered out before matching, so both fall through
    to a MISSING_APPROVAL (P2, risk 60, SUSPICIOUS) finding.
    """
    tenant = uuid4()
    event = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-approval-mismatch",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    resource = event.resource_id
    assert resource is not None

    wrong_action = ApprovalEvidence(
        tenant_id=tenant,
        approver="security-lead",
        action="DeleteUser",
        resource_id=resource,
        status="APPROVED",
        valid_from=SCENARIO_NOW - timedelta(hours=1),
        valid_to=SCENARIO_NOW + timedelta(hours=1),
    )
    wrong_action_findings = detect_approval_violation(
        [event], [wrong_action], covered_sources={"cloudtrail"}
    )
    assert len(wrong_action_findings) == 1
    assert wrong_action_findings[0].finding_type == "MISSING_APPROVAL"
    assert wrong_action_findings[0].outcome == "SUSPICIOUS"
    assert wrong_action_findings[0].risk_score == 60

    cross_tenant = ApprovalEvidence(
        tenant_id=uuid4(),
        approver="security-lead",
        action="AssumeRole",
        resource_id=resource,
        status="APPROVED",
        valid_from=SCENARIO_NOW - timedelta(hours=1),
        valid_to=SCENARIO_NOW + timedelta(hours=1),
    )
    cross_tenant_findings = detect_approval_violation(
        [event], [cross_tenant], covered_sources={"cloudtrail"}
    )
    assert len(cross_tenant_findings) == 1
    assert cross_tenant_findings[0].finding_type == "MISSING_APPROVAL"
    assert cross_tenant_findings[0].outcome == "SUSPICIOUS"
    assert cross_tenant_findings[0].tenant_id == tenant


def test_evidence_bundle_hash_is_stable_and_redaction_boundary_is_explicit() -> None:
    """Evidence bundle: hashes are stable and redaction is caller-applied.

    ``build_evidence_bundle`` is deterministic for identical inputs, but it
    copies ``excerpt`` verbatim: the caller must run ``redact_secrets`` before
    including untrusted text. The collector-level pgAudit SQL redaction is
    already applied to ``correlation_metadata["sql_redacted"]``.
    """
    tenant = uuid4()
    event = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-bundle-integrity",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    finding = run_detection([event])[0]
    ref = EvidenceReference(
        id=uuid4(),
        finding_id=finding.id,
        source_event_id=event.event_id,
        content_hash=event.payload_hash,
        excerpt="observed key AKIAIOSFODNN7EXAMPLE",
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=SCENARIO_NOW,
    )
    bundle_a = build_evidence_bundle(finding, [ref])
    bundle_b = build_evidence_bundle(finding, [ref])
    assert bundle_a["bundle_hash"] == bundle_b["bundle_hash"]
    assert len(bundle_a["bundle_hash"]) == 64
    assert bundle_a["evidence"][0]["content_hash"] == event.payload_hash

    # The bundle copies excerpts verbatim; redaction is the caller's duty.
    excerpt = str(bundle_a["evidence"][0]["excerpt"])
    assert "AKIAIOSFODNN7EXAMPLE" in excerpt
    assert "AKIAIOSFODNN7EXAMPLE" not in redact_secrets(excerpt)

    # Tampering with evidence content changes the deterministic hash.
    tampered = EvidenceReference(
        id=ref.id,
        finding_id=finding.id,
        source_event_id=event.event_id,
        content_hash="f" * 64,
        excerpt="different",
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=SCENARIO_NOW,
    )
    bundle_c = build_evidence_bundle(finding, [tampered])
    assert bundle_c["bundle_hash"] != bundle_a["bundle_hash"]

    # pgAudit SQL literals are redacted before the event reaches the bundle.
    pg_line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,3,1,READ,SELECT,"
        "TABLE,public.users,select * from users where email='alice@example.com'"
    )
    pg_rec = parse_pgaudit_line(pg_line)
    assert pg_rec is not None
    pg_event = pg_norm(pg_rec, tenant)
    sql_redacted = str(pg_event.correlation_metadata["sql_redacted"])
    assert "alice@example.com" not in sql_redacted
    assert "'<redacted>'" in sql_redacted


def test_two_tenants_produce_separate_findings_without_cross_tenant_leakage() -> None:
    """Tenant isolation: two tenants' privileged events yield two owned findings.

    Running detection over a combined event stream must attribute each finding
    to the tenant of its source event, with no finding copied across tenants.
    """
    tenant_a = uuid4()
    tenant_b = uuid4()
    event_a = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-tenant-a",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::111:role/Admin"},
        ),
        tenant_a,
    )
    event_b = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-tenant-b",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::222:role/Admin"},
        ),
        tenant_b,
    )
    findings = run_detection([event_a, event_b])
    assert len(findings) == 2
    assert {f.tenant_id for f in findings} == {tenant_a, tenant_b}
    assert sum(1 for f in findings if f.tenant_id == tenant_a) == 1
    assert sum(1 for f in findings if f.tenant_id == tenant_b) == 1
    assert all(f.finding_type == "PRIVILEGE_ESCALATION" for f in findings)


def test_approval_for_one_tenant_does_not_suppress_another_tenants_finding() -> None:
    """Tenant isolation: an approval only authorizes its own tenant's event.

    A valid approval owned by tenant A suppresses tenant A's finding but must
    not suppress tenant B's missing-approval finding.
    """
    tenant_a = uuid4()
    tenant_b = uuid4()
    event_a = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-tenant-suppress-a",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::111:role/Admin"},
        ),
        tenant_a,
    )
    event_b = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-tenant-suppress-b",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::222:role/Admin"},
        ),
        tenant_b,
    )
    resource_a = event_a.resource_id
    assert resource_a is not None
    approval_a = ApprovalEvidence(
        tenant_id=tenant_a,
        approver="security-lead",
        action="AssumeRole",
        resource_id=resource_a,
        status="APPROVED",
        valid_from=SCENARIO_NOW - timedelta(hours=1),
        valid_to=SCENARIO_NOW + timedelta(hours=1),
    )
    findings = detect_approval_violation(
        [event_a, event_b], [approval_a], covered_sources={"cloudtrail"}
    )
    assert len(findings) == 1
    assert findings[0].tenant_id == tenant_b
    assert findings[0].finding_type == "MISSING_APPROVAL"


@pytest.mark.asyncio
async def test_investigation_rejects_evidence_outside_snapshot() -> None:
    """Investigation boundary: model evidence must exist in the snapshot.

    ``run_investigation`` raises ``ValueError`` when the model cites evidence
    that was not supplied in ``evidence_snapshot_ids`` (the model output is
    validated at the trust boundary).
    """
    request = InvestigationRequest(
        investigation_id=uuid4(),
        tenant_id=uuid4(),
        finding_id=uuid4(),
        evidence_snapshot_ids=[uuid4()],
        question="Why did this privileged action occur?",
        max_tool_calls=3,
        max_model_calls=1,
        deadline_seconds=5.0,
    )
    outside = uuid4()
    proposal = InvestigationProposal(
        investigation_id=request.investigation_id,
        hypothesis="Evidence points outside the snapshot.",
        supporting_evidence=[outside],
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="high",
        recommended_disposition="NEEDS_MORE_EVIDENCE",
        model_version="test-model-v1",
        prompt_version="test-prompt-v1",
    )

    class FakeModel:
        async def investigate(
            self, req: InvestigationRequest, evidence: dict[UUID, str]
        ) -> InvestigationProposal:
            return proposal

    async def fetcher(ids: list[UUID]) -> dict[UUID, str]:
        return {i: "redacted excerpt" for i in ids}

    with pytest.raises(ValueError, match="invalid evidence reference"):
        await run_investigation(request, fetch_evidence=fetcher, model=FakeModel())


def test_repeated_detection_produces_identical_stable_findings() -> None:
    """Idempotency: detection is a pure function of the input events.

    Two runs over the same event list produce findings with identical stable
    content (type, severity, outcome, risk, title, tenant, rule version,
    status); only the generated ``id`` / ``detected_at`` may differ.
    """

    def stable(f: Finding) -> tuple[str, str, str, int, str, str, str, str]:
        return (
            f.finding_type,
            str(f.severity),
            f.outcome,
            f.risk_score,
            f.title,
            str(f.tenant_id),
            f.rule_version,
            f.status,
        )

    tenant = uuid4()
    events = _build_events(
        tenant,
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-determinism",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        _gh_record(),
    )
    first = run_detection(events)
    second = run_detection(events)
    assert len(first) == 1
    assert [stable(f) for f in first] == [stable(f) for f in second]
    assert first[0].id != second[0].id


def test_repeated_normalization_produces_stable_idempotency_keys_and_hashes() -> None:
    """Determinism: re-normalizing a source record is content-stable.

    For all three collectors, repeated normalization of the same raw record
    yields the same idempotency key and payload hash; only the generated
    ``event_id`` differs.
    """
    tenant = uuid4()

    ct_record = _ct_record(eventID="e-norm-stable")
    ct_a = ct_norm(ct_record, tenant)
    ct_b = ct_norm(ct_record, tenant)
    assert ct_a.event_id != ct_b.event_id
    assert ct_a.idempotency_key == ct_b.idempotency_key
    assert ct_a.payload_hash == ct_b.payload_hash

    gh_record = _gh_record()
    gh_a = gh_norm(gh_record, tenant)
    gh_b = gh_norm(gh_record, tenant)
    assert gh_a.event_id != gh_b.event_id
    assert gh_a.idempotency_key == gh_b.idempotency_key
    assert gh_a.payload_hash == gh_b.payload_hash

    pg_line = (
        "2026-01-01 12:00:00 UTC:alice@db:LOG:  AUDIT: SESSION,7,1,READ,SELECT,"
        "TABLE,public.users,select * from users"
    )
    pg_rec_a = parse_pgaudit_line(pg_line)
    pg_rec_b = parse_pgaudit_line(pg_line)
    assert pg_rec_a is not None
    assert pg_rec_b is not None
    pg_a = pg_norm(pg_rec_a, tenant)
    pg_b = pg_norm(pg_rec_b, tenant)
    assert pg_a.event_id != pg_b.event_id
    assert pg_a.idempotency_key == pg_b.idempotency_key
    assert pg_a.payload_hash == pg_b.payload_hash


def test_finding_rule_version_and_severity_risk_contract_is_stable() -> None:
    """Contract: core rule families keep their version/severity/risk mapping.

    PRIVILEGE_ESCALATION is P2/SUSPICIOUS/70, FAILED_ACCESS is
    P3/SUSPICIOUS/40 and COVERAGE_GAP is P3/COVERAGE_GAP/30, all under the
    exported ``RULE_VERSION``.
    """
    tenant = uuid4()
    privileged = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-contract-priv",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    failed = ct_norm(
        _ct_record(
            eventSource="s3.amazonaws.com",
            eventName="GetObject",
            eventID="e-contract-fail",
            readOnly=True,
            requestParameters={"bucketName": "audit-logs"},
            errorCode="AccessDenied",
        ),
        tenant,
    )
    gap = detect_coverage_gap("cloudtrail", tenant, None, 3600, now=SCENARIO_NOW)
    assert gap is not None

    findings = run_detection([privileged, failed]) + [gap]
    assert all(f.rule_version == RULE_VERSION == "detection-rules-v1" for f in findings)
    contract = {(f.finding_type, str(f.severity), f.outcome, f.risk_score) for f in findings}
    assert contract == {
        ("PRIVILEGE_ESCALATION", "P2", "SUSPICIOUS", 70),
        ("FAILED_ACCESS", "P3", "SUSPICIOUS", 40),
        ("COVERAGE_GAP", "P3", "COVERAGE_GAP", 30),
    }


def test_approval_rule_family_severity_risk_contract_is_stable() -> None:
    """Contract: approval-evidence findings keep their version/severity/risk.

    Missing approval is P2/SUSPICIOUS/60; expired, revoked and mismatched
    approvals are P2/VIOLATION/70; an unresolved identity is
    P3/INCONCLUSIVE/30. Every finding carries the exported ``RULE_VERSION``.
    """
    tenant = uuid4()
    event = ct_norm(
        _ct_record(
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-contract-approval",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    resource = event.resource_id
    assert resource is not None

    missing = detect_approval_violation([event], [], covered_sources={"cloudtrail"})[0]
    expired = detect_approval_violation(
        [event],
        [
            ApprovalEvidence(
                tenant_id=tenant,
                action="AssumeRole",
                resource_id=resource,
                status="APPROVED",
                valid_from=SCENARIO_NOW - timedelta(days=2),
                valid_to=SCENARIO_NOW - timedelta(days=1),
            )
        ],
        covered_sources={"cloudtrail"},
    )[0]
    revoked = detect_approval_violation(
        [event],
        [
            ApprovalEvidence(
                tenant_id=tenant,
                action="AssumeRole",
                resource_id=resource,
                status="REVOKED",
                valid_from=SCENARIO_NOW - timedelta(hours=1),
                valid_to=SCENARIO_NOW + timedelta(hours=1),
            )
        ],
        covered_sources={"cloudtrail"},
    )[0]
    mismatch = detect_approval_violation(
        [event],
        [
            ApprovalEvidence(
                tenant_id=tenant,
                action="AssumeRole",
                resource_id="arn:aws:iam::123:role/Other",
                status="APPROVED",
                valid_from=SCENARIO_NOW - timedelta(hours=1),
                valid_to=SCENARIO_NOW + timedelta(hours=1),
            )
        ],
        covered_sources={"cloudtrail"},
    )[0]

    unknown_identity_event = ct_norm(
        _ct_record(
            userIdentity={},
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            eventID="e-contract-unknown",
            readOnly=False,
            requestParameters={"roleArn": "arn:aws:iam::123:role/Admin"},
        ),
        tenant,
    )
    inconclusive = detect_approval_violation(
        [unknown_identity_event], [], covered_sources={"cloudtrail"}
    )[0]

    findings = [missing, expired, revoked, mismatch, inconclusive]
    contract = {
        (f.finding_type, str(f.severity), f.outcome, f.risk_score, f.rule_version) for f in findings
    }
    assert contract == {
        ("MISSING_APPROVAL", "P2", "SUSPICIOUS", 60, RULE_VERSION),
        ("EXPIRED_APPROVAL", "P2", "VIOLATION", 70, RULE_VERSION),
        ("REVOKED_APPROVAL", "P2", "VIOLATION", 70, RULE_VERSION),
        ("APPROVAL_MISMATCH", "P2", "VIOLATION", 70, RULE_VERSION),
        ("UNRESOLVED_IDENTITY", "P3", "INCONCLUSIVE", 30, RULE_VERSION),
    }
