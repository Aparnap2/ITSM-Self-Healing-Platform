"""Deterministic detection engine (Task 12). Pure domain logic, no LLM."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from itsm_agent.domain.events import SourceEvent, ensure_utc
from itsm_agent.domain.models import Finding, Severity

RULE_VERSION = "detection-rules-v1"


def _finding(
    tenant_id: UUID,
    finding_type: str,
    severity: Severity,
    title: str,
    description: str,
    outcome: str,
    risk_score: int = 50,
) -> Finding:
    return Finding(
        id=uuid4(),
        tenant_id=tenant_id,
        finding_type=finding_type,
        severity=severity,
        status="OPEN",
        title=title,
        description=description,
        detected_at=datetime.now(tz=UTC),
        rule_version=RULE_VERSION,
        risk_score=risk_score,
        outcome=outcome,
    )


def detect_privilege_escalation(events: list[SourceEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for ev in events:
        name = ev.event_type.lower()
        if (
            "assumerole" in name
            or "attach" in name
            or "putrolepolicy" in name
            or "createuser" in name
        ):
            findings.append(
                _finding(
                    ev.tenant_id,
                    "PRIVILEGE_ESCALATION",
                    Severity.P2,
                    f"Privileged action: {ev.event_type}",
                    f"Principal {ev.principal_id or ev.actor_id} performed "
                    f"{ev.event_type} on {ev.resource_id}",
                    "SUSPICIOUS",
                    70,
                )
            )
    return findings


def detect_failed_access(events: list[SourceEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for ev in events:
        if ev.outcome == "failure" or ev.outcome == "denied":
            findings.append(
                _finding(
                    ev.tenant_id,
                    "FAILED_ACCESS",
                    Severity.P3,
                    f"Failed/denied action: {ev.event_type}",
                    f"Action {ev.event_type} by {ev.actor_id} returned {ev.outcome}",
                    "SUSPICIOUS",
                    40,
                )
            )
    return findings


def detect_coverage_gap(
    source: str,
    tenant_id: UUID,
    last_event_time: datetime | None,
    expected_cadence_seconds: int,
    now: datetime | None = None,
) -> Finding | None:
    now = now or datetime.now(tz=UTC)
    if last_event_time is None:
        return _finding(
            tenant_id,
            "COVERAGE_GAP",
            Severity.P3,
            f"No events from {source}",
            f"Source {source} has no recorded events",
            "COVERAGE_GAP",
            30,
        )
    if (now - last_event_time).total_seconds() > expected_cadence_seconds:
        return _finding(
            tenant_id,
            "COVERAGE_GAP",
            Severity.P3,
            f"Source {source} silent",
            f"Last event from {source} at {last_event_time.isoformat()} exceeds cadence",
            "COVERAGE_GAP",
            30,
        )
    return None


# ---------------------------------------------------------------------------
# 12.8 Approval-evidence detection
# ---------------------------------------------------------------------------

# (SourceEvent is imported at module top)


def _is_privileged_event(ev: SourceEvent) -> bool:
    name = ev.event_type.lower()
    return (
        "assumerole" in name
        or "attach" in name
        or "putrolepolicy" in name
        or "createuser" in name
        or "putuserpolicy" in name
        or "createaccesskey" in name
        or "deactivateaccesskey" in name
        or "deleteuser" in name
    )


def _as_approval(raw: object) -> dict[str, object]:
    """Normalize an approval record (model or dict) into a loose dict."""
    if isinstance(raw, dict):
        return dict(raw)
    out: dict[str, object] = {}
    for attr in (
        "id",
        "approval_id",
        "tenant_id",
        "approver_id",
        "approver",
        "action",
        "action_type",
        "event_type",
        "resource_id",
        "resource",
        "target",
        "target_id",
        "scope",
        "parameters",
        "context",
        "status",
        "decision",
        "outcome",
        "actor_id",
        "subject",
        "principal_id",
        "valid_from",
        "valid_from_at",
        "issued_at",
        "requested_at",
        "created_at",
        "decided_at",
        "valid_to",
        "valid_until",
        "expires_at",
        "expiry",
        "source",
        "provenance",
    ):
        val = getattr(raw, attr, None)
        if val is not None:
            out[attr] = val
    # Also pull from resolved_* helpers if present.
    for helper, key in (
        ("resolved_approver", "approver_id"),
        ("resolved_action", "action"),
        ("resolved_resource", "resource_id"),
        ("resolved_actor", "actor_id"),
        ("resolved_status", "status"),
        ("resolved_valid_from", "valid_from"),
        ("resolved_valid_to", "valid_to"),
    ):
        fn = getattr(raw, helper, None)
        if callable(fn):
            try:
                v = fn()
            except Exception:
                v = None
            if v is not None and key not in out:
                out[key] = v
    return out


def _norm_dt(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    # Allow ISO strings.
    try:
        return ensure_utc(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except (ValueError, TypeError):
        return None


def _approval_status(ap: dict[str, object]) -> str:
    raw = ap.get("status") or ap.get("decision") or ap.get("outcome") or "APPROVED"
    return str(raw).upper()


def _approval_matches_event(ap: dict[str, object], ev: SourceEvent) -> bool:
    # Tenant isolation: an approval from another tenant never satisfies.
    ap_tenant = ap.get("tenant_id")
    if ap_tenant is not None and ap_tenant != ev.tenant_id:
        return False
    # Action dimension.
    ap_action = ap.get("action") or ap.get("action_type") or ap.get("event_type")
    if ap_action is not None:
        s = str(ap_action).strip().lower()
        if (
            s not in ("", "*", "any", "all", "none")
            and s != ev.event_type.lower()
            and s != ev.action.lower()
        ):
            return False
    # Resource dimension.
    ap_resource = (
        ap.get("resource_id") or ap.get("resource") or ap.get("target") or ap.get("target_id")
    )
    if ap_resource is not None:
        s = str(ap_resource).strip()
        if s not in ("", "*", "any", "all", "none"):
            if ev.resource_id is not None and s != str(ev.resource_id):
                return False
            if (
                ev.resource_id is None
                and ev.resource_type is not None
                and s != str(ev.resource_type)
            ):
                return False
    # Actor/subject dimension (only enforced when the approval declares one).
    ap_actor = ap.get("actor_id") or ap.get("subject") or ap.get("principal_id")
    if ap_actor is not None:
        s = str(ap_actor).strip()
        if s not in ("", "*", "any", "all", "none"):
            candidates = {x for x in (ev.actor_id, ev.principal_id) if x is not None}
            if candidates and s not in candidates:
                return False
    # Scope dimension: every declared scope key must match the event.
    scope = ap.get("scope") or ap.get("parameters") or ap.get("context") or {}
    if isinstance(scope, dict):
        for key, val in scope.items():
            ev_val = ev.permission_context.get(key)
            if ev_val is None:
                ev_val = ev.correlation_metadata.get(key)
            if ev_val is not None and ev_val != val:
                return False
    return True


def _is_valid_approval(ap: dict[str, object], event_time: datetime) -> bool:
    status = _approval_status(ap)
    if status not in ("APPROVED", "APPROVE"):
        return False
    vf = _norm_dt(ap.get("valid_from"))
    vt = _norm_dt(ap.get("valid_to"))
    if vf is not None and event_time < vf:
        return False
    return not (vt is not None and event_time > vt)


def _classify_approval_failure(ap: dict[str, object], event_time: datetime) -> str:
    status = _approval_status(ap)
    if status in ("DENIED", "REJECTED"):
        return "DENIED_APPROVAL"
    if status == "REVOKED":
        return "REVOKED_APPROVAL"
    if status in ("EXPIRED",):
        return "EXPIRED_APPROVAL"
    vt = _norm_dt(ap.get("valid_to"))
    if vt is not None and event_time > vt:
        return "EXPIRED_APPROVAL"
    # mismatched: approval exists for same tenant but dimensions differ;
    # handled by caller via _approval_matches_event == False.
    return "APPROVAL_MISMATCH"


def detect_approval_violation(
    events: list[SourceEvent],
    approvals: list[object] | None = None,
    *,
    covered_sources: Any = None,
    source_coverage: Any = None,
    now: datetime | None = None,
) -> list[Finding]:
    """Approval-evidence detection (Task 12.8).

    For each privileged event, determine whether a valid, matching approval
    exists. Produces findings only when no valid matching approval is found;
    a valid matching approval suppresses the finding entirely.

    Outcomes:
      - VIOLATION: denied/revoked/expired/mismatched approval evidence.
      - SUSPICIOUS: privileged action with no approval in a fully covered
        source with a known identity.
      - COVERAGE_GAP: privileged action with no approval where source
        coverage is incomplete (not a confirmed violation).
      - INCONCLUSIVE: privileged action with no approval and an unresolved
        identity.
    """
    approvals = approvals or []
    norm_approvals = [_as_approval(a) for a in approvals]
    # Normalize coverage inputs.
    covered: set[str] | None = None
    if covered_sources is not None:
        try:
            covered = {str(x) for x in covered_sources}
        except TypeError:
            covered = None
    coverage_map: dict[str, bool] | None = None
    if isinstance(source_coverage, dict):
        coverage_map = {str(k): bool(v) for k, v in source_coverage.items()}

    def source_is_covered(src: str) -> bool:
        if coverage_map is not None and src in coverage_map:
            return coverage_map[src]
        if covered is not None:
            return src in covered
        # Default: assume full coverage (closed-world for the demo).
        return True

    now = now or datetime.now(tz=UTC)
    findings: list[Finding] = []
    for ev in events:
        if not _is_privileged_event(ev):
            continue
        event_time = ensure_utc(ev.event_time)
        # Cross-tenant filter: only approvals for this tenant are eligible.
        tenant_approvals = [a for a in norm_approvals if a.get("tenant_id") == ev.tenant_id]

        # Unknown identity -> preserve uncertainty, no confirmed violation.
        identity_unknown = ev.actor_id is None and ev.principal_id is None

        # Find matching approvals (dimension-wise).
        matching = [a for a in tenant_approvals if _approval_matches_event(a, ev)]
        # Non-matching approvals for the same tenant+action suggest mismatch.
        same_action_nonmatching = [
            a
            for a in tenant_approvals
            if not _approval_matches_event(a, ev)
            and (
                str(a.get("action") or a.get("action_type") or "").lower()
                in ("", "*", "any", "all", "none", ev.event_type.lower(), ev.action.lower())
            )
        ]

        # Check for a valid matching approval -> authorized, no finding.
        valid_matching = [a for a in matching if _is_valid_approval(a, event_time)]
        if valid_matching:
            continue

        # Determine finding type + outcome.
        if identity_unknown:
            findings.append(
                _finding(
                    ev.tenant_id,
                    "UNRESOLVED_IDENTITY",
                    Severity.P3,
                    f"Privileged action with unresolved identity: {ev.event_type}",
                    f"Principal unresolved for {ev.event_type} on {ev.resource_id}; "
                    f"approval evidence cannot be attributed",
                    "INCONCLUSIVE",
                    30,
                )
            )
            continue

        src = str(ev.source)
        if not source_is_covered(src):
            findings.append(
                _finding(
                    ev.tenant_id,
                    "COVERAGE_GAP",
                    Severity.P3,
                    f"Approval coverage gap: {ev.event_type}",
                    f"Source {src} coverage incomplete; cannot confirm approval "
                    f"for {ev.event_type} by {ev.actor_id or ev.principal_id}",
                    "COVERAGE_GAP",
                    30,
                )
            )
            continue

        # Coverage complete, identity known: classify the failure mode.
        if matching:
            # Pick the strongest negative among matching approvals.
            neg = None
            for a in matching:
                st = _approval_status(a)
                if st in ("DENIED", "REJECTED"):
                    neg = ("DENIED_APPROVAL", "VIOLATION")
                    break
            if neg is None:
                for a in matching:
                    if _approval_status(a) == "REVOKED":
                        neg = ("REVOKED_APPROVAL", "VIOLATION")
                        break
            if neg is None:
                for a in matching:
                    vt = _norm_dt(a.get("valid_to"))
                    st = _approval_status(a)
                    if st == "EXPIRED" or (vt is not None and event_time > vt):
                        neg = ("EXPIRED_APPROVAL", "VIOLATION")
                        break
            if neg is None:
                neg = ("APPROVAL_MISMATCH", "VIOLATION")
            ftype, outcome = neg
            findings.append(
                _finding(
                    ev.tenant_id,
                    ftype,
                    Severity.P2 if outcome == "VIOLATION" else Severity.P3,
                    f"Approval failure: {ev.event_type}",
                    f"Privileged action {ev.event_type} by "
                    f"{ev.actor_id or ev.principal_id} on {ev.resource_id} "
                    f"has no valid approval ({ftype})",
                    outcome,
                    70 if outcome == "VIOLATION" else 50,
                )
            )
        elif same_action_nonmatching:
            findings.append(
                _finding(
                    ev.tenant_id,
                    "APPROVAL_MISMATCH",
                    Severity.P2,
                    f"Approval mismatch: {ev.event_type}",
                    f"Privileged action {ev.event_type} by "
                    f"{ev.actor_id or ev.principal_id} on {ev.resource_id} "
                    f"has approval evidence but dimensions do not match",
                    "VIOLATION",
                    70,
                )
            )
        else:
            findings.append(
                _finding(
                    ev.tenant_id,
                    "MISSING_APPROVAL",
                    Severity.P2,
                    f"Privileged action without approval: {ev.event_type}",
                    f"Privileged action {ev.event_type} by "
                    f"{ev.actor_id or ev.principal_id} on {ev.resource_id} "
                    f"has no approval evidence",
                    "SUSPICIOUS",
                    60,
                )
            )
    return findings


# Backwards-compatible / discoverable aliases.
detect_missing_approval = detect_approval_violation
detect_approval_mismatch = detect_approval_violation
detect_unapproved_privileged_activity = detect_approval_violation
detect_unapproved_activity = detect_approval_violation
detect_approval_evidence = detect_approval_violation
detect_approval_gap = detect_approval_violation


def run_detection(
    events: list[SourceEvent],
    approvals: list[object] | None = None,
    *,
    covered_sources: Any = None,
    source_coverage: Any = None,
    now: datetime | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    out.extend(detect_privilege_escalation(events))
    out.extend(detect_failed_access(events))
    if approvals is not None or covered_sources is not None or source_coverage is not None:
        out.extend(
            detect_approval_violation(
                events,
                approvals,
                covered_sources=covered_sources,
                source_coverage=source_coverage,
                now=now,
            )
        )
    return out


__all__ = [
    "RULE_VERSION",
    "detect_approval_evidence",
    "detect_approval_gap",
    "detect_approval_mismatch",
    "detect_approval_violation",
    "detect_coverage_gap",
    "detect_failed_access",
    "detect_missing_approval",
    "detect_privilege_escalation",
    "detect_unapproved_activity",
    "detect_unapproved_privileged_activity",
    "run_detection",
]
