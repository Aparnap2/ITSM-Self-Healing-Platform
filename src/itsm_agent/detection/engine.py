"""Deterministic detection engine (Task 12). Pure domain logic, no LLM."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from itsm_agent.domain.events import SourceEvent
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


def run_detection(events: list[SourceEvent]) -> list[Finding]:
    out: list[Finding] = []
    out.extend(detect_privilege_escalation(events))
    out.extend(detect_failed_access(events))
    return out


__all__ = [
    "RULE_VERSION",
    "detect_coverage_gap",
    "detect_failed_access",
    "detect_privilege_escalation",
    "run_detection",
]
