"""Explicit state-transition tables (PRD §3.1, §3.3).

All transitions must be explicit. Illegal transitions raise
``IllegalTransitionError`` and fail closed; they are audited by callers.
Pure domain: stdlib only.
"""

from __future__ import annotations

from enum import StrEnum

from itsm_agent.domain.errors import IllegalTransitionError
from itsm_agent.domain.models import IncidentStatus, WorkflowStatus

#: Allowed incident status transitions (PRD §3.1 canonical workflow).
ALLOWED_INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset(
        {IncidentStatus.TRIAGED, IncidentStatus.REJECTED, IncidentStatus.ESCALATED}
    ),
    IncidentStatus.TRIAGED: frozenset({IncidentStatus.IN_PROGRESS, IncidentStatus.ESCALATED}),
    IncidentStatus.IN_PROGRESS: frozenset(
        {
            IncidentStatus.WAITING_APPROVAL,
            IncidentStatus.RESOLVED,
            IncidentStatus.ESCALATED,
        }
    ),
    IncidentStatus.WAITING_APPROVAL: frozenset(
        {IncidentStatus.IN_PROGRESS, IncidentStatus.ESCALATED}
    ),
    # Terminal states have no outgoing transitions.
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.ESCALATED: frozenset(),
    IncidentStatus.REJECTED: frozenset(),
}

#: Allowed workflow-run status transitions.
ALLOWED_WORKFLOW_TRANSITIONS: dict[WorkflowStatus, frozenset[WorkflowStatus]] = {
    WorkflowStatus.PENDING: frozenset({WorkflowStatus.RUNNING}),
    WorkflowStatus.RUNNING: frozenset(
        {
            WorkflowStatus.WAITING_APPROVAL,
            WorkflowStatus.SUCCEEDED,
            WorkflowStatus.FAILED,
            WorkflowStatus.ESCALATED,
            WorkflowStatus.CANCELLED,
        }
    ),
    WorkflowStatus.WAITING_APPROVAL: frozenset(
        {WorkflowStatus.RUNNING, WorkflowStatus.ESCALATED, WorkflowStatus.CANCELLED}
    ),
    WorkflowStatus.SUCCEEDED: frozenset(),
    WorkflowStatus.FAILED: frozenset(),
    WorkflowStatus.ESCALATED: frozenset(),
    WorkflowStatus.CANCELLED: frozenset(),
}


def transition[StrEnumT: StrEnum](
    current: StrEnumT,
    target: StrEnumT,
    table: dict[StrEnumT, frozenset[StrEnumT]],
) -> StrEnumT:
    """Apply an explicit transition or fail closed."""
    if target not in table.get(current, frozenset()):
        raise IllegalTransitionError(
            f"Illegal transition {current} -> {target}",
            code="ILLEGAL_TRANSITION",
        )
    return target


def transition_incident(current: IncidentStatus, target: IncidentStatus) -> IncidentStatus:
    return transition(current, target, ALLOWED_INCIDENT_TRANSITIONS)


def transition_workflow(current: WorkflowStatus, target: WorkflowStatus) -> WorkflowStatus:
    return transition(current, target, ALLOWED_WORKFLOW_TRANSITIONS)


def is_terminal_incident(status: IncidentStatus) -> bool:
    return not ALLOWED_INCIDENT_TRANSITIONS[status]


def is_terminal_workflow(status: WorkflowStatus) -> bool:
    return not ALLOWED_WORKFLOW_TRANSITIONS[status]
