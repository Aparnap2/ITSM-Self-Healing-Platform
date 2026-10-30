"""Workflow state schema, routing functions, and bounded-execution helpers.

Routing uses typed statuses and explicit predicates — never substring
matching on natural-language output (PRD §3.2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypedDict

WORKFLOW_VERSION = "1.0.0"


class WorkflowState(TypedDict, total=False):
    """Short-lived orchestration snapshot (PRD §3.3) — not canonical DB state.

    Stores only what is needed to resume safely: references, hashes,
    counters, deadlines. Large raw logs live in the evidence store.
    """

    # Identity
    workflow_id: str
    incident_id: str
    correlation_id: str
    workflow_version: str

    # Normalized request
    incident: dict[str, Any]  # serialized IncidentCreated

    # Orchestration position
    status: str  # IncidentStatus value
    current_node: str

    # Triage / evidence (serialized contract dicts — JSON-safe)
    triage: dict[str, Any] | None
    evidence_ids: list[str]
    evidence_indicates_unhealthy: bool

    # Candidate action + policy
    candidate: dict[str, Any] | None  # serialized ActionProposal
    policy_decision: dict[str, Any] | None  # serialized PolicyDecisionResult
    policy_revalidated: bool

    # Approval
    approval: dict[str, Any] | None  # serialized ApprovalRequestContract
    approval_decision: dict[str, Any] | None  # serialized ApprovalDecision

    # Execution
    action_attempt_id: str | None
    idempotency_key: str | None
    intent_status: str | None  # durable ActionStatus at intent record time
    tool_result: dict[str, Any] | None  # serialized ToolResult
    action_attempts: int

    # Reconciliation (uncertain outcomes — never a blind retry)
    reconciliation: dict[str, Any] | None  # serialized ReconciliationResult
    reconciliation_attempts: int

    # Verification
    verification: dict[str, Any] | None  # serialized VerificationResult

    # Budgets
    max_action_attempts: int
    max_reconciliation_attempts: int
    model_attempts: int
    tool_calls: int
    deadline_at: str | None  # ISO timestamp

    # Outcome
    error_code: str | None
    error_detail: str | None
    itsm_updated: bool
    audit_event_ids: list[str]
    resolution_summary: str | None


# ---------------------------------------------------------------------------
# Bounded-execution helpers
# ---------------------------------------------------------------------------


def parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def deadline_exceeded(state: WorkflowState, now: datetime) -> bool:
    deadline = parse_iso(state.get("deadline_at"))
    return deadline is not None and now >= deadline


def set_error(state: WorkflowState, code: str) -> dict[str, Any]:
    """Terminal escalation update: never resolves, always auditable."""
    return {
        "status": "ESCALATED",
        "current_node": "escalate",
        "error_code": code,
    }


# ---------------------------------------------------------------------------
# Route functions (explicit, typed — PRD §3.2)
# ---------------------------------------------------------------------------


def route_entry(state: WorkflowState) -> str:
    """Fresh run vs. resumed run after approval."""
    if state.get("approval_decision") is not None:
        return "validate_approval"
    return "validate_event"


def route_after_policy(state: WorkflowState) -> str:
    decision = state.get("policy_decision")
    if decision is None:
        return "escalate"
    if decision["outcome"] == "ALLOW":
        return "record_action_intent"
    if decision["outcome"] == "REQUIRE_APPROVAL":
        return "request_approval"
    return "escalate"


def route_after_request_approval(state: WorkflowState) -> str:
    """Persist-and-resume: waiting approval ends this worker invocation."""
    if state.get("approval") is not None:
        return "__end__"
    return "escalate"


def route_after_validate_approval(state: WorkflowState) -> str:
    if state.get("policy_revalidated") and state.get("policy_decision") is not None:
        decision = state["policy_decision"]
        if isinstance(decision, dict) and decision.get("outcome") == "ALLOW":
            return "record_action_intent"
    return "escalate"


def route_after_execute(state: WorkflowState) -> str:
    result = state.get("tool_result")
    if result is None:
        return "escalate"
    if result["status"] == "SUCCEEDED":
        return "verify_postcondition"
    if result["status"] == "OUTCOME_UNKNOWN":
        # Never retry a possibly-applied mutation: reconcile first.
        return "reconcile_uncertain_action"
    # FAILED: only a provably pre-execution failure may be retried, and only
    # through the same policy-checked retry path as reconciliation.
    if result.get("retryable") is True:
        return "prepare_retry"
    return "escalate"


def route_after_reconcile(state: WorkflowState) -> str:
    if state.get("error_code") is not None:
        return "escalate"
    reconciliation = state.get("reconciliation")
    if reconciliation is None:
        return "escalate"
    outcome = reconciliation["outcome"]
    if outcome == "APPLIED":
        return "verify_postcondition"
    if outcome == "NOT_APPLIED":
        if state.get("action_attempts", 0) >= state.get("max_action_attempts", 1):
            return "escalate"
        return "prepare_retry"
    # INCONCLUSIVE: bounded reconciliation passes, then escalate.
    if state.get("reconciliation_attempts", 0) >= state.get("max_reconciliation_attempts", 2):
        return "escalate"
    if state.get("action_attempts", 0) >= state.get("max_action_attempts", 1):
        return "escalate"
    return "reconcile_uncertain_action"


def route_after_retry_precheck(state: WorkflowState) -> str:
    decision = state.get("policy_decision")
    if decision is not None and decision["outcome"] == "ALLOW":
        return "record_action_intent"
    return "escalate"


def route_after_verify(state: WorkflowState) -> str:
    verification = state.get("verification")
    if verification is not None and verification["passed"] is True:
        return "update_itsm"
    return "escalate"


def route_terminal(state: WorkflowState) -> str:
    """After finalize_audit: end the run."""
    return "__end__"
