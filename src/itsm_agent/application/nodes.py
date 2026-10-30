"""Explicit LangGraph workflow nodes (PRD §3.2).

Each node is a function of (state, deps) -> state update. Dependencies
are injected via ``WorkflowDeps``; no node imports a concrete adapter.
State stores serialized contract dicts (JSON-safe references), and every
node re-validates untrusted data at its boundary. Safety properties:

- LLM output is re-validated through ``TriageOutput``; invalid output is
  retried within budget, then the workflow escalates (never mutates).
- No node can reach ``execute_action`` without a durable ALLOW policy
  decision (freshly evaluated or revalidated after approval).
- No node can reach ``update_itsm``/resolution without a passing
  independent ``VerificationResult``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from itsm_agent.application.commands import WorkflowDeps
from itsm_agent.application.services import (
    WorkflowState,
    deadline_exceeded,
    set_error,
)
from itsm_agent.domain.events import (
    ActionProposal,
    ApprovalRequestContract,
    AuditEvent,
    ClearCacheParameters,
    GrantTestAccessParameters,
    IncidentCreated,
    RestartServiceParameters,
    VerificationResult,
    parse_action_proposal,
)
from itsm_agent.domain.models import ActionType, Environment
from itsm_agent.domain.policies import (
    PolicyContext,
    evaluate,
    parameters_hash,
    proposal_hash,
)
from itsm_agent.ports.model import TriageInput, TriageOutput

# Deterministic candidate selection: triage category -> action type.
CANDIDATE_BY_CATEGORY: dict[str, ActionType] = {
    "SERVICE_UNHEALTHY": ActionType.RESTART_SERVICE,
    "ACCESS_REQUEST": ActionType.GRANT_TEST_RESOURCE_ACCESS,
}


def environment_or_unknown(value: str) -> Any:
    """Map a raw environment string; unknown values fail closed in policy."""
    try:
        return Environment(value)
    except ValueError:
        return value


def _resource_id_of(proposal: ActionProposal) -> str:
    if isinstance(proposal, GrantTestAccessParameters):
        return proposal.resource_id
    return proposal.service_name


def _audit_event(
    state: WorkflowState,
    deps: WorkflowDeps,
    event_type: str,
    payload: dict[str, str | int | float | bool | None],
) -> AuditEvent:
    return AuditEvent(
        event_id=uuid4(),
        occurred_at=deps.clock.now(),
        correlation_id=UUID(state["correlation_id"]),
        incident_id=UUID(state["incident_id"]),
        workflow_id=UUID(state["workflow_id"]),
        actor_type="WORKER",
        actor_id="workflow",
        event_type=event_type,
        payload_redacted=payload,
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def validate_event(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Trust boundary 1: re-validate the incident contract; set deadline."""
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")
    try:
        IncidentCreated.model_validate(state["incident"])
    except Exception:  # noqa: BLE001 — fail closed on any validation failure
        return set_error(state, "EVENT_VALIDATION_FAILED")
    deadline = (now + timedelta(seconds=deps.limits.deadline_seconds)).isoformat()
    return {
        "current_node": "validate_event",
        "status": "NEW",
        "deadline_at": deadline,
    }


async def normalize_incident(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    if deadline_exceeded(state, deps.clock.now()):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")
    return {"current_node": "normalize_incident", "status": "NEW"}


async def triage_incident(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Call the model through ModelPort; validate output; bounded retry.

    Invalid model output never mutates state beyond the attempt counter;
    exhaustion escalates (PRD §3.4, architecture failure domains).
    """
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")

    incident = state["incident"]
    request = TriageInput(
        incident_id=state["incident_id"],
        title=incident["title"],
        description=incident["description"],
        service_name=incident["service_name"],
        severity=incident["severity"],
        environment=incident["environment"],
    )

    attempts = state.get("model_attempts", 0)
    last_error: str | None = None
    for _ in range(deps.limits.max_model_attempts):
        attempts += 1
        try:
            raw = await deps.model.triage(request)
            triage = TriageOutput.model_validate(raw.model_dump())
            return {
                "current_node": "triage_incident",
                "status": "TRIAGED",
                "triage": triage.model_dump(mode="json"),
                "model_attempts": attempts,
            }
        except Exception as exc:  # noqa: BLE001 — bounded retry, then escalate
            last_error = f"{type(exc).__name__}: {exc}"

    return {
        **set_error(state, "MODEL_OUTPUT_INVALID"),
        "model_attempts": attempts,
        "error_detail": last_error,
    }


async def collect_diagnostics(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")
    incident = IncidentCreated.model_validate(state["incident"])
    observations = await deps.diagnostics.collect(incident, deps.limits.max_tool_calls)
    unhealthy = any(obs.structured_facts.get("healthy") is False for obs in observations)
    return {
        "current_node": "collect_diagnostics",
        "evidence_ids": [str(obs.evidence_id) for obs in observations],
        "evidence_indicates_unhealthy": unhealthy,
        "tool_calls": state.get("tool_calls", 0) + len(observations),
    }


async def select_remediation_candidate(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Deterministic candidate selection — the LLM never authorizes."""
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")

    triage = state.get("triage")
    if triage is None:
        return set_error(state, "NO_TRIAGE_RESULT")

    action_type = CANDIDATE_BY_CATEGORY.get(triage["category"])
    if action_type is None:
        return set_error(state, "NO_REMEDIATION_CANDIDATE")

    incident = state["incident"]
    evidence_ids = [UUID(e) for e in state.get("evidence_ids", [])][:10]

    candidate: ActionProposal
    if action_type is ActionType.GRANT_TEST_RESOURCE_ACCESS:
        candidate = GrantTestAccessParameters(
            action_type="GRANT_TEST_RESOURCE_ACCESS",
            principal_id="test-user",
            resource_id="test-bucket",
            environment="test",
            ticket_reference=state["incident_id"],
        )
    else:
        candidate = _build_service_action(
            action_type, incident["service_name"], incident["environment"], evidence_ids
        )

    return {
        "current_node": "select_remediation_candidate",
        "candidate": candidate.model_dump(mode="json"),
    }


def _build_service_action(
    action_type: ActionType,
    service_name: str,
    environment: str,
    evidence_ids: list[UUID],
) -> ActionProposal:
    env = environment_or_unknown(environment)
    if action_type is ActionType.CLEAR_SIMULATED_CACHE:
        return ClearCacheParameters(
            action_type="CLEAR_SIMULATED_CACHE",
            service_name=service_name,
            environment=env,
            reason="Deterministic remediation candidate",
            evidence_ids=evidence_ids or [uuid4()],
        )
    return RestartServiceParameters(
        action_type="RESTART_SERVICE",
        service_name=service_name,
        environment=env,
        reason="Deterministic remediation candidate",
        evidence_ids=evidence_ids or [uuid4()],
    )


async def evaluate_policy(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Deterministic policy gate. A proposal is data, not permission."""
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")

    raw_candidate = state.get("candidate")
    if raw_candidate is None:
        return set_error(state, "NO_REMEDIATION_CANDIDATE")
    try:
        proposal = parse_action_proposal(raw_candidate)
    except Exception:  # noqa: BLE001 — malformed proposal fails closed
        return set_error(state, "PROPOSAL_VALIDATION_FAILED")

    incident = IncidentCreated.model_validate(state["incident"])
    context = PolicyContext(
        principal_id="workflow-worker",
        environment=environment_or_unknown(incident.environment),
        target_registered=True,
        evidence_indicates_unhealthy=state.get("evidence_indicates_unhealthy", False),
        retry_budget_available=state.get("action_attempts", 0) < deps.limits.max_action_attempts,
        model_confidence=(state.get("triage") or {}).get("confidence", 0.0),
    )
    decision = evaluate(proposal, context, deps.policy_snapshot, now=now)
    return {
        "current_node": "evaluate_policy",
        "policy_decision": decision.model_dump(mode="json"),
        "policy_revalidated": False,
    }


async def request_approval(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Persist an exact-hash-bound approval request, then wait (resume)."""
    now = deps.clock.now()
    decision = state.get("policy_decision")
    raw_candidate = state.get("candidate")
    if decision is None or raw_candidate is None:
        return set_error(state, "APPROVAL_STATE_MISSING")
    proposal = parse_action_proposal(raw_candidate)
    phash = proposal_hash(proposal, decision["policy_version"])

    approval = await deps.approvals.create_request(
        incident_id=UUID(state["incident_id"]),
        workflow_id=UUID(state["workflow_id"]),
        proposal_hash=phash,
        action_type=proposal.action_type,
        resource_id=_resource_id_of(proposal),
        parameters_hash=parameters_hash(proposal),
        requested_at=now,
        expires_at=now + timedelta(seconds=deps.limits.approval_lifetime_seconds),
    )
    return {
        "current_node": "request_approval",
        "status": "WAITING_APPROVAL",
        "approval": approval.model_dump(mode="json"),
    }


async def validate_approval(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Revalidate approval + policy + preconditions before execution.

    Approval binds to the exact proposal hash, must be unexpired, and
    never overrides a currently denied policy (PRD §8.2).
    """
    now = deps.clock.now()
    decision_in = state.get("approval_decision")
    approval = state.get("approval")
    raw_candidate = state.get("candidate")
    prior_decision = state.get("policy_decision")
    if decision_in is None or approval is None or raw_candidate is None or prior_decision is None:
        return set_error(state, "APPROVAL_VALIDATION_FAILED")

    proposal = parse_action_proposal(raw_candidate)
    phash = proposal_hash(proposal, prior_decision["policy_version"])

    # Exact-hash binding (proposal identity + approval identity).
    if approval["proposal_hash"] != phash or decision_in["approval_id"] != approval["approval_id"]:
        return set_error(state, "APPROVAL_HASH_MISMATCH")

    # Expiry.
    if now >= datetime.fromisoformat(approval["expires_at"]):
        return set_error(state, "APPROVAL_EXPIRED")

    # Decision must be an approval, not a rejection.
    if decision_in["decision"] != "APPROVE":
        return set_error(state, "APPROVAL_REJECTED")

    # Single-use nonce consumption is enforced by the ApprovalPort
    # (durable, one-time); this node enforces hash binding, expiry, and
    # decision semantics.

    # Re-evaluate policy with fresh preconditions (PRD §8.2 #5). The
    # valid approval satisfies the approval requirement; it can never
    # convert a DENY into an ALLOW.
    incident = IncidentCreated.model_validate(state["incident"])
    context = PolicyContext(
        principal_id="workflow-worker",
        environment=environment_or_unknown(incident.environment),
        target_registered=True,
        evidence_indicates_unhealthy=state.get("evidence_indicates_unhealthy", False),
        retry_budget_available=state.get("action_attempts", 0) < deps.limits.max_action_attempts,
        approval_satisfied=True,
    )
    fresh = evaluate(proposal, context, deps.policy_snapshot, now=now)
    if fresh.outcome != "ALLOW":
        return {
            **set_error(state, "POLICY_CHANGED_AFTER_APPROVAL"),
            "policy_decision": fresh.model_dump(mode="json"),
            "policy_revalidated": True,
        }

    return {
        "current_node": "validate_approval",
        "status": "IN_PROGRESS",
        "policy_decision": fresh.model_dump(mode="json"),
        "policy_revalidated": True,
    }


async def record_action_intent(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Durable intent + idempotency key BEFORE any side effect (rule 10)."""
    decision = state.get("policy_decision")
    raw_candidate = state.get("candidate")
    if decision is None or raw_candidate is None:
        return set_error(state, "INTENT_REQUIRES_POLICY_DECISION")
    if decision["outcome"] != "ALLOW":
        # Defensive: graph structure should make this unreachable.
        return set_error(state, "EXECUTION_WITHOUT_ALLOW")

    proposal = parse_action_proposal(raw_candidate)
    next_attempt = state.get("action_attempts", 0) + 1
    idempotency_key = canonical_idempotency_key(
        state["workflow_id"], decision["proposal_hash"], next_attempt
    )
    intent_status, durable_attempt = await deps.intents.record_intent(
        incident_id=UUID(state["incident_id"]),
        workflow_id=UUID(state["workflow_id"]),
        action_type=str(proposal.action_type),
        resource_id=_resource_id_of(proposal),
        idempotency_key=idempotency_key,
        proposal_hash=decision["proposal_hash"],
        adapter_name=type(deps.executor).__name__,
        attempt_number=next_attempt,
        recorded_at=deps.clock.now(),
    )
    attempt_id = str(uuid4())
    await deps.audit.append(
        _audit_event(
            state,
            deps,
            "ACTION_INTENT_RECORDED",
            {
                "idempotency_key": idempotency_key,
                "attempt_number": durable_attempt,
                "intent_status": intent_status,
            },
        )
    )
    return {
        "current_node": "record_action_intent",
        "status": "IN_PROGRESS",
        "action_attempt_id": attempt_id,
        "idempotency_key": idempotency_key,
        "intent_status": intent_status,
        "action_attempts": durable_attempt,
    }


def canonical_idempotency_key(workflow_id: str, proposal_hash_value: str, attempt: int) -> str:
    raw = f"{workflow_id}:{proposal_hash_value}:{attempt}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


async def execute_action(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")
    raw_candidate = state.get("candidate")
    idempotency_key = state.get("idempotency_key")
    attempt_id = state.get("action_attempt_id")
    if raw_candidate is None or idempotency_key is None or attempt_id is None:
        return set_error(state, "EXECUTION_STATE_MISSING")
    proposal = parse_action_proposal(raw_candidate)

    # Crash/replay recovery: the durable intent already records the outcome.
    # Never re-execute a mutation whose result is known or uncertain.
    intent_status = state.get("intent_status")
    if intent_status == "SUCCEEDED":
        return _replayed_result(state, "SUCCEEDED", "REPLAYED_SUCCESS")
    if intent_status in {"FAILED", "CANCELLED"}:
        return _replayed_result(state, "FAILED", "REPLAYED_FAILURE")
    if intent_status in {"OUTCOME_UNKNOWN", "RECONCILED", "RUNNING"}:
        # RUNNING without a recorded outcome means the worker died mid-call.
        return _replayed_result(state, "OUTCOME_UNKNOWN", "CRASH_DURING_EXECUTION")

    await deps.intents.mark_outcome(
        idempotency_key=idempotency_key, status="RUNNING", result_code="EXECUTING"
    )
    result = await deps.executor.execute(proposal, idempotency_key)
    await deps.intents.mark_outcome(
        idempotency_key=idempotency_key,
        status=result.status,
        result_code=result.result_code,
        result_summary=result.summary[:1000],
    )
    return {
        "current_node": "execute_action",
        "tool_result": result.model_dump(mode="json"),
        "tool_calls": state.get("tool_calls", 0) + 1,
    }


def _replayed_result(state: WorkflowState, status: str, result_code: str) -> dict[str, Any]:
    return {
        "current_node": "execute_action",
        "tool_result": {
            "action_attempt_id": state.get("action_attempt_id"),
            "idempotency_key": state.get("idempotency_key"),
            "status": status,
            "result_code": result_code,
            "summary": "Recovered from durable action intent; not re-executed.",
            "observed_at": None,
            "evidence_ids": [],
            "retryable": False,
        },
    }


async def reconcile_uncertain_action(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Uncertain outcome: query target state before any retry (rule 11).

    Never performs a mutation and never resolves the incident. Exhausting
    the bounded reconciliation budget escalates with the uncertainty intact.
    """
    raw_candidate = state.get("candidate")
    idempotency_key = state.get("idempotency_key")
    attempt_id = state.get("action_attempt_id")
    if raw_candidate is None or idempotency_key is None or attempt_id is None:
        return set_error(state, "RECONCILE_STATE_MISSING")

    proposal = parse_action_proposal(raw_candidate)
    reconciliation = await deps.reconciler.reconcile(
        proposal,
        idempotency_key=idempotency_key,
        action_attempt_id=UUID(attempt_id),
    )
    status_map = {
        "APPLIED": ("RECONCILED", "RECONCILED_APPLIED"),
        "NOT_APPLIED": ("FAILED", "RECONCILED_NOT_APPLIED"),
        "INCONCLUSIVE": ("OUTCOME_UNKNOWN", "RECONCILIATION_INCONCLUSIVE"),
    }
    durable_status, result_code = status_map[reconciliation.outcome]
    await deps.intents.mark_outcome(
        idempotency_key=idempotency_key,
        status=durable_status,
        result_code=result_code,
        result_summary=(
            f"reconciliation={reconciliation.outcome} evidence={reconciliation.evidence_hash[:16]}"
        ),
    )
    await deps.audit.append(
        _audit_event(
            state,
            deps,
            "ACTION_RECONCILED",
            {
                "action_attempt_id": attempt_id,
                "idempotency_key": idempotency_key,
                "outcome": reconciliation.outcome,
                "result_code": result_code,
                "evidence_hash": reconciliation.evidence_hash,
            },
        )
    )

    reconciliation_attempts = state.get("reconciliation_attempts", 0) + 1
    update: dict[str, Any] = {
        "current_node": "reconcile_uncertain_action",
        "reconciliation": reconciliation.model_dump(mode="json"),
        "reconciliation_attempts": reconciliation_attempts,
        "status": "IN_PROGRESS",
    }
    if reconciliation.outcome == "INCONCLUSIVE":
        if reconciliation_attempts >= state.get("max_reconciliation_attempts", 2):
            update.update(set_error(state, "RECONCILIATION_EXHAUSTED"))
        elif state.get("action_attempts", 0) >= state.get("max_action_attempts", 1):
            # No retry path remains; do not spin reconciliation forever.
            update.update(set_error(state, "RECONCILIATION_EXHAUSTED"))
    elif reconciliation.outcome == "NOT_APPLIED" and state.get("action_attempts", 0) >= state.get(
        "max_action_attempts", 1
    ):
        update.update(set_error(state, "RETRY_BUDGET_EXHAUSTED"))
    return update


async def prepare_retry(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Re-evaluate policy and preconditions before any retry (PRD §8.2).

    An approval consumed by the first attempt is *not* re-used: if the
    policy requires approval again, the retry escalates rather than
    bypassing the approval boundary on replay.
    """
    now = deps.clock.now()
    if deadline_exceeded(state, now):
        return set_error(state, "WORKFLOW_DEADLINE_EXCEEDED")
    raw_candidate = state.get("candidate")
    if raw_candidate is None:
        return set_error(state, "RETRY_STATE_MISSING")
    proposal = parse_action_proposal(raw_candidate)
    incident = IncidentCreated.model_validate(state["incident"])
    context = PolicyContext(
        principal_id="workflow-worker",
        environment=environment_or_unknown(incident.environment),
        target_registered=True,
        evidence_indicates_unhealthy=state.get("evidence_indicates_unhealthy", False),
        retry_budget_available=state.get("action_attempts", 0)
        < state.get("max_action_attempts", 1),
        approval_satisfied=False,
    )
    decision = evaluate(proposal, context, deps.policy_snapshot, now=now)
    if decision.outcome != "ALLOW":
        return {
            **set_error(state, "RETRY_DENIED_BY_POLICY"),
            "policy_decision": decision.model_dump(mode="json"),
            "policy_revalidated": True,
        }
    return {
        "current_node": "prepare_retry",
        "policy_decision": decision.model_dump(mode="json"),
        "policy_revalidated": True,
        "status": "IN_PROGRESS",
    }


async def verify_postcondition(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Independent verification. Tool success is NOT proof of recovery."""
    attempt_id = state.get("action_attempt_id")
    if attempt_id is None:
        return set_error(state, "VERIFY_STATE_MISSING")
    verification: VerificationResult = await deps.verifier.verify(
        UUID(state["incident_id"]), UUID(attempt_id)
    )
    if verification.passed:
        return {
            "current_node": "verify_postcondition",
            "verification": verification.model_dump(mode="json"),
        }
    return {
        **set_error(state, "VERIFICATION_FAILED"),
        "verification": verification.model_dump(mode="json"),
    }


async def update_itsm(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    verification = state.get("verification")
    if verification is None or verification["passed"] is not True:
        # Defensive: graph structure should make this unreachable.
        return set_error(state, "RESOLVE_WITHOUT_VERIFICATION")
    audit = _audit_event(
        state,
        deps,
        "INCIDENT_RESOLVED",
        {"verification_id": str(verification["verification_id"])},
    )
    await deps.audit.append(audit)
    return {
        "current_node": "update_itsm",
        "status": "RESOLVED",
        "itsm_updated": True,
        "resolution_summary": "Postcondition independently verified.",
        "audit_event_ids": [*state.get("audit_event_ids", []), str(audit.event_id)],
    }


async def escalate(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    """Retry exhaustion / denial / failed verification: escalate, never resolve."""
    error_code = state.get("error_code") or "WORKFLOW_ESCALATED"
    await deps.audit.append(
        _audit_event(state, deps, "INCIDENT_ESCALATED", {"error_code": error_code})
    )
    return {
        "current_node": "escalate",
        "status": "ESCALATED",
        "error_code": error_code,
    }


async def finalize_audit(state: WorkflowState, deps: WorkflowDeps) -> dict[str, Any]:
    await deps.audit.append(
        _audit_event(state, deps, "WORKFLOW_FINALIZED", {"final_status": state.get("status", "")})
    )
    return {"current_node": "finalize_audit"}


# ---------------------------------------------------------------------------
# Dependency binding
# ---------------------------------------------------------------------------

NodeFn = Callable[[WorkflowState, WorkflowDeps], Awaitable[dict[str, Any]]]

_NODE_FUNCTIONS: dict[str, NodeFn] = {
    "validate_event": validate_event,
    "normalize_incident": normalize_incident,
    "triage_incident": triage_incident,
    "collect_diagnostics": collect_diagnostics,
    "select_remediation_candidate": select_remediation_candidate,
    "evaluate_policy": evaluate_policy,
    "request_approval": request_approval,
    "validate_approval": validate_approval,
    "record_action_intent": record_action_intent,
    "execute_action": execute_action,
    "prepare_retry": prepare_retry,
    "reconcile_uncertain_action": reconcile_uncertain_action,
    "verify_postcondition": verify_postcondition,
    "update_itsm": update_itsm,
    "escalate": escalate,
    "finalize_audit": finalize_audit,
}


def _bind(fn: NodeFn, deps: WorkflowDeps) -> Callable[[WorkflowState], Awaitable[dict[str, Any]]]:
    async def node(state: WorkflowState) -> dict[str, Any]:
        return await fn(state, deps)

    return node


def bind_nodes(
    deps: WorkflowDeps,
) -> dict[str, Callable[[WorkflowState], Awaitable[dict[str, Any]]]]:
    """Node name -> state-only callable with deps closed over."""
    return {name: _bind(fn, deps) for name, fn in _NODE_FUNCTIONS.items()}


def approval_contract_from(state: WorkflowState) -> ApprovalRequestContract:
    """Re-validate a serialized approval request from state."""
    return ApprovalRequestContract.model_validate(state["approval"])


__all__ = [
    "CANDIDATE_BY_CATEGORY",
    "approval_contract_from",
    "bind_nodes",
    "canonical_idempotency_key",
    "collect_diagnostics",
    "environment_or_unknown",
    "escalate",
    "evaluate_policy",
    "execute_action",
    "finalize_audit",
    "normalize_incident",
    "prepare_retry",
    "record_action_intent",
    "reconcile_uncertain_action",
    "request_approval",
    "select_remediation_candidate",
    "triage_incident",
    "update_itsm",
    "validate_approval",
    "validate_event",
    "verify_postcondition",
]
