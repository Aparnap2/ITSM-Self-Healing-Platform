"""Explicit LangGraph workflow assembly (PRD §3.2).

Graph topology (safety-critical edges only):

    START -> route_entry
      -> validate_event -> normalize_incident -> triage_incident
         -> collect_diagnostics -> select_remediation_candidate
         -> evaluate_policy --(route_after_policy)-->
              ALLOW            -> record_action_intent -> execute_action
              REQUIRE_APPROVAL -> request_approval -> END (persist & resume)
              DENY / missing   -> escalate
      resumed: validate_approval --(revalidated ALLOW)--> record_action_intent
               else -> escalate
    execute_action --(route_after_execute)-->
              SUCCEEDED        -> verify_postcondition
              OUTCOME_UNKNOWN  -> reconcile_uncertain_action
              FAILED / missing -> escalate
    reconcile_uncertain_action -> verify_postcondition | escalate
    verify_postcondition --(route_after_verify)--> update_itsm | escalate
    update_itsm / escalate -> finalize_audit -> END

Invariants enforced structurally:
- ``execute_action`` is reachable only through ``record_action_intent``,
  which requires a durable ALLOW decision.
- An approval-pending run ends at ``request_approval``; execution cannot
  proceed until a resumed run passes ``validate_approval``.
- ``update_itsm`` (resolution) is reachable only from
  ``verify_postcondition`` with ``VerificationResult.passed is True``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langgraph.graph import START, StateGraph

from itsm_agent.application.commands import WorkflowDeps
from itsm_agent.application.nodes import bind_nodes
from itsm_agent.application.services import (
    WORKFLOW_VERSION,
    WorkflowState,
    route_after_execute,
    route_after_policy,
    route_after_reconcile,
    route_after_request_approval,
    route_after_validate_approval,
    route_after_verify,
    route_entry,
    route_terminal,
)


def build_workflow(deps: WorkflowDeps) -> Any:
    """Compile the remediation graph with injected dependencies."""
    nodes = bind_nodes(deps)
    builder = StateGraph(WorkflowState)

    for name, fn in nodes.items():
        builder.add_node(name, fn)  # type: ignore[call-overload]

    builder.add_conditional_edges(START, route_entry, ["validate_event", "validate_approval"])

    builder.add_edge("validate_event", "normalize_incident")
    builder.add_edge("normalize_incident", "triage_incident")
    builder.add_edge("triage_incident", "collect_diagnostics")
    builder.add_edge("collect_diagnostics", "select_remediation_candidate")
    builder.add_edge("select_remediation_candidate", "evaluate_policy")

    builder.add_conditional_edges(
        "evaluate_policy",
        route_after_policy,
        ["record_action_intent", "request_approval", "escalate"],
    )
    builder.add_conditional_edges(
        "request_approval",
        route_after_request_approval,
        ["__end__", "escalate"],
    )
    builder.add_conditional_edges(
        "validate_approval",
        route_after_validate_approval,
        ["record_action_intent", "escalate"],
    )

    builder.add_edge("record_action_intent", "execute_action")
    builder.add_conditional_edges(
        "execute_action",
        route_after_execute,
        ["verify_postcondition", "reconcile_uncertain_action", "escalate"],
    )
    builder.add_conditional_edges(
        "reconcile_uncertain_action",
        route_after_reconcile,
        ["verify_postcondition", "escalate"],
    )
    builder.add_conditional_edges(
        "verify_postcondition",
        route_after_verify,
        ["update_itsm", "escalate"],
    )

    builder.add_edge("update_itsm", "finalize_audit")
    builder.add_edge("escalate", "finalize_audit")
    builder.add_conditional_edges("finalize_audit", route_terminal, ["__end__"])

    return builder.compile()


def graph_node_names(deps: WorkflowDeps) -> set[str]:
    return set(bind_nodes(deps))


def route_table() -> dict[str, Callable[[WorkflowState], str]]:
    """Expose route functions for structural invariant tests."""
    return {
        "route_entry": route_entry,
        "route_after_policy": route_after_policy,
        "route_after_request_approval": route_after_request_approval,
        "route_after_validate_approval": route_after_validate_approval,
        "route_after_execute": route_after_execute,
        "route_after_reconcile": route_after_reconcile,
        "route_after_verify": route_after_verify,
        "route_terminal": route_terminal,
    }


__all__ = [
    "WORKFLOW_VERSION",
    "build_workflow",
    "graph_node_names",
    "route_table",
]
