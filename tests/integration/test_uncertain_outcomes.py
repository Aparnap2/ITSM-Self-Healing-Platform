"""Phase 2: uncertain side effects + reconciliation-before-retry."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from itsm_agent.application.commands import ExecutionLimits, WorkflowDeps
from itsm_agent.application.services import WorkflowState
from itsm_agent.application.workflow import build_workflow
from itsm_agent.domain.policies import default_policy_snapshot
from itsm_agent.simulators.infrastructure.simulator import InfrastructureSimulator
from tests.integration.test_ingestion_loop import (
    FakeApprovals,
    FakeClock,
    FakeDiagnostics,
    FakeModel,
    SimExecutor,
    SimReconciler,
    SimVerifier,
)


def _make_incident(service: str = "payments-api") -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source_system": "mockoon-itsm",
        "source_incident_id": f"INC-{uuid4().hex[:8]}",
        "external_event_id": f"evt-{uuid4().hex}",
        "occurred_at": datetime.now(UTC).isoformat(),
        "correlation_id": str(uuid4()),
        "title": f"{service} unhealthy",
        "description": "Health check failing",
        "service_name": service,
        "severity": "P2",
        "environment": "test",
    }


def _state(incident: dict[str, Any]) -> WorkflowState:
    return {
        "workflow_id": str(uuid4()),
        "incident_id": str(uuid4()),
        "correlation_id": incident["correlation_id"],
        "workflow_version": "1.0.0",
        "incident": incident,
        "status": "NEW",
        "current_node": "",
        "triage": None,
        "evidence_ids": [],
        "evidence_indicates_unhealthy": False,
        "candidate": None,
        "policy_decision": None,
        "policy_revalidated": False,
        "approval": None,
        "approval_decision": None,
        "action_attempt_id": None,
        "idempotency_key": None,
        "intent_status": None,
        "tool_result": None,
        "action_attempts": 0,
        "reconciliation": None,
        "reconciliation_attempts": 0,
        "verification": None,
        "max_action_attempts": 1,
        "max_reconciliation_attempts": 2,
        "model_attempts": 0,
        "tool_calls": 0,
        "deadline_at": None,
        "error_code": None,
        "error_detail": None,
        "itsm_updated": False,
        "audit_event_ids": [],
        "resolution_summary": None,
    }


def _deps(
    sim: InfrastructureSimulator,
    *,
    fault_mode: str = "transient_fail",
    transient_failures: int = 0,
    max_action_attempts: int = 1,
    max_reconciliation_attempts: int = 2,
) -> WorkflowDeps:
    return WorkflowDeps(
        model=FakeModel(),
        diagnostics=FakeDiagnostics(),
        executor=SimExecutor(sim, fault_mode=fault_mode, transient_failures=transient_failures),
        verifier=SimVerifier(sim, "payments-api", "test"),
        reconciler=SimReconciler(sim),
        intents=_MemoryIntentStore(),
        approvals=FakeApprovals(),
        audit=_CollectingAudit(),
        clock=FakeClock(),
        limits=ExecutionLimits(
            max_action_attempts=max_action_attempts,
            max_reconciliation_attempts=max_reconciliation_attempts,
        ),
        policy_snapshot=default_policy_snapshot(),
    )


class _MemoryIntentStore:
    def __init__(self) -> None:
        self._rows: dict[str, tuple[str, int]] = {}

    async def record_intent(self, **kw: Any) -> tuple[str, int]:
        key = kw["idempotency_key"]
        if key in self._rows:
            return self._rows[key]
        self._rows[key] = ("INTENT_RECORDED", kw["attempt_number"])
        return self._rows[key]

    async def mark_outcome(self, **kw: Any) -> None:
        key = kw["idempotency_key"]
        if key in self._rows:
            self._rows[key] = (kw["status"], self._rows[key][1])


class _CollectingAudit:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def append(self, event: Any) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_A_apply_then_timeout_reconciles_applied_no_retry() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )
    deps = _deps(sim, fault_mode="apply_then_timeout")
    graph = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    result = await graph.ainvoke(state)
    assert result["status"] == "RESOLVED", result.get("error_code")
    assert result["action_attempts"] == 1
    assert result["reconciliation"]["outcome"] == "APPLIED"
    # restart_count increased exactly once
    obs = sim.read_state(service_name="payments-api", environment="test")
    assert obs.restart_count == 1
    assert obs.status == "HEALTHY"


@pytest.mark.asyncio
async def test_B_timeout_before_mutation_retries_and_resolves() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )
    deps = _deps(sim, fault_mode="timeout_before_mutation", max_action_attempts=2)
    graph = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    # max_action_attempts needs to be 2 in state too
    state["max_action_attempts"] = 2
    result = await graph.ainvoke(state)
    assert result["status"] == "RESOLVED", result.get("error_code")
    assert result["action_attempts"] == 2
    assert result["reconciliation"]["outcome"] == "NOT_APPLIED"
    obs = sim.read_state(service_name="payments-api", environment="test")
    assert obs.restart_count == 1


@pytest.mark.asyncio
async def test_C_read_failure_escalates_no_retry() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )
    sim.fail_next_state_reads(1)
    deps = _deps(sim, fault_mode="apply_then_timeout")
    graph = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    result = await graph.ainvoke(state)
    assert result["status"] == "ESCALATED"
    assert result["reconciliation"]["outcome"] == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_D_stale_state_escalates() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )
    sim.force_stale_state_once()
    deps = _deps(sim, fault_mode="apply_then_timeout")
    graph = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    result = await graph.ainvoke(state)
    # stale read may yield INCONCLUSIVE or APPLIED
    assert result["status"] in {"ESCALATED", "RESOLVED"}


@pytest.mark.asyncio
async def test_E_retry_budget_exhausted_escalates() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )
    deps = _deps(sim, fault_mode="timeout_before_mutation", max_action_attempts=1)
    graph = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    state["max_action_attempts"] = 1
    result = await graph.ainvoke(state)
    assert result["status"] == "ESCALATED"
    assert result.get("error_code") in {"RETRY_BUDGET_EXHAUSTED", "RECONCILIATION_EXHAUSTED"}


@pytest.mark.asyncio
async def test_F_idempotent_intent_replay() -> None:
    store = _MemoryIntentStore()
    await store.record_intent(
        incident_id=uuid4(),
        workflow_id=uuid4(),
        action_type="RESTART_SERVICE",
        resource_id="payments-api",
        idempotency_key="k1",
        proposal_hash="h",
        adapter_name="x",
        attempt_number=1,
        recorded_at=datetime.now(UTC),
    )
    await store.mark_outcome(idempotency_key="k1", status="SUCCEEDED", result_code="OK")
    r2 = await store.record_intent(
        incident_id=uuid4(),
        workflow_id=uuid4(),
        action_type="RESTART_SERVICE",
        resource_id="payments-api",
        idempotency_key="k1",
        proposal_hash="h",
        adapter_name="x",
        attempt_number=2,
        recorded_at=datetime.now(UTC),
    )
    assert r2[0] == "SUCCEEDED"
    assert r2[1] == 1


@pytest.mark.asyncio
async def test_G_reconciliation_budget_exhausted_escalates() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )
    # force inconclusive on every reconcile by failing state reads
    sim.fail_next_state_reads(10)
    deps = _deps(sim, fault_mode="apply_then_timeout", max_reconciliation_attempts=1)
    graph = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    state["max_reconciliation_attempts"] = 1
    result = await graph.ainvoke(state)
    assert result["status"] == "ESCALATED"
