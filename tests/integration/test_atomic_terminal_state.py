"""Integration: atomic terminal state (incident + workflow) and recovery.

Covers the Phase 1 correctness slice:

* A — the workflow-state write fails after the incident write: both roll back.
* B — the incident write fails first: nothing is committed.
* C — commit succeeds, the process dies before ACK: redelivery is a duplicate.
* D — two concurrent attempts for the same event: one incident, no overwrite.
* E — audit persistence fails: no terminal state is ever committed.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from itsm_agent.adapters.persistence.audit_port import PsycopgAuditPort
from itsm_agent.adapters.persistence.workflow_intents import WorkflowIntentStore
from itsm_agent.application.commands import (
    ExecutionLimits,
    ExecutorPort,
    VerifierPort,
    WorkflowDeps,
)
from itsm_agent.application.worker import consume_one, process_event
from itsm_agent.domain.events import (
    DiagnosticObservation,
    IncidentCreated,
    ToolResult,
    VerificationResult,
)
from itsm_agent.domain.models import Incident, IncidentStatus, WorkflowRun, WorkflowStatus
from itsm_agent.domain.policies import default_policy_snapshot
from itsm_agent.ports.model import TriageOutput
from itsm_agent.ports.repositories import TerminalStateConflictError
from itsm_agent.simulators.infrastructure.simulator import InfrastructureSimulator
from itsm_agent.simulators.infrastructure.verifier import IndependentVerifier

pytestmark = pytest.mark.integration


class FakeModel:
    async def triage(self, request: Any) -> TriageOutput:
        return TriageOutput(
            category="SERVICE_UNHEALTHY",
            suspected_failure_class="PROCESS_DOWN",
            urgency="HIGH",
            confidence=0.9,
            rationale="sim",
        )


class FakeDiagnostics:
    async def collect(self, incident: Any, max_calls: int) -> list[DiagnosticObservation]:
        return [
            DiagnosticObservation(
                evidence_id=uuid4(),
                source="sim",
                kind="HEALTH_CHECK",
                observed_at=datetime.now(UTC),
                content_hash="0" * 64,
                sanitized_summary="unhealthy",
                structured_facts={"healthy": False},
                trust_level="SIMULATOR_OBSERVATION",
            )
        ]


class SimExecutor(ExecutorPort):
    def __init__(self, sim: InfrastructureSimulator) -> None:
        self.sim = sim

    async def execute(self, proposal: Any, idempotency_key: str) -> ToolResult:
        service = getattr(proposal, "service_name", "payments-api")
        env = getattr(proposal, "environment", "test")
        result = self.sim.restart_service(
            service_name=service, environment=env, idempotency_key=idempotency_key
        )
        return ToolResult(
            action_attempt_id=uuid4(),
            idempotency_key=idempotency_key,
            status=result.status,
            result_code=result.result_code,
            summary="ok",
            observed_at=datetime.now(UTC),
            evidence_ids=[],
        )


class SimVerifier(VerifierPort):
    def __init__(self, sim: InfrastructureSimulator, service: str, env: str) -> None:
        self.sim = sim
        self.service = service
        self.env = env
        self.verifier = IndependentVerifier(sim)

    async def verify(self, incident_id: UUID, action_attempt_id: UUID) -> VerificationResult:
        obs = self.verifier.verify(
            service_name=self.service, environment=self.env, predicate="service_healthy"
        )
        return VerificationResult(
            verification_id=uuid4(),
            incident_id=incident_id,
            action_attempt_id=action_attempt_id,
            predicate="service_healthy",
            passed=obs.passed,
            observed_state=obs.observed_state,
            evidence_id=uuid4(),
            verified_at=datetime.now(UTC),
            verifier_version=obs.verifier_version,
        )


class FakeApprovals:
    async def create_request(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("approval not expected in test env")

    async def get_decision(self, approval_id: UUID) -> None:
        return None


class SimReconciler:
    def __init__(self, sim: InfrastructureSimulator) -> None:
        from itsm_agent.simulators.infrastructure.reconciler import InfrastructureReconciler

        self.r = InfrastructureReconciler(sim)

    async def reconcile(
        self, proposal: Any, *, idempotency_key: str, action_attempt_id: Any
    ) -> Any:
        return self.r.reconcile(
            proposal, idempotency_key=idempotency_key, action_attempt_id=action_attempt_id
        )


class FakeClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FailingAudit:
    async def append(self, event: Any) -> None:
        raise RuntimeError("simulated audit persistence failure")


def _make_event() -> IncidentCreated:
    now = datetime.now(UTC)
    return IncidentCreated(
        schema_version="1.0",
        event_id=uuid4(),
        source_system="mockoon-itsm",
        source_incident_id=f"INC-{uuid4().hex[:8]}",
        external_event_id=f"evt-{uuid4().hex}",
        occurred_at=now,
        correlation_id=uuid4(),
        title="payments-api unhealthy",
        description="Health check failing",
        service_name="payments-api",
        severity="P2",
        environment="test",
    )


def _make_deps(repos: Any, sim: InfrastructureSimulator, *, audit: Any = None) -> WorkflowDeps:
    return WorkflowDeps(
        model=FakeModel(),
        diagnostics=FakeDiagnostics(),
        executor=SimExecutor(sim),
        verifier=SimVerifier(sim, "payments-api", "test"),
        reconciler=SimReconciler(sim),
        intents=WorkflowIntentStore(repos.action_intents),
        approvals=FakeApprovals(),
        audit=audit if audit is not None else PsycopgAuditPort(repos.audit),
        clock=FakeClock(),
        limits=ExecutionLimits(),
        policy_snapshot=default_policy_snapshot(),
    )


def _seed_service(sim: InfrastructureSimulator) -> None:
    sim.seed_service(
        service_name="payments-api", environment="test", status="DOWN", restart_count=0
    )


async def _seed_rows(repos: Any) -> tuple[UUID, UUID]:
    now = datetime.now(UTC)
    incident_id = uuid4()
    workflow_id = uuid4()
    await repos.incidents.create(
        Incident(
            id=incident_id,
            source_system="mockoon-itsm",
            source_incident_id=f"INC-{uuid4().hex[:8]}",
            external_event_id=f"evt-{uuid4().hex}",
            title="seed",
            description="seed",
            service_name="payments-api",
            severity="P2",
            status=IncidentStatus.NEW,
            created_at=now,
            updated_at=now,
            correlation_id=uuid4(),
            current_workflow_id=workflow_id,
        )
    )
    await repos.workflow_state.create(
        WorkflowRun(
            id=workflow_id,
            incident_id=incident_id,
            workflow_version="1.0.0",
            status=WorkflowStatus.PENDING,
            current_node="start",
            started_at=now,
            updated_at=now,
            correlation_id=uuid4(),
        )
    )
    return incident_id, workflow_id


async def test_workflow_update_failure_rolls_back_incident(repos: Any) -> None:
    """A: incident write succeeds, workflow write fails → both roll back."""
    incident_id, workflow_id = await _seed_rows(repos)

    with pytest.raises(errors.CheckViolation):
        await repos.terminal_state.finalize(
            workflow_id=workflow_id,
            incident_id=incident_id,
            workflow_status="NOT_A_STATUS",
            current_node="finalize_audit",
            attempt_count=1,
            last_error_code=None,
            incident_status="RESOLVED",
        )

    incident = await repos.incidents.get(incident_id)
    workflow = await repos.workflow_state.get(workflow_id)
    assert incident is not None and incident.status == "NEW"
    assert workflow is not None and workflow.status == "PENDING"
    assert workflow.finished_at is None


async def test_incident_update_failure_commits_nothing(repos: Any) -> None:
    """B: incident write fails first → workflow is never touched."""
    incident_id, workflow_id = await _seed_rows(repos)

    with pytest.raises(errors.CheckViolation):
        await repos.terminal_state.finalize(
            workflow_id=workflow_id,
            incident_id=incident_id,
            workflow_status="SUCCEEDED",
            current_node="finalize_audit",
            attempt_count=1,
            last_error_code=None,
            incident_status="NOT_A_STATUS",
        )

    incident = await repos.incidents.get(incident_id)
    workflow = await repos.workflow_state.get(workflow_id)
    assert incident is not None and incident.status == "NEW"
    assert workflow is not None and workflow.status == "PENDING"
    assert workflow.finished_at is None


async def test_finalize_rejects_already_finished_workflow(repos: Any) -> None:
    """Terminal-state protection: a committed transition cannot be overwritten."""
    incident_id, workflow_id = await _seed_rows(repos)
    await repos.terminal_state.finalize(
        workflow_id=workflow_id,
        incident_id=incident_id,
        workflow_status="SUCCEEDED",
        current_node="finalize_audit",
        attempt_count=1,
        last_error_code=None,
        incident_status="RESOLVED",
    )

    with pytest.raises(TerminalStateConflictError):
        await repos.terminal_state.finalize(
            workflow_id=workflow_id,
            incident_id=incident_id,
            workflow_status="FAILED",
            current_node="finalize_audit",
            attempt_count=1,
            last_error_code=None,
            incident_status="ESCALATED",
        )

    incident = await repos.incidents.get(incident_id)
    workflow = await repos.workflow_state.get(workflow_id)
    assert incident is not None and incident.status == "RESOLVED"
    assert workflow is not None and workflow.status == "SUCCEEDED"


class _Message:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.subject = "itsm.events.incident.created"
        self.delivery_attempt = 1


class _FakeConsumer:
    """Deterministic stand-in; optionally crashes on the first ACK."""

    def __init__(self, message: _Message, *, crash_on_ack: bool) -> None:
        self._message = message
        self._crash_on_ack = crash_on_ack
        self._delivered = False
        self.acked = False
        self.naks = 0

    async def fetch(self, *, timeout_seconds: float, batch: int) -> list[_Message]:
        if self._delivered:
            return []
        self._delivered = True
        return [self._message]

    async def ack(self, message: _Message) -> None:
        if self._crash_on_ack:
            raise RuntimeError("simulated process crash before ACK")
        self.acked = True

    async def nak(self, message: _Message, *, delay_seconds: float = 0.0) -> None:
        self.naks += 1

    async def dead_letter(self, message: _Message, *, error: str = "") -> None:
        raise AssertionError(f"unexpected dead-letter: {error}")


async def test_crash_after_commit_before_ack_is_idempotent(repos: Any) -> None:
    """C: state commits, ACK crashes, redelivery is a duplicate — no re-run."""
    sim = InfrastructureSimulator(seed=42)
    _seed_service(sim)
    deps = _make_deps(repos, sim)
    event = _make_event()
    payload = json.dumps({"payload": event.model_dump(mode="json")}).encode()

    first = _FakeConsumer(_Message(payload), crash_on_ack=True)
    with pytest.raises(RuntimeError, match="crash before ACK"):
        await consume_one(
            consumer=first,  # type: ignore[arg-type]
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            terminal_state=repos.terminal_state,
            clock_now=lambda: datetime.now(UTC),
        )

    incident = await repos.incidents.find_by_external_event("mockoon-itsm", event.external_event_id)
    assert incident is not None and incident.status == "RESOLVED"

    second = _FakeConsumer(_Message(payload), crash_on_ack=False)
    outcome = await consume_one(
        consumer=second,  # type: ignore[arg-type]
        deps=deps,
        incidents=repos.incidents,
        workflow_states=repos.workflow_state,
        terminal_state=repos.terminal_state,
        clock_now=lambda: datetime.now(UTC),
    )
    assert outcome == "duplicate"
    assert second.acked is True

    incidents = await repos.incidents.find_by_external_event(
        "mockoon-itsm", event.external_event_id
    )
    assert incidents is not None and incidents.status == "RESOLVED"
    assert incidents.current_workflow_id is not None
    workflow = await repos.workflow_state.get(incidents.current_workflow_id)
    assert workflow is not None and workflow.status == "SUCCEEDED"


async def test_concurrent_duplicate_processing_creates_one_incident(repos: Any) -> None:
    """D: overlapping attempts → one logical incident, consistent terminal state."""
    sim = InfrastructureSimulator(seed=42)
    _seed_service(sim)
    deps = _make_deps(repos, sim)
    event = _make_event()

    results = await asyncio.gather(
        process_event(
            event=event,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            terminal_state=repos.terminal_state,
            clock_now=datetime.now(UTC),
        ),
        process_event(
            event=event,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            terminal_state=repos.terminal_state,
            clock_now=datetime.now(UTC),
        ),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, BaseException)]
    assert successes, "at least one attempt must succeed"

    rows = await _count_incidents(repos, event.external_event_id)
    assert rows == 1

    incident = await repos.incidents.find_by_external_event("mockoon-itsm", event.external_event_id)
    assert incident is not None and incident.status == "RESOLVED"
    assert incident.current_workflow_id is not None
    workflow = await repos.workflow_state.get(incident.current_workflow_id)
    assert workflow is not None and workflow.status == "SUCCEEDED"

    replay = await process_event(
        event=event,
        deps=deps,
        incidents=repos.incidents,
        workflow_states=repos.workflow_state,
        terminal_state=repos.terminal_state,
        clock_now=datetime.now(UTC),
    )
    assert replay.already_processed is True


async def _count_incidents(repos: Any, external_event_id: str) -> int:
    async with repos.incidents._pool.connection() as conn, conn.cursor() as cur:  # noqa: SLF001
        await cur.execute(
            "SELECT count(*) FROM incidents WHERE external_event_id = %s",
            (external_event_id,),
        )
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def test_audit_failure_leaves_no_terminal_state(repos: Any) -> None:
    """E: audit persistence is a precondition; failure leaves a non-terminal record."""
    sim = InfrastructureSimulator(seed=42)
    _seed_service(sim)
    deps = _make_deps(repos, sim, audit=FailingAudit())
    event = _make_event()

    with pytest.raises(RuntimeError, match="audit persistence"):
        await process_event(
            event=event,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            terminal_state=repos.terminal_state,
            clock_now=datetime.now(UTC),
        )

    incident = await repos.incidents.find_by_external_event("mockoon-itsm", event.external_event_id)
    assert incident is not None and incident.status == "NEW"
    assert incident.current_workflow_id is not None
    workflow = await repos.workflow_state.get(incident.current_workflow_id)
    assert workflow is not None and workflow.status == "PENDING"
    assert workflow.finished_at is None
