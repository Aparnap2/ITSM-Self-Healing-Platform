"""Integration: full ingestion -> worker -> resolution loop (real PG, optional NATS)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from itsm_agent.adapters.persistence.audit_port import PsycopgAuditPort
from itsm_agent.adapters.persistence.ingestion_sink import PsycopgIngestionSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.commands import (
    ExecutionLimits,
    ExecutorPort,
    VerifierPort,
    WorkflowDeps,
)
from itsm_agent.application.worker import process_event
from itsm_agent.domain.events import (
    DiagnosticObservation,
    IncidentCreated,
    ToolResult,
    VerificationResult,
)
from itsm_agent.domain.policies import default_policy_snapshot
from itsm_agent.ports.model import TriageOutput
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
        from datetime import UTC, datetime

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
    async def create_request(
        self,
        incident_id: UUID,
        workflow_id: UUID,
        proposal_hash: str,
        action_type: str,
        resource_id: str,
        parameters_hash: str,
        requested_at: datetime,
        expires_at: datetime,
    ) -> Any:
        raise RuntimeError("approval not expected in test env")

    async def get_decision(self, approval_id: UUID) -> None:
        return None


class FakeClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _make_event(service: str = "payments-api", env: str = "test") -> IncidentCreated:
    now = datetime.now(UTC)
    return IncidentCreated(
        schema_version="1.0",
        event_id=uuid4(),
        source_system="mockoon-itsm",
        source_incident_id="INC-1001",
        external_event_id=f"evt-{uuid4().hex}",
        occurred_at=now,
        correlation_id=uuid4(),
        title=f"{service} unhealthy",
        description="Health check failing",
        service_name=service,
        severity="P2",
        environment=env,
    )


@pytest.fixture
async def pg_pool(pg_dsn: str) -> Any:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=5))
    await pool.open()
    yield pool
    await pool.close()


async def test_ingestion_loop_resolves(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=5))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE workflow_state, audit_events, approvals, action_intents, "
                "outbox, event_inbox, incidents CASCADE"
            )

        repos = RepositoryBundle(pool)
        sim = InfrastructureSimulator(seed=42)
        sim.seed_service(
            service_name="payments-api", environment="test", status="DOWN", restart_count=0
        )

        sink = PsycopgIngestionSink(pool)
        event = _make_event()

        # 1. Durable acceptance
        outcome = await sink.accept_incident(event)
        assert outcome.value == "ACCEPTED"

        # 2. Inbox + outbox rows present
        inbox_row = await repos.inbox.get("mockoon-itsm", event.external_event_id)
        assert inbox_row is not None
        assert await repos.outbox.count_pending() == 1

        # 3. Build deps
        deps = WorkflowDeps(
            model=FakeModel(),
            diagnostics=FakeDiagnostics(),
            executor=SimExecutor(sim),
            verifier=SimVerifier(sim, "payments-api", "test"),
            approvals=FakeApprovals(),
            audit=PsycopgAuditPort(repos.audit),
            clock=FakeClock(),
            limits=ExecutionLimits(),
            policy_snapshot=default_policy_snapshot(),
        )

        # 4. Process event (idempotent worker)
        result = await process_event(
            event=event,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            clock_now=datetime.now(UTC),
        )
        assert result.status == "RESOLVED"
        assert result.already_processed is False

        # 5. Incident persisted
        incident = await repos.incidents.find_by_external_event(
            "mockoon-itsm", event.external_event_id
        )
        assert incident is not None
        assert incident.status == "RESOLVED"

        # 6. Workflow state persisted
        wf = await repos.workflow_state.get(result.workflow_id)
        assert wf is not None
        assert wf.status == "SUCCEEDED"
        assert wf.finished_at is not None

        # 7. Duplicate delivery is idempotent
        result2 = await process_event(
            event=event,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            clock_now=datetime.now(UTC),
        )
        assert result2.already_processed is True
        assert result2.status == "RESOLVED"
        # still one incident
        found = await repos.incidents.find_by_external_event(
            "mockoon-itsm", event.external_event_id
        )
        assert found is not None
    finally:
        await pool.close()


async def test_ingestion_duplicate_event(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=5))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE workflow_state, audit_events, approvals, action_intents, "
                "outbox, event_inbox, incidents CASCADE"
            )
        sink = PsycopgIngestionSink(pool)
        event = _make_event()
        first = await sink.accept_incident(event)
        second = await sink.accept_incident(event)
        assert first.value == "ACCEPTED"
        assert second.value == "DUPLICATE"
    finally:
        await pool.close()
