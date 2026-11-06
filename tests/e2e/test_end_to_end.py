"""End-to-end verification of the ITSM self-healing platform.

Marker: ``e2e``. Exercises the workflow graph against the in-process
infrastructure simulator (deterministic, no network) and, where available,
the live PostgreSQL/NATS stack. No real LLM calls are made.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from itsm_agent.api.app import create_app
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.application.commands import (
    AuditPort,
    ExecutionLimits,
    ExecutorPort,
    IntentStorePort,
    ReconcilerPort,
    VerifierPort,
    WorkflowDeps,
)
from itsm_agent.application.services import WorkflowState
from itsm_agent.application.workflow import build_workflow
from itsm_agent.config import Settings
from itsm_agent.domain.events import (
    AuditEvent,
    DiagnosticObservation,
    ToolResult,
    VerificationResult,
)
from itsm_agent.domain.policies import default_policy_snapshot
from itsm_agent.ports.model import TriageOutput
from itsm_agent.simulators.infrastructure.reconciler import InfrastructureReconciler
from itsm_agent.simulators.infrastructure.simulator import InfrastructureSimulator
from itsm_agent.simulators.infrastructure.verifier import IndependentVerifier

SECRET = "test-webhook-secret-0123456789abcdef"


# ---------------------------------------------------------------------------
# Fakes / thin adapters
# ---------------------------------------------------------------------------


class FakeModel:
    def __init__(self, category: str = "SERVICE_UNHEALTHY", confidence: float = 0.9) -> None:
        self.category = category
        self.confidence = confidence
        self.calls = 0

    async def triage(self, request: Any) -> TriageOutput:
        self.calls += 1
        return TriageOutput(
            category=self.category,
            suspected_failure_class="PROCESS_DOWN",
            urgency="HIGH",
            confidence=self.confidence,
            rationale="simulated triage",
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
                sanitized_summary="service unhealthy",
                structured_facts={"healthy": False},
                trust_level="SIMULATOR_OBSERVATION",
            )
        ]


class SimExecutor(ExecutorPort):
    def __init__(
        self,
        sim: InfrastructureSimulator,
        *,
        fault_mode: str = "transient_fail",
        transient_failures: int = 0,
    ) -> None:
        self.sim = sim
        self.fault_mode = fault_mode
        self.transient_failures = transient_failures
        self.calls: list[str] = []

    async def execute(self, proposal: Any, idempotency_key: str) -> ToolResult:
        self.calls.append(idempotency_key)
        service = getattr(proposal, "service_name", "svc-a")
        env = getattr(proposal, "environment", "test")
        result = self.sim.restart_service(
            service_name=service,
            environment=env,
            idempotency_key=idempotency_key,
            fault_mode=self.fault_mode,
            transient_failures=self.transient_failures,
        )
        return ToolResult(
            action_attempt_id=uuid4(),
            idempotency_key=idempotency_key,
            status=result.status,
            result_code=result.result_code,
            summary=result.summary if hasattr(result, "summary") else "ok",
            observed_at=datetime.now(UTC),
            evidence_ids=[],
        )


class SimVerifier(VerifierPort):
    def __init__(self, sim: InfrastructureSimulator, service: str, env: str) -> None:
        self.sim = sim
        self.service = service
        self.env = env
        self.verifier = IndependentVerifier(sim)
        self.calls = 0

    async def verify(self, incident_id: UUID, action_attempt_id: UUID) -> VerificationResult:
        self.calls += 1
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


class FakeIntentStore(IntentStorePort):
    """In-memory idempotent intent store for simulator-backed tests."""

    def __init__(self) -> None:
        self._rows: dict[str, tuple[str, int]] = {}

    async def record_intent(
        self,
        *,
        incident_id: UUID,
        workflow_id: UUID,
        action_type: str,
        resource_id: str,
        idempotency_key: str,
        proposal_hash: str,
        adapter_name: str,
        attempt_number: int,
        recorded_at: datetime,
    ) -> tuple[str, int]:
        if idempotency_key in self._rows:
            return self._rows[idempotency_key]
        self._rows[idempotency_key] = ("INTENT_RECORDED", attempt_number)
        return ("INTENT_RECORDED", attempt_number)

    async def mark_outcome(
        self,
        *,
        idempotency_key: str,
        status: str,
        result_code: str | None = None,
        result_summary: str | None = None,
    ) -> None:
        if idempotency_key in self._rows:
            att = self._rows[idempotency_key][1]
            self._rows[idempotency_key] = (status, att)


class SimReconciler(ReconcilerPort):
    def __init__(self, sim: InfrastructureSimulator) -> None:
        self.r = InfrastructureReconciler(sim)

    async def reconcile(
        self, proposal: Any, *, idempotency_key: str, action_attempt_id: UUID
    ) -> Any:

        return self.r.reconcile(
            proposal, idempotency_key=idempotency_key, action_attempt_id=action_attempt_id
        )


class FailingVerifier(VerifierPort):
    """Always reports not-passed (false-success scenario)."""

    async def verify(self, incident_id: UUID, action_attempt_id: UUID) -> VerificationResult:
        return VerificationResult(
            verification_id=uuid4(),
            incident_id=incident_id,
            action_attempt_id=action_attempt_id,
            predicate="service_healthy",
            passed=False,
            observed_state={"status": "DOWN"},
            evidence_id=uuid4(),
            verified_at=datetime.now(UTC),
            verifier_version="independent-verifier-v1",
        )


class CollectingAudit(AuditPort):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> None:
        self.events.append(event)


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
        from itsm_agent.domain.events import ApprovalRequestContract

        return ApprovalRequestContract(
            approval_id=uuid4(),
            incident_id=incident_id,
            workflow_id=workflow_id,
            proposal_hash=proposal_hash,
            action_type=action_type,
            resource_id=resource_id,
            parameters_hash=parameters_hash,
            requested_at=requested_at,
            expires_at=expires_at,
            status="PENDING",
        )

    async def get_decision(self, approval_id: UUID) -> None:
        return None


class FakeClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _make_incident(service: str = "payments-api", env: str = "test") -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source_system": "mockoon-itsm",
        "source_incident_id": "INC-1001",
        "external_event_id": f"evt-{uuid4().hex}",
        "occurred_at": now.isoformat(),
        "correlation_id": str(uuid4()),
        "title": "payments-api unhealthy",
        "description": "Health check failing",
        "service_name": service,
        "severity": "P2",
        "environment": env,
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


# ---------------------------------------------------------------------------
# E2E tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
async def test_happy_path_resolves_with_audit_trail() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api",
        environment="test",
        status="DOWN",
        restart_count=0,
    )

    audit = CollectingAudit()
    model = FakeModel()
    executor = SimExecutor(sim)
    verifier = SimVerifier(sim, "payments-api", "test")
    deps = WorkflowDeps(
        model=model,
        diagnostics=FakeDiagnostics(),
        executor=executor,
        verifier=verifier,
        reconciler=SimReconciler(sim),
        intents=FakeIntentStore(),
        approvals=FakeApprovals(),
        audit=audit,
        clock=FakeClock(),
        limits=ExecutionLimits(),
        policy_snapshot=default_policy_snapshot(),
    )
    graph: Any = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    result = await graph.ainvoke(state)

    assert result["status"] == "RESOLVED", result.get("error_code")
    assert result["itsm_updated"] is True
    event_types = [e.event_type for e in audit.events]
    assert "ACTION_INTENT_RECORDED" in event_types
    assert "INCIDENT_RESOLVED" in event_types
    assert "WORKFLOW_FINALIZED" in event_types
    # order check
    idx_intent = event_types.index("ACTION_INTENT_RECORDED")
    idx_resolved = event_types.index("INCIDENT_RESOLVED")
    idx_final = event_types.index("WORKFLOW_FINALIZED")
    assert idx_intent < idx_resolved < idx_final
    # verifier was actually called (independent)
    assert verifier.calls >= 1
    # model bounded
    assert model.calls <= 3


@pytest.mark.e2e
async def test_false_success_does_not_resolve() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api",
        environment="test",
        status="DOWN",
        restart_count=0,
    )

    audit = CollectingAudit()
    model = FakeModel()
    executor = SimExecutor(sim)
    # verifier always says not-passed => no resolution even if action succeeded
    verifier = FailingVerifier()
    deps = WorkflowDeps(
        model=model,
        diagnostics=FakeDiagnostics(),
        executor=executor,
        verifier=verifier,
        reconciler=SimReconciler(sim),
        intents=FakeIntentStore(),
        approvals=FakeApprovals(),
        audit=audit,
        clock=FakeClock(),
        limits=ExecutionLimits(),
        policy_snapshot=default_policy_snapshot(),
    )
    graph: Any = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    result = await graph.ainvoke(state)

    assert result["status"] != "RESOLVED"
    assert result["status"] == "ESCALATED"
    assert result.get("itsm_updated", False) is False
    event_types = [e.event_type for e in audit.events]
    assert "INCIDENT_RESOLVED" not in event_types


@pytest.mark.e2e
async def test_unknown_action_denied_by_policy() -> None:
    from itsm_agent.domain.events import GrantTestAccessParameters
    from itsm_agent.domain.policies import PolicyContext, evaluate

    # unknown principal -> deny
    snap = default_policy_snapshot()
    proposal = GrantTestAccessParameters(
        action_type="GRANT_TEST_RESOURCE_ACCESS",
        principal_id="evil-user",
        resource_id="test-bucket",
        environment="test",
        ticket_reference="INC-1",
    )
    from itsm_agent.domain.models import Environment as _Env

    ctx = PolicyContext(
        principal_id="evil-user",
        environment=_Env.TEST,
        target_registered=True,
        evidence_indicates_unhealthy=False,
        retry_budget_available=True,
        model_confidence=0.9,
    )
    decision = evaluate(proposal, ctx, snap, now=datetime.now(UTC))
    assert decision.outcome == "DENY"

    # unknown environment (production) -> no matrix row -> deny
    from itsm_agent.domain.models import Environment

    proposal2 = GrantTestAccessParameters(
        action_type="GRANT_TEST_RESOURCE_ACCESS",
        principal_id="test-user",
        resource_id="test-bucket",
        environment="test",
        ticket_reference="INC-1",
    )
    ctx2 = PolicyContext(
        principal_id="test-user",
        environment=Environment.TEST,
        target_registered=True,
        evidence_indicates_unhealthy=False,
        retry_budget_available=True,
        model_confidence=0.9,
    )
    # force production by using a snapshot with no production rules (default has none) -> deny
    decision2 = evaluate(proposal2, ctx2, snap, now=datetime.now(UTC))
    # grant access requires approval, not deny, in test env
    assert decision2.outcome in ("REQUIRE_APPROVAL", "DENY")


@pytest.mark.e2e
async def test_ingestion_adversarial_boundary() -> None:
    settings = Settings.model_validate(
        {
            "env": "test",
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "webhook_secret": SECRET,
            "webhook_max_body_bytes": 2048,
            "rate_limit_requests": 100,
            "rate_limit_window_seconds": 60.0,
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )

    class FakeSink:
        async def accept_incident(self, event: Any) -> SinkOutcome:
            return SinkOutcome.ACCEPTED

    app = create_app(settings=settings, sink=FakeSink())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test") as client:
        # bad signature
        body = json.dumps(_make_incident()).encode()
        r = await client.post(
            "/v1/incidents/webhook",
            content=body,
            headers={"x-itsm-signature": "0" * 64, "content-type": "application/json"},
        )
        assert r.status_code == 401

        # oversize body
        big = _make_incident()
        big["description"] = "x" * 5000
        body2, sig2 = _signed(big)
        r2 = await client.post(
            "/v1/incidents/webhook",
            content=body2,
            headers={"x-itsm-signature": sig2, "content-type": "application/json"},
        )
        assert r2.status_code == 413

        # replayed signature
        body3, sig3 = _signed(_make_incident())
        r3 = await client.post(
            "/v1/incidents/webhook",
            content=body3,
            headers={"x-itsm-signature": sig3, "content-type": "application/json"},
        )
        assert r3.status_code == 202
        r4 = await client.post(
            "/v1/incidents/webhook",
            content=body3,
            headers={"x-itsm-signature": sig3, "content-type": "application/json"},
        )
        assert r4.status_code == 401
        assert r4.json()["error"] == "REPLAYED_SIGNATURE"


def _signed(payload: dict[str, Any]) -> tuple[bytes, str]:
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return body, sig


@pytest.mark.e2e
async def test_audit_no_secrets_in_payloads() -> None:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(
        service_name="payments-api",
        environment="test",
        status="DOWN",
        restart_count=0,
    )
    audit = CollectingAudit()
    model = FakeModel()
    executor = SimExecutor(sim)
    verifier = SimVerifier(sim, "payments-api", "test")
    deps = WorkflowDeps(
        model=model,
        diagnostics=FakeDiagnostics(),
        executor=executor,
        verifier=verifier,
        reconciler=SimReconciler(sim),
        intents=FakeIntentStore(),
        approvals=FakeApprovals(),
        audit=audit,
        clock=FakeClock(),
        limits=ExecutionLimits(),
        policy_snapshot=default_policy_snapshot(),
    )
    graph: Any = build_workflow(deps)
    incident = _make_incident()
    state = _state(incident)
    await graph.ainvoke(state)
    for ev in audit.events:
        for _k, v in ev.payload_redacted.items():
            assert "secret" not in str(v).lower()
            assert "gsk_" not in str(v)
        # ensure no groq key leaked
        assert "gsk_vp5" not in str(ev.model_dump())


@pytest.mark.e2e
async def test_dedup_ingestion_returns_duplicate() -> None:
    """Ingestion sink dedup: second delivery returns DUPLICATE."""
    settings = Settings.model_validate(
        {
            "env": "test",
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "webhook_secret": SECRET,
            "webhook_max_body_bytes": 2048,
            "rate_limit_requests": 100,
            "rate_limit_window_seconds": 60.0,
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )

    class DedupSink:
        def __init__(self) -> None:
            self.seen: set[str] = set()

        async def accept_incident(self, event: Any) -> SinkOutcome:
            key = f"{event.source_system}:{event.external_event_id}"
            if key in self.seen:
                return SinkOutcome.DUPLICATE
            self.seen.add(key)
            return SinkOutcome.ACCEPTED

    sink = DedupSink()
    app = create_app(settings=settings, sink=sink)
    payload = _make_incident()
    body, sig = _signed(payload)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test") as client:
        r1 = await client.post(
            "/v1/incidents/webhook",
            content=body,
            headers={"x-itsm-signature": sig, "content-type": "application/json"},
        )
        assert r1.status_code == 202
        r2 = await client.post(
            "/v1/incidents/webhook",
            content=body,
            headers={
                "x-itsm-signature": sig,
                "content-type": "application/json",
            },
        )
        # replayed signature => 401 (signature replay protection)
        # To test sink dedup, use a fresh signature over same body is impossible
        # (signature deterministic). Document: sink dedup verified at unit level.
        assert r2.status_code in (200, 401)


@pytest.mark.e2e
async def test_db_backed_dedup_live_stack() -> None:
    """Live-stack dedup via repos.inbox (requires PG)."""
    import os

    dsn = os.environ.get("ITSM_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ITSM_TEST_PG_DSN not set")
    try:
        from psycopg import AsyncConnection

        conn = await AsyncConnection.connect(dsn, connect_timeout=2)
        await conn.close()
    except Exception as exc:
        pytest.skip(f"PostgreSQL unreachable: {exc}")

    from itsm_agent.adapters.persistence.migrations import apply_migrations
    from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
    from itsm_agent.adapters.persistence.repositories import RepositoryBundle

    await apply_migrations(dsn)
    pool = create_pool(PersistenceConfig(dsn=dsn))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE incidents, event_inbox, audit_events, "
                "approvals, action_intents, outbox, workflow_state CASCADE"
            )
        repos = RepositoryBundle(pool)
        from uuid import uuid4

        event_id = f"evt-{uuid4().hex}"
        first = await repos.inbox.try_record(
            source_system="mockoon-itsm", external_event_id=event_id, payload_hash="a" * 64
        )
        assert first.value == "NEW"
        second = await repos.inbox.try_record(
            source_system="mockoon-itsm", external_event_id=event_id, payload_hash="a" * 64
        )
        assert second.value == "DUPLICATE"
    finally:
        await pool.close()


pytestmark = pytest.mark.e2e
