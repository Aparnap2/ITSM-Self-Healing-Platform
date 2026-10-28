"""Integration: real NATS JetStream -> worker consumer path."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from itsm_agent.adapters.messaging.nats_bus import (
    JetStreamConsumer,
    JetStreamPublisher,
    MessagingConfig,
)
from itsm_agent.adapters.persistence.ingestion_sink import PsycopgIngestionSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.commands import (
    ExecutionLimits,
    WorkflowDeps,
)
from itsm_agent.application.worker import consume_one, process_event
from itsm_agent.domain.events import IncidentCreated
from itsm_agent.domain.policies import default_policy_snapshot
from itsm_agent.simulators.infrastructure.simulator import InfrastructureSimulator
from tests.integration.test_ingestion_loop import (
    FakeClock,
    FakeDiagnostics,
    FakeModel,
    SimExecutor,
    SimVerifier,
)

pytestmark = pytest.mark.integration


async def _reset_streams(nats_url: str) -> None:
    import nats

    nc = await nats.connect(servers=[nats_url], connect_timeout=2.0)
    try:
        js = nc.jetstream()
        for name in ("ITSM_EVENTS", "ITSM_DLQ"):
            import contextlib

            with contextlib.suppress(Exception):
                await js.delete_stream(name)
    finally:
        await nc.drain()


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
async def pool_and_repos(pg_dsn: str) -> Any:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=5))
    await pool.open()
    async with pool.connection() as conn:
        await conn.execute(
            "TRUNCATE workflow_state, audit_events, approvals, action_intents, "
            "outbox, event_inbox, incidents CASCADE"
        )
    yield pool, RepositoryBundle(pool)
    await pool.close()


async def test_nats_consumer_processes_published_event(pg_dsn: str, nats_url: str) -> None:
    await _reset_streams(nats_url)
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

        from itsm_agent.adapters.persistence.audit_port import PsycopgAuditPort

        deps = WorkflowDeps(
            model=FakeModel(),
            diagnostics=FakeDiagnostics(),
            executor=SimExecutor(sim),
            verifier=SimVerifier(sim, "payments-api", "test"),
            approvals=__import__(
                "tests.integration.test_ingestion_loop", fromlist=["FakeApprovals"]
            ).FakeApprovals(),
            audit=PsycopgAuditPort(repos.audit),
            clock=FakeClock(),
            limits=ExecutionLimits(),
            policy_snapshot=default_policy_snapshot(),
        )

        sink = PsycopgIngestionSink(pool)
        event = _make_event()
        assert (await sink.accept_incident(event)).value == "ACCEPTED"

        # Publish via outbox relay
        from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay

        mc = MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
        pub = JetStreamPublisher(mc)
        await pub.ensure_stream()
        relay = OutboxRelay(repos.outbox, pub, backoff_seconds=0.0, max_attempts=10)
        await relay._publisher.ensure_stream()
        published = await relay.relay_once()
        assert published == 1

        # Consume
        cons = JetStreamConsumer(mc)
        await cons.ensure_consumer()
        outcome = await consume_one(
            consumer=cons,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            clock_now=lambda: datetime.now(UTC),
            max_deliver=3,
            timeout_seconds=2.0,
        )
        assert outcome == "processed"

        incident = await repos.incidents.find_by_external_event(
            "mockoon-itsm", event.external_event_id
        )
        assert incident is not None
        assert incident.status == "RESOLVED"

        found = await repos.incidents.find_by_external_event(
            "mockoon-itsm", event.external_event_id
        )
        assert found is not None
        assert found.current_workflow_id is not None
        wf = await repos.workflow_state.get(found.current_workflow_id)
        assert wf is not None
        assert wf.status == "SUCCEEDED"

        await cons.close()
        await pub.close()
    finally:
        await pool.close()


async def test_nats_consumer_duplicate_delivery_harmless(pg_dsn: str, nats_url: str) -> None:
    await _reset_streams(nats_url)
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

        from itsm_agent.adapters.persistence.audit_port import PsycopgAuditPort

        deps = WorkflowDeps(
            model=FakeModel(),
            diagnostics=FakeDiagnostics(),
            executor=SimExecutor(sim),
            verifier=SimVerifier(sim, "payments-api", "test"),
            approvals=__import__(
                "tests.integration.test_ingestion_loop", fromlist=["FakeApprovals"]
            ).FakeApprovals(),
            audit=PsycopgAuditPort(repos.audit),
            clock=FakeClock(),
            limits=ExecutionLimits(),
            policy_snapshot=default_policy_snapshot(),
        )

        sink = PsycopgIngestionSink(pool)
        event = _make_event()
        await sink.accept_incident(event)

        from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay

        mc = MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
        pub = JetStreamPublisher(mc)
        await pub.ensure_stream()
        relay = OutboxRelay(repos.outbox, pub, backoff_seconds=0.0, max_attempts=10)
        await relay._publisher.ensure_stream()
        await relay.relay_once()

        cons = JetStreamConsumer(mc)
        await cons.ensure_consumer()

        # First delivery
        o1 = await consume_one(
            consumer=cons,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            clock_now=lambda: datetime.now(UTC),
            max_deliver=3,
            timeout_seconds=2.0,
        )
        assert o1 == "processed"

        # Simulate duplicate delivery: publish a second message with the same event
        await sink.accept_incident(event)  # returns DUPLICATE, but outbox already has first
        # Directly verify idempotency through process_event (consumer path)
        result2 = await process_event(
            event=event,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            clock_now=datetime.now(UTC),
        )
        assert result2.already_processed is True

        await cons.close()
        await pub.close()
    finally:
        await pool.close()
