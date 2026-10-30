"""Integration: long-running worker process consumes a published event."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from itsm_agent.adapters.messaging.nats_bus import JetStreamPublisher, MessagingConfig
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.ingestion_sink import PsycopgIngestionSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.adapters.persistence.workflow_intents import WorkflowIntentStore
from itsm_agent.application.commands import ExecutionLimits, WorkflowDeps
from itsm_agent.domain.events import IncidentCreated
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

pytestmark = pytest.mark.integration


async def _reset(pg_dsn: str, nats_url: str) -> None:
    import contextlib

    import nats

    pool = create_pool(PersistenceConfig(dsn=pg_dsn))
    await pool.open()
    async with pool.connection() as conn:
        await conn.execute(
            "TRUNCATE workflow_state, audit_events, approvals, action_intents, "
            "outbox, event_inbox, incidents CASCADE"
        )
    await pool.close()

    nc = await nats.connect(servers=[nats_url], connect_timeout=2.0)
    try:
        js = nc.jetstream()
        for name in ("ITSM_EVENTS", "ITSM_DLQ"):
            with contextlib.suppress(Exception):
                await js.delete_stream(name)
    finally:
        await nc.drain()


@pytest.mark.asyncio
async def test_worker_process_resolves_published_event(pg_dsn: str, nats_url: str) -> None:
    await _reset(pg_dsn, nats_url)

    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path("src").resolve())
    env["ITSM_POSTGRES_DSN"] = pg_dsn
    env["ITSM_NATS_URL"] = nats_url
    env["ITSM_SIMULATOR_SEED"] = "42"
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "-m", "itsm_agent.workers.consumer"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        # wait for startup
        await asyncio.sleep(5)

        # publish an event
        pool = create_pool(PersistenceConfig(dsn=pg_dsn))
        await pool.open()
        sink = PsycopgIngestionSink(pool)
        event = IncidentCreated(
            schema_version="1.0",
            event_id=uuid4(),
            source_system="mockoon-itsm",
            source_incident_id="INC-1001",
            external_event_id=f"evt-{uuid4().hex}",
            occurred_at=datetime.now(UTC),
            correlation_id=uuid4(),
            title="payments-api unhealthy",
            description="Health check failing",
            service_name="payments-api",
            severity="P2",
            environment="test",
        )
        assert (await sink.accept_incident(event)).value == "ACCEPTED"
        repos = RepositoryBundle(pool)
        mc = MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
        pub = JetStreamPublisher(mc)
        await pub.ensure_stream()
        relay = OutboxRelay(repos.outbox, pub, backoff_seconds=0.0, max_attempts=10)
        await relay._publisher.ensure_stream()
        assert await relay.relay_once() == 1
        await pub.close()

        # poll for terminal state
        eid = event.external_event_id
        terminal = None
        for _ in range(40):
            await asyncio.sleep(0.5)
            inc = await repos.incidents.find_by_external_event("mockoon-itsm", eid)
            if inc is not None and inc.status in ("RESOLVED", "ESCALATED"):
                terminal = inc.status
                break
        await pool.close()

        assert terminal == "RESOLVED", f"terminal={terminal}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.asyncio
async def test_worker_exits_nonzero_on_bad_nats_url(pg_dsn: str) -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path("src").resolve())
    env["ITSM_POSTGRES_DSN"] = pg_dsn
    env["ITSM_NATS_URL"] = "nats://localhost:1"  # unreachable
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-m", "itsm_agent.workers.consumer"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        rc = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = -1
    assert rc != 0, f"expected nonzero exit, got {rc}"


@pytest.mark.asyncio
async def test_crash_after_commit_is_idempotent(pg_dsn: str) -> None:
    """Simulate crash after DB commit: reprocessing must not duplicate."""
    pool = create_pool(PersistenceConfig(dsn=pg_dsn))
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
            reconciler=SimReconciler(sim),
            intents=WorkflowIntentStore(repos.action_intents),
            approvals=FakeApprovals(),
            audit=PsycopgAuditPort(repos.audit),
            clock=FakeClock(),
            limits=ExecutionLimits(),
            policy_snapshot=default_policy_snapshot(),
        )

        from itsm_agent.application.worker import process_event
        from tests.integration.test_ingestion_loop import _make_event as make_event

        ev = make_event()
        await PsycopgIngestionSink(pool).accept_incident(ev)

        # First processing (commits)
        r1 = await process_event(
            event=ev,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            terminal_state=repos.terminal_state,
            clock_now=datetime.now(UTC),
        )
        assert r1.already_processed is False

        # "Crash" then redelivery: reprocessing must be idempotent
        r2 = await process_event(
            event=ev,
            deps=deps,
            incidents=repos.incidents,
            workflow_states=repos.workflow_state,
            terminal_state=repos.terminal_state,
            clock_now=datetime.now(UTC),
        )
        assert r2.already_processed is True
        assert r2.status == r1.status
    finally:
        await pool.close()
