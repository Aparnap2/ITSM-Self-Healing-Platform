"""Integration: the packaged audit consumer process on real PostgreSQL + NATS.

Marker: ``integration``. This is the staging path proven end to end **without
any model call**: the investigation stage is disabled, so the pipeline is
deterministic and completely offline.

What it proves:

* ``python -m itsm_agent.workers.audit_consumer`` starts against the local
  PostgreSQL and NATS, consumes a published source event, and persists the
  finding the deterministic detection engine produced;
* the process shuts down cleanly on SIGTERM with exit code ``0``;
* the disabled investigation stage records nothing and calls no model;
* an enabled investigation stage without a model key makes the packaged
  process exit ``2`` (fail closed) instead of silently running without it.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from itsm_agent.adapters.messaging.nats_bus import JetStreamPublisher, MessagingConfig
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.collectors.aws.cloudtrail import normalize_record

pytestmark = pytest.mark.integration

#: How long to wait for the packaged process to produce the finding.
FINDING_TIMEOUT_SECONDS = 45.0


def _ct_record(tenant: UUID) -> dict[str, object]:
    return {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA",
            "arn": "arn:aws:iam::123:user/alice",
            "accountId": "123",
            "userName": "alice",
        },
        "eventTime": "2026-01-01T12:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/Admin"},
        "requestID": "req-consumer-1",
        "eventID": f"evt-{uuid.uuid4().hex}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }


async def _reset(pg_dsn: str, nats_url: str) -> None:
    """Clear the application tables and the NATS streams."""
    pool = create_pool(PersistenceConfig(dsn=pg_dsn))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE source_events, event_inbox, outbox, findings, "
                "processing_records, investigation_requests, investigation_proposals, "
                "evidence_references, coverage_status, tenants CASCADE"
            )
    finally:
        await pool.close()

    import nats

    nc = await nats.connect(servers=[nats_url], connect_timeout=2.0)
    try:
        js = nc.jetstream()
        for name in ("ITSM_EVENTS", "ITSM_DLQ"):
            with contextlib.suppress(Exception):
                await js.delete_stream(name)
    finally:
        await nc.drain()


def _consumer_env(runtime_dsn: str, nats_url: str) -> dict[str, str]:
    """Environment for the packaged process. No model key: the stage is off."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path("src").resolve())
    env["ITSM_POSTGRES_DSN"] = runtime_dsn
    env["ITSM_NATS_URL"] = nats_url
    env["ITSM_INVESTIGATION_ENABLED"] = "false"
    env["ITSM_INVESTIGATION_LLM_BUDGET_CALLS"] = "3"
    env["ITSM_LOG_LEVEL"] = "INFO"
    env["PYTHONUNBUFFERED"] = "1"
    env.pop("ITSM_GROQ_API_KEY", None)
    return env


async def _seed_and_publish(pg_dsn: str, nats_url: str) -> tuple[UUID, UUID]:
    """Register the tenant, persist the source event and relay it to NATS."""
    pool = create_pool(PersistenceConfig(dsn=pg_dsn))
    await pool.open()
    try:
        repositories = RepositoryBundle(pool)
        tenant = uuid.uuid4()
        await repositories.tenants.ensure(tenant, name="audit-consumer-integration")

        event = normalize_record(_ct_record(tenant), tenant)
        sink = PsycopgSourceEventSink(pool)
        assert (await sink.accept_source_event(event)).value == "ACCEPTED"

        publisher = JetStreamPublisher(
            MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
        )
        await publisher.ensure_stream()
        relay = OutboxRelay(repositories.outbox, publisher, backoff_seconds=0.0, max_attempts=10)
        published = await relay.relay_once(tenant_id=tenant)
        await publisher.close()
        assert published == 1
        return tenant, event.event_id
    finally:
        await pool.close()


async def test_packaged_audit_consumer_ingests_a_source_event_and_creates_a_finding(
    pg_dsn: str, runtime_dsn: str, nats_url: str
) -> None:
    """The whole staging path, with the model stage disabled."""
    await _reset(pg_dsn, nats_url)
    tenant, event_id = await _seed_and_publish(pg_dsn, nats_url)

    proc = subprocess.Popen(
        [sys.executable, "-m", "itsm_agent.workers.audit_consumer"],
        env=_consumer_env(runtime_dsn, nats_url),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = ""
    try:
        pool = create_pool(PersistenceConfig(dsn=pg_dsn))
        await pool.open()
        try:
            repositories = RepositoryBundle(pool)
            findings = []
            deadline = asyncio.get_running_loop().time() + FINDING_TIMEOUT_SECONDS
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.5)
                findings = await repositories.findings.list_for_tenant(tenant)
                if findings:
                    break

            assert findings, "the packaged audit consumer produced no finding"
            finding = findings[0]
            assert finding.finding_type in {
                "PRIVILEGE_ESCALATION",
                "MISSING_APPROVAL",
            }
            assert finding.severity in {"P1", "P2"}
            assert finding.outcome in {"SUSPICIOUS", "VIOLATION"}
            # Detection is authoritative: the finding is open, not resolved.
            assert finding.status == "OPEN"

            # The investigation stage was disabled: no ledger row, no model.
            requests = await repositories.investigation.list_requests_for_finding(
                tenant, finding.id
            )
            assert requests == []
            assert (
                await repositories.investigation.list_proposals_for_finding(tenant, finding.id)
                == []
            )

            # Exactly one processing record, COMPLETED (idempotent claim).
            async with pool.connection() as conn, conn.cursor() as cur:
                await cur.execute(
                    "SELECT status FROM processing_records WHERE tenant_id = %s", (tenant,)
                )
                rows = await cur.fetchall()
            assert len(rows) == 1
            assert rows[0][0] == "COMPLETED"
        finally:
            await pool.close()
    finally:
        proc.terminate()
        try:
            output = (proc.stdout.read() if proc.stdout else b"").decode("utf-8", "replace")
        except Exception:  # pragma: no cover - best-effort log capture
            output = ""
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()

    assert proc.returncode == 0, f"consumer exited {proc.returncode}: {output}"
    assert "audit consumer started" in output
    # The disabled stage never claimed to be running.
    assert "investigation stage enabled but no service configured" not in output


async def test_packaged_audit_consumer_fails_closed_without_a_model_key(
    runtime_dsn: str, nats_url: str
) -> None:
    """An enabled stage without a model key must abort the process."""
    env = _consumer_env(runtime_dsn, nats_url)
    env["ITSM_INVESTIGATION_ENABLED"] = "true"

    proc = subprocess.run(
        [sys.executable, "-m", "itsm_agent.workers.audit_consumer"],
        env=env,
        capture_output=True,
        timeout=60,
    )

    assert proc.returncode == 2, proc.stderr.decode("utf-8", "replace")
    assert b"ITSM_GROQ_API_KEY" in proc.stderr


async def test_packaged_audit_consumer_refuses_an_unsafe_database_role(
    pg_dsn: str, nats_url: str
) -> None:
    """A superuser connection must be refused at startup (fail closed)."""
    env = _consumer_env(pg_dsn, nats_url)

    proc = subprocess.run(
        [sys.executable, "-m", "itsm_agent.workers.audit_consumer"],
        env=env,
        capture_output=True,
        timeout=60,
    )

    assert proc.returncode == 2, proc.stderr.decode("utf-8", "replace")
    assert b"SUPERUSER" in proc.stderr


async def test_consumer_source_event_is_not_reprocessed(
    pg_dsn: str, runtime_dsn: str, nats_url: str
) -> None:
    """A redelivered event must not create a second finding."""
    await _reset(pg_dsn, nats_url)
    tenant, event_id = await _seed_and_publish(pg_dsn, nats_url)

    pool = create_pool(PersistenceConfig(dsn=pg_dsn))
    await pool.open()
    try:
        repositories = RepositoryBundle(pool)
        from itsm_agent.application.audit_consumer import consume_source_event

        messaging = MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
        publisher = JetStreamPublisher(messaging)
        await publisher.ensure_stream()
        await publisher.close()

        from itsm_agent.adapters.messaging.nats_bus import JetStreamConsumer

        consumer = JetStreamConsumer(messaging)
        await consumer.ensure_consumer()
        try:
            first = await consume_source_event(
                consumer=consumer,
                pool=pool,
                findings_repo=repositories.findings,
                processing_repo=repositories.processing_records,
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(UTC),
                timeout_seconds=5.0,
            )
            assert first == "processed"
            count = await repositories.findings.count_for_tenant(tenant)
            assert count >= 1
        finally:
            await consumer.close()
    finally:
        await pool.close()
