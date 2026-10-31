"""Integration: durable security-audit pipeline (outbox -> NATS -> detection -> findings)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from itsm_agent.adapters.messaging.nats_bus import (
    JetStreamConsumer,
    JetStreamPublisher,
    MessagingConfig,
)
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.audit_consumer import (
    consume_source_event,
    process_source_event,
)
from itsm_agent.collectors.aws.cloudtrail import normalize_record

pytestmark = pytest.mark.integration


def _ct_record(tenant: uuid.UUID, event_id: str) -> dict[str, object]:
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
        "requestID": "req-1",
        "eventID": event_id,
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }


@pytest.mark.asyncio
async def test_source_event_processed_once_under_redelivery(pg_dsn: str, nats_url: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE source_events, event_inbox, outbox, findings, processing_records CASCADE"
            )
        tenant = uuid.uuid4()
        ev = normalize_record(_ct_record(tenant, f"evt-{uuid.uuid4().hex}"), tenant)
        sink = PsycopgSourceEventSink(pool)
        assert (await sink.accept_source_event(ev)).value == "ACCEPTED"

        repos = RepositoryBundle(pool)
        findings_repo = repos.findings
        processing_repo = repos.processing_records

        # First processing commits findings + COMPLETED record.
        already1, ids1 = await process_source_event(
            event=ev,
            pool=pool,
            findings_repo=findings_repo,
            processing_repo=processing_repo,
            covered_sources={"cloudtrail"},
            clock_now=lambda: datetime.now(UTC),
        )
        assert already1 is False
        assert len(ids1) >= 1
        count_after_first = await findings_repo.count_for_tenant(tenant)

        # Redelivery (crash-after-commit-before-ack): record is COMPLETED.
        already2, ids2 = await process_source_event(
            event=ev,
            pool=pool,
            findings_repo=findings_repo,
            processing_repo=processing_repo,
            covered_sources={"cloudtrail"},
            clock_now=lambda: datetime.now(UTC),
        )
        assert already2 is True
        assert ids2 == []
        # No duplicate findings.
        assert await findings_repo.count_for_tenant(tenant) == count_after_first
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_full_nats_round_trip_persists_finding(pg_dsn: str, nats_url: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE source_events, event_inbox, outbox, findings, processing_records CASCADE"
            )
        # Reset streams.
        import contextlib

        import nats

        nc = await nats.connect(servers=[nats_url], connect_timeout=2.0)
        try:
            js = nc.jetstream()
            for name in ("ITSM_EVENTS", "ITSM_DLQ"):
                with contextlib.suppress(Exception):
                    await js.delete_stream(name)
        finally:
            await nc.drain()

        tenant = uuid.uuid4()
        ev = normalize_record(_ct_record(tenant, f"evt-{uuid.uuid4().hex}"), tenant)
        sink = PsycopgSourceEventSink(pool)
        assert (await sink.accept_source_event(ev)).value == "ACCEPTED"

        repos = RepositoryBundle(pool)
        pub = JetStreamPublisher(MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0))
        await pub.ensure_stream()
        relay = OutboxRelay(repos.outbox, pub, backoff_seconds=0.0, max_attempts=10)
        published = await relay.relay_once()
        assert published >= 1

        consumer = JetStreamConsumer(
            MessagingConfig(servers=(nats_url,), connect_timeout_seconds=2.0)
        )
        await consumer.ensure_consumer()
        outcome1 = await consume_source_event(
            consumer=consumer,
            pool=pool,
            findings_repo=repos.findings,
            processing_repo=repos.processing_records,
            covered_sources={"cloudtrail"},
            clock_now=lambda: datetime.now(UTC),
            timeout_seconds=2.0,
        )
        assert outcome1 == "processed"

        # Redelivery: message was acked, so no second message.
        outcome2 = await consume_source_event(
            consumer=consumer,
            pool=pool,
            findings_repo=repos.findings,
            processing_repo=repos.processing_records,
            covered_sources={"cloudtrail"},
            clock_now=lambda: datetime.now(UTC),
            timeout_seconds=1.0,
        )
        assert outcome2 == "none"

        findings = await repos.findings.list_for_tenant(tenant)
        assert len(findings) >= 1
        assert any(f.finding_type == "PRIVILEGE_ESCALATION" for f in findings)
        # Exactly one processing record, COMPLETED.
        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT status FROM processing_records WHERE tenant_id = %s", (tenant,)
            )
            rows = await cur.fetchall()
            assert len(rows) == 1
            assert rows[0][0] == "COMPLETED"

        await consumer.close()
        await pub.close()
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_unknown_event_is_quarantined(pg_dsn: str, nats_url: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE source_events, event_inbox, outbox, findings, processing_records CASCADE"
            )
        # Build an event that was never ingested.
        tenant = uuid.uuid4()
        ev = normalize_record(_ct_record(tenant, f"evt-{uuid.uuid4().hex}"), tenant)
        repos = RepositoryBundle(pool)
        with pytest.raises(ValueError):
            await process_source_event(
                event=ev,
                pool=pool,
                findings_repo=repos.findings,
                processing_repo=repos.processing_records,
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(UTC),
            )
        # No processing record persisted.
        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT count(*) FROM processing_records WHERE tenant_id = %s", (tenant,)
            )
            row = await cur.fetchone()
            assert row is not None and row[0] == 0
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_tenant_mismatch_rejected(pg_dsn: str, nats_url: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE source_events, event_inbox, outbox, findings, processing_records CASCADE"
            )
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        ev = normalize_record(_ct_record(t1, f"evt-{uuid.uuid4().hex}"), t1)
        sink = PsycopgSourceEventSink(pool)
        assert (await sink.accept_source_event(ev)).value == "ACCEPTED"
        # Tamper: claim a different tenant in the message.
        tampered = ev.model_copy(update={"tenant_id": t2})
        repos = RepositoryBundle(pool)
        with pytest.raises(ValueError):
            await process_source_event(
                event=tampered,
                pool=pool,
                findings_repo=repos.findings,
                processing_repo=repos.processing_records,
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(UTC),
            )
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_two_tenants_identical_event_ids_isolated(pg_dsn: str, nats_url: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=4))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                "TRUNCATE source_events, event_inbox, outbox, findings, processing_records CASCADE"
            )
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        shared_event_id = f"evt-{uuid.uuid4().hex}"
        e1 = normalize_record(_ct_record(t1, shared_event_id), t1)
        e2 = normalize_record(_ct_record(t2, shared_event_id), t2)
        sink = PsycopgSourceEventSink(pool)
        assert (await sink.accept_source_event(e1)).value == "ACCEPTED"
        assert (await sink.accept_source_event(e2)).value == "ACCEPTED"
        repos = RepositoryBundle(pool)
        await process_source_event(
            event=e1,
            pool=pool,
            findings_repo=repos.findings,
            processing_repo=repos.processing_records,
            covered_sources={"cloudtrail"},
            clock_now=lambda: datetime.now(UTC),
        )
        await process_source_event(
            event=e2,
            pool=pool,
            findings_repo=repos.findings,
            processing_repo=repos.processing_records,
            covered_sources={"cloudtrail"},
            clock_now=lambda: datetime.now(UTC),
        )
        assert await repos.findings.count_for_tenant(t1) >= 1
        assert await repos.findings.count_for_tenant(t2) >= 1
        # processing records are tenant-scoped
        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM processing_records")
            row = await cur.fetchone()
            assert row is not None and row[0] == 2
    finally:
        await pool.close()
