"""Task 7: NATS durable consumers + replay safety (vertical slice)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.application.replay import replay_source_events
from itsm_agent.domain.events import SourceEvent

pytestmark = pytest.mark.integration


def _make_event(tenant_id: uuid.UUID) -> SourceEvent:
    now = datetime.now(UTC)
    return SourceEvent(
        event_id=uuid.uuid4(),
        tenant_id=tenant_id,
        source="cloudtrail",
        source_event_id=f"evt-{uuid.uuid4().hex}",
        idempotency_key=f"key-{uuid.uuid4().hex}",
        canonical_schema_version="1.0",
        event_type="AssumeRole",
        event_category="auth",
        event_time=now,
        observed_at=now,
        action="sts:AssumeRole",
        payload_hash="0" * 64,
    )


@pytest.mark.asyncio
async def test_replay_enqueues_without_duplicate_source_events(pg_dsn: str, nats_url: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute("TRUNCATE source_events, event_inbox, outbox CASCADE")
        sink = PsycopgSourceEventSink(pool)
        tenant = uuid.uuid4()
        ev = _make_event(tenant)
        assert (await sink.accept_source_event(ev)).value == "ACCEPTED"

        # first replay
        ids1 = await replay_source_events(
            pool,
            tenant_id=tenant,
            source="cloudtrail",
            start=ev.event_time - timedelta(minutes=1),
            end=ev.event_time + timedelta(minutes=1),
            limit=10,
        )
        assert ids1 == [ev.event_id]

        # second replay is idempotent: no new requeue
        ids2 = await replay_source_events(
            pool,
            tenant_id=tenant,
            source="cloudtrail",
            start=ev.event_time - timedelta(minutes=1),
            end=ev.event_time + timedelta(minutes=1),
            limit=10,
        )
        assert ids2 == []

        # source_events unchanged
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) FROM source_events WHERE tenant_id = %s", (tenant,)
            )
            r = await cur.fetchone()
            assert r is not None
            assert r[0] == 1

        # one replay outbox row
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) FROM outbox WHERE event_type = %s AND tenant_id = %s",
                ("SourceEventReplayed", tenant),
            )
            r = await cur.fetchone()
            assert r is not None
            assert r[0] == 1
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_replay_bounded_limit(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute("TRUNCATE source_events, event_inbox, outbox CASCADE")
        sink = PsycopgSourceEventSink(pool)
        tenant = uuid.uuid4()
        for _ in range(5):
            ev = _make_event(tenant)
            assert (await sink.accept_source_event(ev)).value == "ACCEPTED"

        ids = await replay_source_events(
            pool,
            tenant_id=tenant,
            source="cloudtrail",
            start=datetime.now(UTC) - timedelta(hours=1),
            end=datetime.now(UTC) + timedelta(hours=1),
            limit=2,
        )
        assert len(ids) == 2
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_replay_invalid_limit_raises(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        import pytest as _p

        with _p.raises(ValueError):
            await replay_source_events(
                pool,
                tenant_id=uuid.uuid4(),
                source="cloudtrail",
                start=datetime.now(UTC),
                end=datetime.now(UTC),
                limit=0,
            )
        with _p.raises(ValueError):
            await replay_source_events(
                pool,
                tenant_id=uuid.uuid4(),
                source="cloudtrail",
                start=datetime.now(UTC),
                end=datetime.now(UTC),
                limit=1001,
            )
    finally:
        await pool.close()
