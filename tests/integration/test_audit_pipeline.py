"""Integration: real PostgreSQL source-event ingestion -> detection (audit pipeline)."""

from __future__ import annotations

import uuid

import pytest

from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.detection.engine import run_detection

pytestmark = pytest.mark.integration


def _ct_record(tenant: uuid.UUID) -> dict[str, object]:
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
        "eventID": f"evt-{uuid.uuid4().hex}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }


@pytest.mark.asyncio
async def test_ingested_source_event_drives_detection(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute("TRUNCATE source_events, event_inbox, outbox CASCADE")
        tenant = uuid.uuid4()
        ev = normalize_record(_ct_record(tenant), tenant)
        sink = PsycopgSourceEventSink(pool)
        outcome = await sink.accept_source_event(ev)
        assert outcome.value == "ACCEPTED"

        # Read back from canonical store and run detection.
        from itsm_agent.adapters.persistence.repositories import PsycopgSourceEventRepository

        r = PsycopgSourceEventRepository(pool)
        stored = await r.get(ev.event_id)
        assert stored is not None
        assert stored.tenant_id == tenant

        findings = run_detection([stored])
        assert len(findings) >= 1
        assert any(f.finding_type == "PRIVILEGE_ESCALATION" for f in findings)
        assert all(f.tenant_id == tenant for f in findings)

        # Idempotent re-ingestion is a duplicate, no second source row.
        dup = await sink.accept_source_event(ev)
        assert dup.value == "DUPLICATE"
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) FROM source_events WHERE tenant_id = %s", (tenant,)
            )
            row = await cur.fetchone()
            assert row is not None and row[0] == 1
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_cross_tenant_source_events_isolated(pg_dsn: str) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute("TRUNCATE source_events, event_inbox, outbox CASCADE")
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        e1 = normalize_record(_ct_record(t1), t1)
        e2 = normalize_record(_ct_record(t2), t2)
        sink = PsycopgSourceEventSink(pool)
        assert (await sink.accept_source_event(e1)).value == "ACCEPTED"
        assert (await sink.accept_source_event(e2)).value == "ACCEPTED"

        from itsm_agent.adapters.persistence.repositories import PsycopgSourceEventRepository

        r = PsycopgSourceEventRepository(pool)
        s1 = await r.get(e1.event_id)
        s2 = await r.get(e2.event_id)
        assert s1 is not None and s2 is not None
        assert s1.tenant_id == t1
        assert s2.tenant_id == t2
    finally:
        await pool.close()
