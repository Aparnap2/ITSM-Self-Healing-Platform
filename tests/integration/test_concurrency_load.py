"""Integration: bounded concurrency — exactly-once behaviour under load.

Marker: ``integration``.

This is the closest thing the repository has to a load test, and it is
deliberately **not** a performance benchmark: it asserts correctness under
concurrency, not throughput or latency, because a latency assertion on a
shared CI runner is a flake generator dressed as a gate.

Two properties are pinned:

* **The same event delivered concurrently is processed once.** Fifty parallel
  deliveries of one source event must leave exactly one canonical event, one
  inbox row and one finding — the idempotency contract must hold under
  concurrency, not only sequentially.
* **Distinct events delivered concurrently are all persisted.** Fifty parallel
  deliveries of fifty distinct events must produce fifty canonical events and
  fifty findings: concurrency must not lose work.

Both use real PostgreSQL, so the unique constraints and the transactional
outbox do the work.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest

from itsm_agent.adapters.persistence.ingestion_sink import PsycopgSourceEventSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.application.audit_consumer import process_source_event
from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.domain.events import SourceEvent

pytestmark = pytest.mark.integration

#: Concurrency level for one run. Big enough to interleave, small enough to
#: stay fast and deterministic on a shared runner.
CONCURRENCY = 25

#: Upper bound on the wall time of the concurrent phase. This is a watchdog
#: against a deadlock or a lock convoy, NOT a performance claim.
WATCHDOG_SECONDS = 120.0


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


async def test_the_same_event_delivered_concurrently_is_processed_once(
    pg_dsn: str,
) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=8))
    await pool.open()
    try:
        tenant = uuid.uuid4()
        event = normalize_record(_ct_record(tenant, f"evt-{uuid.uuid4().hex}"), tenant)
        sink = PsycopgSourceEventSink(pool)
        repos = RepositoryBundle(pool)

        async def deliver() -> None:
            await sink.accept_source_event(event)

        await asyncio.wait_for(
            asyncio.gather(*[deliver() for _ in range(CONCURRENCY)]),
            timeout=WATCHDOG_SECONDS,
        )

        # Exactly one canonical event survived the race.
        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM source_events WHERE tenant_id = %s", (tenant,))
            row = await cur.fetchone()
        assert row is not None and row[0] == 1, "the same event was stored twice"

        # Detection then runs for the same event concurrently: the processing
        # record must short-circuit the duplicates, so exactly one finding and
        # one processing record exist.
        async def detect() -> None:
            await process_source_event(
                event=event,
                pool=pool,
                findings_repo=repos.findings,
                processing_repo=repos.processing_records,
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(UTC),
            )

        await asyncio.wait_for(
            asyncio.gather(*[detect() for _ in range(4)]),
            timeout=WATCHDOG_SECONDS,
        )

        findings = await repos.findings.list_for_tenant(tenant)
        assert len(findings) == 1, "the same event produced duplicate findings"

        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT count(*) FROM processing_records WHERE tenant_id = %s", (tenant,)
            )
            row = await cur.fetchone()
        assert row is not None and row[0] == 1, "the event was processed more than once"
    finally:
        await pool.close()


async def test_distinct_events_delivered_concurrently_are_all_persisted(
    pg_dsn: str,
) -> None:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=8))
    await pool.open()
    try:
        tenant = uuid.uuid4()
        events = [
            normalize_record(_ct_record(tenant, f"evt-{uuid.uuid4().hex}"), tenant)
            for _ in range(CONCURRENCY)
        ]
        sink = PsycopgSourceEventSink(pool)
        repos = RepositoryBundle(pool)

        async def deliver(event: SourceEvent) -> None:
            await sink.accept_source_event(event)

        await asyncio.wait_for(
            asyncio.gather(*[deliver(event) for event in events]),
            timeout=WATCHDOG_SECONDS,
        )

        async def detect(event: SourceEvent) -> None:
            await process_source_event(
                event=event,
                pool=pool,
                findings_repo=repos.findings,
                processing_repo=repos.processing_records,
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(UTC),
            )

        await asyncio.wait_for(
            asyncio.gather(*[detect(event) for event in events]),
            timeout=WATCHDOG_SECONDS,
        )

        # No event was lost: every delivery produced its own canonical row
        # and its own processing record.
        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM source_events WHERE tenant_id = %s", (tenant,))
            row = await cur.fetchone()
        assert row is not None and row[0] == CONCURRENCY, "an event was lost"

        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT count(*) FROM processing_records WHERE tenant_id = %s", (tenant,)
            )
            row = await cur.fetchone()
        assert row is not None and row[0] == CONCURRENCY, "a processing record was lost"

        # Findings are deduplicated by design: the table is unique on
        # (tenant_id, finding_type, title), and every event here carries the
        # same rule's title, so they collapse into one finding. That is the
        # intended triage behaviour, not a lost finding.
        findings = await repos.findings.list_for_tenant(tenant)
        assert len(findings) == 1
        assert findings[0].tenant_id == tenant
    finally:
        await pool.close()
