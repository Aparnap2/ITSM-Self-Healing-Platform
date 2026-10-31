"""Integration: inbox dedup => single logical incident (PRD ITSM-011 path)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from psycopg import AsyncConnection

from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.ports.repositories import AuditEvent, InboxReceipt, Incident

pytestmark = pytest.mark.integration


def _incident(external_event_id: str) -> Incident:
    now = datetime.now(UTC)
    return Incident(
        id=uuid4(),
        source_system="mockoon-itsm",
        source_incident_id="INC-1001",
        external_event_id=external_event_id,
        title="payments-api unhealthy",
        description="Health check failing for payments-api",
        service_name="payments-api",
        severity="P2",
        status="NEW",
        created_at=now,
        updated_at=now,
        correlation_id=uuid4(),
    )


async def test_duplicate_delivery_creates_single_incident(repos: RepositoryBundle) -> None:
    event_id = f"evt-{uuid4().hex}"

    first = await repos.inbox.try_record(
        source_system="mockoon-itsm", external_event_id=event_id, payload_hash="a" * 64
    )
    assert first is InboxReceipt.NEW
    await repos.incidents.create(_incident(event_id))

    second = await repos.inbox.try_record(
        source_system="mockoon-itsm", external_event_id=event_id, payload_hash="a" * 64
    )
    assert second is InboxReceipt.DUPLICATE

    found = await repos.incidents.find_by_external_event("mockoon-itsm", event_id)
    assert found is not None
    by_source = await repos.incidents.find_by_source("mockoon-itsm", "INC-1001")
    assert by_source is not None
    assert found.id == by_source.id


async def test_concurrent_duplicate_delivery_exactly_one_wins(repos: RepositoryBundle) -> None:
    event_id = f"evt-{uuid4().hex}"
    results = await asyncio.gather(
        repos.inbox.try_record(
            source_system="mockoon-itsm", external_event_id=event_id, payload_hash="b" * 64
        ),
        repos.inbox.try_record(
            source_system="mockoon-itsm", external_event_id=event_id, payload_hash="b" * 64
        ),
    )
    assert sorted(r.value for r in results) == sorted(
        [InboxReceipt.NEW.value, InboxReceipt.DUPLICATE.value]
    )


async def test_audit_events_are_append_only(repos: RepositoryBundle, pg_dsn: str) -> None:
    event = AuditEvent(
        id=uuid4(),
        occurred_at=datetime.now(UTC),
        correlation_id=uuid4(),
        actor_type="SYSTEM",
        actor_id="ingestion",
        event_type="EVENT_RECEIVED",
        payload_redacted={"source": "mockoon-itsm"},
    )
    await repos.audit.append(event)

    async with await AsyncConnection.connect(pg_dsn) as conn:
        with pytest.raises(Exception, match="append-only"):
            await conn.execute(
                "UPDATE audit_events SET actor_id = 'tampered' WHERE id = %s", (event.id,)
            )
        await conn.rollback()
        with pytest.raises(Exception, match="append-only"):
            await conn.execute("DELETE FROM audit_events WHERE id = %s", (event.id,))
        await conn.rollback()
