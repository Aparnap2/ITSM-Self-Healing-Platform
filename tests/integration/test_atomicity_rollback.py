"""Transaction atomicity and rollback safety for the durable write paths.

The ingestion sinks accept an event by writing the inbox receipt, the
source-event row (source path) and the matching outbox row inside ONE
transaction. If any step fails the whole write set must vanish; a partial
write would poison every retry and, worse, present an outbox row without an
inbox receipt (or vice versa) to the relay.

These tests inject the failure *inside* the transaction and then assert the
database is byte-for-byte empty for that event, and that a retry after the
transient failure succeeds exactly once.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from psycopg import AsyncConnection

from itsm_agent.adapters.persistence.ingestion_sink import (
    PsycopgIngestionSink,
    PsycopgSourceEventSink,
)
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.events import IncidentCreated, SourceEvent

pytestmark = pytest.mark.integration


def _incident(source_system: str = "mockoon-itsm") -> IncidentCreated:
    now = datetime.now(UTC)
    return IncidentCreated(
        event_id=uuid.uuid4(),
        source_system=source_system,
        source_incident_id=f"INC-{uuid.uuid4().hex[:12]}",
        external_event_id=f"ext-{uuid.uuid4().hex}",
        occurred_at=now,
        received_at=now,
        correlation_id=uuid.uuid4(),
        title="Injection failure test",
        description="rollback must discard the whole write set",
        service_name="payments-api",
        severity="P2",
        environment="test",
    )


def _source_event(tenant_id: uuid.UUID) -> SourceEvent:
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


async def _admin_dsn(pg_dsn: str, query: str, params: tuple[object, ...] = ()) -> list[tuple]:
    async with await AsyncConnection.connect(pg_dsn) as conn:
        return list(await (await conn.execute(query, params)).fetchall())


async def test_outbox_append_failure_rolls_back_incident_write_set(
    repos: RepositoryBundle, pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = _incident()

    async def boom(self: object, *args: object, **kwargs: object) -> None:
        raise RuntimeError("injected outbox append failure")

    monkeypatch.setattr(
        "itsm_agent.adapters.persistence.repositories.PsycopgOutboxRepository.append",
        boom,
    )

    sink = PsycopgIngestionSink(repos.outbox._pool)
    outcome = await sink.accept_incident(event)

    assert outcome.value == "UNAVAILABLE"
    for table, query in (
        ("event_inbox", "SELECT count(*) FROM event_inbox WHERE external_event_id = %s"),
        ("outbox", "SELECT count(*) FROM outbox WHERE payload->>'event_id' = %s"),
    ):
        rows = await _admin_dsn(
            pg_dsn,
            query,
            (event.external_event_id if table == "event_inbox" else str(event.event_id),),
        )
        assert rows == [(0,)], f"{table} leaked a partial row: {rows}"


async def test_outbox_append_failure_rolls_back_source_event_write_set(
    repos: RepositoryBundle, pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = uuid.uuid4()
    event = _source_event(tenant_id)

    async def boom(self: object, *args: object, **kwargs: object) -> None:
        raise RuntimeError("injected outbox append failure")

    monkeypatch.setattr(
        "itsm_agent.adapters.persistence.repositories.PsycopgOutboxRepository.append",
        boom,
    )

    sink = PsycopgSourceEventSink(repos.outbox._pool)
    outcome = await sink.accept_source_event(event)

    assert outcome.value == "UNAVAILABLE"
    rows = await _admin_dsn(
        pg_dsn,
        "SELECT count(*) FROM source_events WHERE idempotency_key = %s",
        (event.idempotency_key,),
    )
    assert rows == [(0,)]
    rows = await _admin_dsn(
        pg_dsn,
        "SELECT count(*) FROM event_inbox WHERE external_event_id = %s",
        (event.idempotency_key,),
    )
    assert rows == [(0,)]
    rows = await _admin_dsn(
        pg_dsn,
        "SELECT count(*) FROM outbox WHERE payload->>'event_id' = %s",
        (str(event.event_id),),
    )
    assert rows == [(0,)]
    rows = await _admin_dsn(
        pg_dsn,
        "SELECT count(*) FROM tenants WHERE id = %s",
        (tenant_id,),
    )
    assert rows == [(0,)]


async def test_retry_after_transient_failure_succeeds_exactly_once(
    repos: RepositoryBundle, pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = _incident()

    async def flaky_append(self: object, *args: object, **kwargs: object) -> object:
        raise RuntimeError("injected transient failure")

    import itsm_agent.adapters.persistence.repositories as repositories_module

    monkeypatch.setattr(repositories_module.PsycopgOutboxRepository, "append", flaky_append)
    sink = PsycopgIngestionSink(repos.outbox._pool)
    assert (await sink.accept_incident(event)).value == "UNAVAILABLE"

    monkeypatch.undo()
    sink = PsycopgIngestionSink(repos.outbox._pool)
    assert (await sink.accept_incident(event)).value == "ACCEPTED"
    # A full replay of the same event is a DUPLICATE, not a duplicate side effect.
    assert (await sink.accept_incident(event)).value == "DUPLICATE"

    rows = await _admin_dsn(
        pg_dsn,
        "SELECT count(*) FROM event_inbox WHERE external_event_id = %s",
        (event.external_event_id,),
    )
    assert rows == [(1,)]
    rows = await _admin_dsn(
        pg_dsn,
        "SELECT count(*) FROM outbox WHERE payload->>'event_id' = %s",
        (str(event.event_id),),
    )
    assert rows == [(1,)]
