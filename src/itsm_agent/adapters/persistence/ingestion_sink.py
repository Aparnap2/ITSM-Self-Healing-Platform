"""DB-backed ``IngestionSink`` (FR-01 durable acceptance).

Writes the validated event to the inbox (dedup on
(source_system, external_event_id)) and appends a matching outbox row in a
single transaction. Returns ACCEPTED only after commit; DUPLICATE when the
inbox constraint fires; UNAVAILABLE on any commit failure (fail closed).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.repositories import (
    PsycopgInboxRepository,
    PsycopgOutboxRepository,
    PsycopgSourceEventRepository,
)
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.domain.events import IncidentCreated, SourceEvent
from itsm_agent.ports.repositories import InboxReceipt

__all__ = ["PsycopgIngestionSink"]


def _payload_hash(event: IncidentCreated) -> str:
    canonical = json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PsycopgIngestionSink:
    """Durable inbox+outbox acceptance backed by PostgreSQL."""

    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool
        self._inbox = PsycopgInboxRepository(pool)
        self._outbox = PsycopgOutboxRepository(pool)

    async def accept_incident(self, event: IncidentCreated) -> SinkOutcome:
        source_system = event.source_system
        external_event_id = event.external_event_id
        try:
            async with self._pool.connection() as conn, conn.transaction():
                receipt = await self._inbox.try_record(
                    source_system=source_system,
                    external_event_id=external_event_id,
                    payload_hash=_payload_hash(event),
                    conn=conn,
                )
                if receipt is InboxReceipt.DUPLICATE:
                    return SinkOutcome.DUPLICATE
                aggregate_id = uuid4()
                await self._outbox.append(
                    event_type="IncidentCreated",
                    aggregate_id=aggregate_id,
                    payload=event.model_dump(mode="json"),
                    conn=conn,
                )
            return SinkOutcome.ACCEPTED
        except Exception:  # noqa: BLE001 — fail closed on any commit failure
            return SinkOutcome.UNAVAILABLE


class PsycopgSourceEventSink:
    """Durable inbox + source_events + outbox acceptance (Task 6)."""

    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool
        self._inbox = PsycopgInboxRepository(pool)
        self._source_events = PsycopgSourceEventRepository(pool)
        self._outbox = PsycopgOutboxRepository(pool)

    async def accept_source_event(self, event: SourceEvent) -> SinkOutcome:
        source_system = event.source
        external_event_id = event.idempotency_key
        try:
            async with self._pool.connection() as conn, conn.transaction():
                receipt = await self._inbox.try_record(
                    source_system=source_system,
                    external_event_id=external_event_id,
                    payload_hash=event.payload_hash,
                    conn=conn,
                )
                if receipt is InboxReceipt.DUPLICATE:
                    return SinkOutcome.DUPLICATE
                await self._source_events.insert(event, conn=conn)
                await self._outbox.append(
                    event_type="SourceEventIngested",
                    aggregate_id=event.event_id,
                    payload=event.model_dump(mode="json"),
                    conn=conn,
                )
            return SinkOutcome.ACCEPTED
        except Exception:  # noqa: BLE001 — fail closed
            return SinkOutcome.UNAVAILABLE
