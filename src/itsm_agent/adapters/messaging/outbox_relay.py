"""Outbox relay: PostgreSQL outbox -> NATS JetStream (ADR-0002).

Publishes claimed pending outbox rows and marks them published ONLY after
broker acknowledgement. On failure, marks failure with bounded backoff;
after max attempts the row goes terminal 'failed' for reconciliation.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING

from itsm_agent.adapters.messaging.nats_bus import (
    EVENT_SUBJECT_PREFIX,
    JetStreamPublisher,
)

if TYPE_CHECKING:
    from itsm_agent.adapters.persistence.repositories import PsycopgOutboxRepository

logger = logging.getLogger(__name__)


class OutboxRelay:
    def __init__(
        self,
        outbox: PsycopgOutboxRepository,
        publisher: JetStreamPublisher,
        *,
        batch_size: int = 10,
        backoff_seconds: float = 2.0,
        max_attempts: int = 10,
        lease_seconds: float = 60.0,
    ) -> None:
        self._outbox = outbox
        self._publisher = publisher
        self._batch_size = batch_size
        self._backoff_seconds = backoff_seconds
        self._max_attempts = max_attempts
        self._lease_seconds = lease_seconds

    async def relay_once(self) -> int:
        """One relay pass. Returns the number of rows published."""
        claimed = await self._outbox.claim_pending(
            limit=self._batch_size, lease_seconds=self._lease_seconds
        )
        published = 0
        for event in claimed:
            subject = f"{EVENT_SUBJECT_PREFIX}{event.event_type}"
            payload = json.dumps(
                {
                    "outbox_id": str(event.id),
                    "event_type": event.event_type,
                    "aggregate_id": str(event.aggregate_id),
                    "payload": event.payload,
                }
            ).encode()
            try:
                await self._publisher.publish(subject, payload)
            except Exception as exc:  # broker down / publish error: bounded retry
                logger.warning("outbox publish failed id=%s: %s", event.id, exc)
                await self._outbox.mark_failed(
                    event.id,
                    str(exc),
                    backoff_seconds=self._backoff_seconds,
                    max_attempts=self._max_attempts,
                )
            else:
                await self._outbox.mark_published(event.id)
                published += 1
        return published

    async def run(self, *, poll_interval_seconds: float = 1.0) -> None:
        """Long-running relay loop (bounded per pass; cancel to stop)."""
        await self._publisher.ensure_stream()
        while True:
            count = await self.relay_once()
            if count == 0:
                await asyncio.sleep(poll_interval_seconds)
