"""Outbox relay: PostgreSQL outbox -> NATS JetStream (ADR-0002).

Publishes claimed pending outbox rows and marks them published ONLY after
broker acknowledgement. On failure, marks failure with bounded backoff;
after max attempts the row goes terminal 'failed' for reconciliation.

Tenant scoping: with row-level security enabled, a relay pass must run under
one tenant's transaction-local context or it sees nothing (fail closed).
``relay_once(tenant_id)`` claims, publishes and marks *only* that tenant's
rows, each database step opening its own scoped transaction; the publish call
itself is never inside a database transaction. ``run()`` enumerates tenants
with ``PsycopgTenantRepository.list_tenant_ids()`` and performs one scoped
pass per tenant. ``tenant_id=None`` is kept for the system-wide tests and is
only correct on a connection that bypasses RLS.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING
from uuid import UUID

from itsm_agent.adapters.messaging.nats_bus import (
    EVENT_SUBJECT_PREFIX,
    JetStreamPublisher,
)

if TYPE_CHECKING:
    from itsm_agent.adapters.persistence.repositories import (
        PsycopgOutboxRepository,
        PsycopgTenantRepository,
    )

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
        tenants: PsycopgTenantRepository | None = None,
    ) -> None:
        self._outbox = outbox
        self._tenants = tenants
        self._publisher = publisher
        self._batch_size = batch_size
        self._backoff_seconds = backoff_seconds
        self._max_attempts = max_attempts
        self._lease_seconds = lease_seconds

    async def relay_once(self, tenant_id: UUID | None = None) -> int:
        """One relay pass. Returns the number of rows published.

        ``tenant_id`` scopes claim and acknowledgement to one tenant; ``None``
        keeps the system-wide claim, which is only valid when RLS is bypassed.
        """
        claimed = await self._outbox.claim_pending(
            limit=self._batch_size,
            lease_seconds=self._lease_seconds,
            tenant_id=tenant_id,
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
                    tenant_id=tenant_id,
                )
            else:
                await self._outbox.mark_published(event.id, tenant_id=tenant_id)
                published += 1
        return published

    async def run(self, *, poll_interval_seconds: float = 1.0) -> None:
        """Long-running relay loop (bounded per pass; cancel to stop).

        One scoped pass per registered tenant. Without a tenant registry the
        legacy system-wide pass runs; that only works on a role that bypasses
        RLS, so a deployment must supply ``tenants=``.
        """
        await self._publisher.ensure_stream()
        while True:
            published = 0
            tenant_ids = await self._tenants.list_tenant_ids() if self._tenants is not None else []
            if tenant_ids:
                for tenant_id in tenant_ids:
                    published += await self.relay_once(tenant_id)
            else:
                published = await self.relay_once()
            if published == 0:
                await asyncio.sleep(poll_interval_seconds)
