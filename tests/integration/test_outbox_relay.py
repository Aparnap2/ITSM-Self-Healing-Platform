"""Integration: outbox accumulates while broker is down, publishes after recovery."""

from __future__ import annotations

import dataclasses
from uuid import uuid4

import pytest

from itsm_agent.adapters.messaging.nats_bus import JetStreamPublisher, MessagingConfig
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.repositories import RepositoryBundle

pytestmark = pytest.mark.integration


def _down_config(messaging_config: MessagingConfig) -> MessagingConfig:
    return dataclasses.replace(
        messaging_config, servers=("nats://localhost:1",), connect_timeout_seconds=1.0
    )


async def test_broker_down_outbox_accumulates_then_publishes_after_recovery(
    repos: RepositoryBundle, messaging_config: MessagingConfig
) -> None:
    # Persist three events through the outbox (transactional append).
    for i in range(3):
        await repos.outbox.append(
            event_type="IncidentCreated", aggregate_id=uuid4(), payload={"seq": i}
        )
    assert await repos.outbox.count_pending() == 3

    # Broker unreachable: relay fails closed per row, rows stay pending.
    down_relay = OutboxRelay(
        repos.outbox,
        JetStreamPublisher(_down_config(messaging_config)),
        backoff_seconds=0.0,
        max_attempts=10,
    )
    published = await down_relay.relay_once()
    assert published == 0
    assert await repos.outbox.count_pending() == 3

    # Broker recovered: same outbox rows publish and are marked published.
    up_relay = OutboxRelay(
        repos.outbox,
        JetStreamPublisher(messaging_config),
        backoff_seconds=0.0,
        max_attempts=10,
    )
    await up_relay._publisher.ensure_stream()
    published = await up_relay.relay_once()
    assert published == 3
    assert await repos.outbox.count_pending() == 0


async def test_outbox_retry_exhaustion_goes_terminal_failed(
    repos: RepositoryBundle, messaging_config: MessagingConfig
) -> None:
    event = await repos.outbox.append(
        event_type="IncidentCreated", aggregate_id=uuid4(), payload={}
    )
    down_relay = OutboxRelay(
        repos.outbox,
        JetStreamPublisher(_down_config(messaging_config)),
        backoff_seconds=0.0,
        max_attempts=2,
    )
    await down_relay.relay_once()  # attempts = 1
    await down_relay.relay_once()  # attempts = 2 -> terminal failed
    assert await repos.outbox.count_pending() == 0
    row = await repos.outbox.claim_pending(limit=10)
    assert row == []
    # Verify terminal state directly.
    from psycopg.rows import dict_row  # noqa: PLC0415

    pool = repos.outbox._pool
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT status, attempts, last_error FROM outbox WHERE id = %s",
            (event.id,),
        )
        r = await cur.fetchone()
    assert r is not None
    assert r["status"] == "failed"
    assert r["attempts"] == 2
    assert r["last_error"] is not None
