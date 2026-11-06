"""Integration: consumer crash between handler and ack => redelivery without
duplicate side effect (idempotent handler + action intent idempotency key).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from itsm_agent.adapters.messaging.nats_bus import (
    DispatchOutcome,
    JetStreamConsumer,
    JetStreamPublisher,
    dispatch_once,
)
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.ports.repositories import ActionIntent, Incident

pytestmark = [pytest.mark.integration, pytest.mark.fault_injection]


async def _seed_incident(repos: RepositoryBundle) -> Incident:
    now = datetime.now(UTC)
    incident = Incident(
        id=uuid4(),
        source_system="mockoon-itsm",
        source_incident_id="INC-2001",
        external_event_id=f"evt-{uuid4().hex}",
        title="payments-api down",
        description="restart needed",
        service_name="payments-api",
        severity="P2",
        status="IN_PROGRESS",
        created_at=now,
        updated_at=now,
        correlation_id=uuid4(),
    )
    await repos.incidents.create(incident)
    return incident


async def test_crash_between_handler_and_ack_redelivers_without_duplicate_side_effect(
    repos: RepositoryBundle, messaging_config: Any
) -> None:
    incident = await _seed_incident(repos)
    workflow_id = uuid4()
    idempotency_key = f"restart:{incident.id}:1"

    publisher = JetStreamPublisher(messaging_config)
    await publisher.ensure_stream()
    await publisher.publish(
        "itsm.events.RemediationProposed",
        b'{"action": "RESTART_SERVICE", "service": "payments-api"}',
    )

    consumer = JetStreamConsumer(messaging_config)
    await consumer.ensure_consumer()

    calls: list[str] = []

    async def crashing_handler(message: Any) -> None:
        """Durable side effect, then crash before the ack."""
        intent = ActionIntent(
            id=uuid4(),
            incident_id=incident.id,
            workflow_id=workflow_id,
            action_type="RESTART_SERVICE",
            resource_id="payments-api",
            idempotency_key=idempotency_key,
            proposal_hash="c" * 64,
            status="INTENT_RECORDED",
            intent_recorded_at=datetime.now(UTC),
            adapter_name="simulated-infra",
        )
        try:
            await repos.action_intents.record(intent)
        except Exception:
            # Redelivery: intent already durable — treat as already done.
            calls.append("duplicate-intent")
            return
        calls.append("recorded-intent")
        raise RuntimeError("worker crashed after side effect, before ack")

    # Delivery 1: side effect recorded, crash before ack -> bounded redelivery.
    outcome1 = await dispatch_once(consumer, crashing_handler, timeout_seconds=2.0)
    assert outcome1 is DispatchOutcome.RETRY_SCHEDULED
    assert calls == ["recorded-intent"]

    # Delivery 2 (redelivery): idempotency key guard -> no duplicate side effect.
    outcome2 = await _dispatch_until(consumer, crashing_handler, expected=DispatchOutcome.PROCESSED)
    assert outcome2 is DispatchOutcome.PROCESSED
    assert calls == ["recorded-intent", "duplicate-intent"]

    # Exactly one durable action intent despite two deliveries.
    stored = await repos.action_intents.get_by_idempotency_key(idempotency_key)
    assert stored is not None
    assert stored.idempotency_key == idempotency_key
    count = await _count_intents(repos, idempotency_key)
    assert count == 1

    await consumer.close()
    await publisher.close()


async def _dispatch_until(
    consumer: JetStreamConsumer,
    handler: Any,
    *,
    expected: DispatchOutcome,
    max_polls: int = 100,
) -> DispatchOutcome:
    """Bounded poll loop (no fixed sleeps): dispatch until expected outcome."""
    for _ in range(max_polls):
        outcome = await dispatch_once(consumer, handler, timeout_seconds=1.0)
        if outcome is expected:
            return outcome
        if outcome is DispatchOutcome.NONE:
            await _tiny_wait()
    raise AssertionError(f"did not reach {expected} within {max_polls} polls")


async def _tiny_wait() -> None:
    import asyncio

    await asyncio.sleep(0.05)


async def _count_intents(repos: RepositoryBundle, idempotency_key: str) -> int:
    from psycopg.rows import dict_row

    pool = repos.incidents._pool  # noqa: SLF001 - test-only access
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT count(*) AS n FROM action_intents WHERE idempotency_key = %s",
            (idempotency_key,),
        )
        row = await cur.fetchone()
    assert row is not None
    return int(row["n"])
