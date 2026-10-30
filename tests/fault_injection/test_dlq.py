"""Integration: bounded redelivery exhaustion => DLQ + escalation event."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import uuid4

import pytest
from nats.js.api import ConsumerConfig

from itsm_agent.adapters.messaging.nats_bus import (
    DLQ_SUBJECT,
    ESCALATION_SUBJECT,
    DispatchOutcome,
    JetStreamConsumer,
    JetStreamPublisher,
    dispatch_once,
)

pytestmark = pytest.mark.integration

MAX_DELIVER = 3


async def test_redelivery_exhaustion_dead_letters_and_escalates(
    messaging_config: Any,
) -> None:
    import contextlib

    import nats

    nc = await nats.connect(servers=list(messaging_config.servers), connect_timeout=2.0)
    try:
        js = nc.jetstream()
        for name in ("ITSM_EVENTS", "ITSM_DLQ"):
            with contextlib.suppress(Exception):
                await js.delete_stream(name)
    finally:
        await nc.drain()

    publisher = JetStreamPublisher(messaging_config)
    await publisher.ensure_stream()
    await publisher.publish("itsm.events.RemediationProposed", b'{"boom": true}')

    consumer = JetStreamConsumer(messaging_config)
    await consumer.ensure_consumer()

    attempts: list[int] = []

    async def always_failing_handler(message: Any) -> None:
        attempts.append(message.delivery_attempt)
        raise RuntimeError(f"permanent failure #{message.delivery_attempt}")

    # Bounded poll loop until the message is dead-lettered (no fixed sleeps).
    outcome = DispatchOutcome.NONE
    for _ in range(200):
        outcome = await dispatch_once(
            consumer, always_failing_handler, max_deliver=MAX_DELIVER, timeout_seconds=1.0
        )
        if outcome is DispatchOutcome.DEAD_LETTERED:
            break
        await asyncio.sleep(0.1)
    assert outcome is DispatchOutcome.DEAD_LETTERED, f"attempts seen: {attempts}"
    assert attempts == [1, 2, 3]  # exactly max_deliver deliveries, then DLQ

    # Drain the DLQ stream and verify payload + escalation event.
    dlq_messages = await _drain_dlq(messaging_config)
    subjects = {m["subject"] for m in dlq_messages}
    assert DLQ_SUBJECT in subjects
    assert ESCALATION_SUBJECT in subjects

    dead = next(m for m in dlq_messages if m["subject"] == DLQ_SUBJECT)
    assert dead["body"]["original_subject"] == "itsm.events.RemediationProposed"
    assert "permanent failure" in dead["body"]["error"]
    assert dead["body"]["delivery_attempt"] == MAX_DELIVER

    escalation = next(m for m in dlq_messages if m["subject"] == ESCALATION_SUBJECT)
    assert escalation["body"]["event_type"] == "ESCALATION"
    assert escalation["body"]["reason"] == "REDELIVERY_EXHAUSTED"

    await consumer.close()
    await publisher.close()


async def _drain_dlq(messaging_config: Any) -> list[dict[str, Any]]:
    """Fetch DLQ + escalation messages with a bounded wait loop."""
    import nats

    nc = await nats.connect(
        servers=list(messaging_config.servers),
        connect_timeout=messaging_config.connect_timeout_seconds,
    )
    try:
        js = nc.jetstream()
        durable = f"dlq-drain-{uuid4().hex}"
        sub = await js.pull_subscribe(
            "itsm.dlq.>", durable=durable, config=ConsumerConfig(durable_name=durable)
        )
        collected: list[dict[str, Any]] = []
        for _ in range(50):
            try:
                msgs = await sub.fetch(2, timeout=0.5)
            except TimeoutError:
                if collected:
                    break
                continue
            for m in msgs:
                collected.append(
                    {
                        "subject": m.subject,
                        "body": json.loads(m.data.decode()),
                    }
                )
                await m.ack()
            if len(collected) >= 2:
                break
        return collected
    finally:
        await nc.drain()
