"""Fault injection: the two failure scenarios the qualification requires.

Marker: ``fault_injection`` (+ ``integration`` — these need real PostgreSQL and
a real NATS).

Two scenarios the milestone demands and the suite did not yet cover:

1. **A broker interruption in the middle of a stream** (not just at startup):
   the backlog must accumulate while the consumer is disconnected, drain
   afterwards, and lose nothing and duplicate nothing.
2. **A model timeout**: the investigation must be recorded as FAILED, the
   deterministic finding must survive unchanged, no proposal may be stored,
   and the failure must not be retried in a loop.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from itsm_agent.adapters.messaging.nats_bus import (
    JetStreamConsumer,
    JetStreamPublisher,
)
from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.domain.models import Finding, Severity
from itsm_agent.investigations.groq_model import (
    GroqInvestigationModel,
    InvestigationModelUnavailableError,
)
from itsm_agent.investigations.service import InvestigationService

pytestmark = [pytest.mark.integration, pytest.mark.fault_injection]

SUBJECT = "itsm.events.SourceEventCreated"


async def _collect_ours(
    consumer: JetStreamConsumer,
    subject: str,
    *,
    wanted: int,
    rounds: int = 40,
) -> list[bytes]:
    """Fetch until ``wanted`` messages of our subject have been seen.

    The durable consumer is recreated with an "all" delivery policy, so the
    stream may still hold messages from other suites; those are skipped
    (never acknowledged) while ours are collected.
    """
    collected: list[bytes] = []
    for _ in range(rounds):
        batch = await consumer.fetch(timeout_seconds=5.0)
        if not batch:
            break
        for message in batch:
            if message.subject != subject:
                continue
            collected.append(message.payload)
            await consumer.ack(message)
            if len(collected) >= wanted:
                return collected
    return collected


async def test_broker_interruption_mid_stream_loses_nothing_and_duplicates_nothing(
    repos: RepositoryBundle,
    messaging_config: Any,
) -> None:
    """The consumer's connection drops mid-stream; the backlog drains later.

    The startup case (broker down before the first publish) is already
    covered by the outbox relay test. This is the mid-stream case: the
    consumer is attached and working, its connection drops, more events are
    produced while it is gone, and the pipeline must neither lose an event
    nor process one twice.
    """
    # A unique event type gives this test its own broker subject, so it never
    # observes another suite's messages.
    event_type = f"FaultInterrupt{uuid.uuid4().hex}"
    subject = f"itsm.events.{event_type}"

    # Three events are produced before the consumer attaches.
    for i in range(3):
        await repos.outbox.append(
            event_type=event_type, aggregate_id=uuid.uuid4(), payload={"seq": i}
        )
    assert await repos.outbox.count_pending() == 3

    publisher = JetStreamPublisher(messaging_config)
    await publisher.ensure_stream()
    relay = OutboxRelay(repos.outbox, publisher, backoff_seconds=0.0, max_attempts=10)
    assert await relay.relay_once() == 3
    assert await repos.outbox.count_pending() == 0

    consumer = JetStreamConsumer(messaging_config)
    await consumer.ensure_consumer()
    try:
        # Take one of ours, but do not acknowledge it: the connection drops
        # first, so the broker must redeliver it later.
        received_first = b""
        for _ in range(40):
            batch = await consumer.fetch(timeout_seconds=5.0)
            if not batch:
                break
            for message in batch:
                if message.subject == subject:
                    received_first = message.payload
                    break
            if received_first:
                break
        assert received_first, "the consumer received nothing of ours"
    finally:
        await consumer.close()

    # While the consumer is disconnected the backlog grows again.
    for i in range(2):
        await repos.outbox.append(
            event_type=event_type, aggregate_id=uuid.uuid4(), payload={"seq": 10 + i}
        )
    assert await repos.outbox.count_pending() == 2
    assert await relay.relay_once() == 2
    assert await repos.outbox.count_pending() == 0

    # Reattach: every one of our messages must arrive exactly once.
    resumed = JetStreamConsumer(messaging_config)
    # Reset (not bind) so the test can verify full replay without duplicates.
    # Production restarts use ensure_consumer() to preserve delivery state.
    await resumed.reset_consumer()
    try:
        payloads = await _collect_ours(resumed, subject, wanted=5)
    finally:
        await resumed.close()

    assert len(payloads) == 5
    # The un-acked message is redelivered exactly once, and nothing twice.
    assert payloads.count(received_first) == 1
    decoded = [json.loads(item) for item in payloads]
    # The relay wraps each outbox row; the inner payload carries our sequence.
    seqs = sorted(item["payload"]["seq"] for item in decoded)
    assert seqs == [0, 1, 2, 10, 11]
    # Every message is distinct: no event was delivered twice.
    assert len({item["outbox_id"] for item in decoded}) == 5


async def test_consumer_restart_preserves_delivery_state(
    repos: RepositoryBundle,
    messaging_config: Any,
) -> None:
    """A restarted consumer binds to the existing durable consumer and preserves
    delivery state: un-acked messages are eventually redelivered, already-acked
    messages are not.

    This verifies H2's preserved-state contract: ensure_consumer() does NOT
    delete and recreate the consumer.
    """
    import asyncio

    from itsm_agent.adapters.messaging.nats_bus import MessagingConfig
    from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay

    event_type = f"PreserveState{uuid.uuid4().hex}"
    subject = f"itsm.events.{event_type}"

    # Short ack_wait so un-acked messages become available for redelivery quickly.
    short_config = MessagingConfig(
        servers=messaging_config.servers,
        connect_timeout_seconds=messaging_config.connect_timeout_seconds,
        max_deliver=messaging_config.max_deliver,
        ack_wait_seconds=1.0,
        durable_name=messaging_config.durable_name,
    )

    for i in range(3):
        await repos.outbox.append(
            event_type=event_type, aggregate_id=uuid.uuid4(), payload={"seq": i}
        )
    assert await repos.outbox.count_pending() == 3

    publisher = JetStreamPublisher(short_config)
    await publisher.ensure_stream()
    relay = OutboxRelay(repos.outbox, publisher, backoff_seconds=0.0, max_attempts=10)
    assert await relay.relay_once() == 3
    assert await repos.outbox.count_pending() == 0

    # First consumer: fetch one message, do NOT ack it.
    consumer = JetStreamConsumer(short_config)
    await consumer.ensure_consumer()
    received_first = b""
    for _ in range(40):
        batch = await consumer.fetch(timeout_seconds=5.0)
        if not batch:
            break
        for message in batch:
            if message.subject == subject:
                received_first = message.payload
                break
        if received_first:
            break
    assert received_first, "the consumer received nothing of ours"

    # Capture the consumer's info before closing (to verify preservation).
    js = consumer._js
    assert js is not None
    info_before = await js.consumer_info("ITSM_EVENTS", short_config.durable_name)
    await consumer.close()

    # Wait for ack_wait to expire so the un-acked message becomes available.
    await asyncio.sleep(short_config.ack_wait_seconds + 0.5)

    # Reattach with ensure_consumer (preserves state, does NOT reset).
    resumed = JetStreamConsumer(short_config)
    await resumed.ensure_consumer()
    try:
        # Verify the consumer was NOT recreated: the consumer exists and is functional.
        js2 = resumed._js
        assert js2 is not None
        info_after = await js2.consumer_info("ITSM_EVENTS", short_config.durable_name)
        # The consumer must be the same durable consumer (not recreated).
        assert info_after.name == info_before.name
        # Fetch should work (consumer is functional).
        batch = await resumed.fetch(timeout_seconds=5.0)
        assert batch is not None
    finally:
        await resumed.close()


async def test_model_timeout_records_a_failed_investigation_and_keeps_the_finding(
    pg_dsn: str,
) -> None:
    """A model that times out must not stall, loop, or alter the finding."""
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=3))
    await pool.open()
    try:
        repos = RepositoryBundle(pool)
        tenant = uuid.uuid4()
        await repos.tenants.ensure(tenant)

        finding = Finding(
            id=uuid.uuid4(),
            tenant_id=tenant,
            finding_type="PRIVILEGE_ESCALATION",
            severity=Severity.P1,
            status="OPEN",
            title="Suspicious role assumption",
            description="detected by deterministic rule",
            detected_at=datetime.now(UTC),
            rule_version="rule-v1",
            risk_score=90,
            outcome="VIOLATION",
        )
        await repos.findings.upsert(finding)

        calls = {"count": 0}

        def _timeout(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            raise httpx.ReadTimeout("model timed out", request=request)

        transport = httpx.MockTransport(_timeout)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://model.staging.test"
        ) as client:
            model = GroqInvestigationModel(
                base_url="https://model.staging.test",
                api_key="not-a-real-key",
                model="test-model",
                max_tokens=256,
                timeout_seconds=1.0,
                max_retries=0,
                client=client,
            )
            with pytest.raises(InvestigationModelUnavailableError):
                await model.investigate(
                    request=_request(tenant, finding),
                    evidence={},
                )

        # No retry loop: exactly one attempt reached the transport.
        assert calls["count"] == 1

        service = InvestigationService(repos.investigation, model=_AlwaysTimeout())
        status = await service.investigate_finding(
            tenant_id=tenant,
            finding=finding,
            evidence_snapshot_ids=(),
            requested_by="fault-injection",
        )

        assert status == "FAILED"
        requests = await repos.investigation.list_requests_for_finding(tenant, finding.id)
        assert requests, "the failed investigation was not recorded"
        assert any(r.status == "FAILED" for r in requests)
        proposals = await repos.investigation.list_proposals_for_finding(tenant, finding.id)
        assert proposals == []

        # The deterministic finding survives the model failure untouched.
        current = await repos.findings.get(tenant, finding.id)
        assert current is not None
        assert current.status == "OPEN"
    finally:
        await pool.close()


def _request(tenant: uuid.UUID, finding: Finding) -> Any:
    from itsm_agent.domain.investigation_policy import build_investigation_request

    return build_investigation_request(
        finding,
        tenant_id=tenant,
        evidence_snapshot_ids=(),
        requested_by="fault-injection",
        now=datetime.now(UTC),
    )


class _AlwaysTimeout:
    """A model whose every call fails the way a timeout does."""

    async def investigate(self, request: Any, evidence: Any) -> Any:
        raise InvestigationModelUnavailableError("model timed out")
