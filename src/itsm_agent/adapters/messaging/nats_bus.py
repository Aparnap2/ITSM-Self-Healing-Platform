"""NATS JetStream publisher/consumer (Phase 3, ADR-0002).

Topology:
- Stream ``ITSM_EVENTS`` subjects ``itsm.events.>`` — WorkQueue retention,
  explicit acks. A single durable consumer drains it; WorkQueue retention
  removes a message once acked, keeping the stream bounded.
- Stream ``ITSM_DLQ`` subjects ``itsm.dlq.>`` — limits retention; holds
  dead-lettered payloads plus escalation events after bounded redelivery
  (max_deliver) is exhausted.

Delivery semantics: at-least-once. Consumers must deduplicate; ack only
after the durable transition commits.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import uuid4

import nats
from nats.aio.client import Client as NatsClient
from nats.aio.msg import Msg
from nats.js import JetStreamContext
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy, RetentionPolicy, StreamConfig
from nats.js.errors import Error as JsError
from nats.js.errors import NotFoundError

from itsm_agent.observability.metrics import (
    observe_adapter_retry,
    observe_batch_size,
    observe_consumer_lag,
    observe_consumer_message,
    observe_dead_letter,
    observe_event_age,
    observe_queue_depth,
    observe_retry,
    observe_tool_error,
)
from itsm_agent.ports.event_bus import ConsumedMessage, PublishResult

logger = logging.getLogger(__name__)

EVENT_STREAM = "ITSM_EVENTS"
DLQ_STREAM = "ITSM_DLQ"
EVENT_SUBJECT_PREFIX = "itsm.events."
DLQ_SUBJECT = "itsm.dlq.events"
ESCALATION_SUBJECT = "itsm.dlq.escalation"
DEFAULT_MAX_DELIVER = 5

#: Label value for the messaging adapter in the adapter-scoped metrics.
MESSAGING_ADAPTER = "messaging"

#: Bounded reasons a message reaches the dead-letter stream.
DLQ_REASON_REDELIVERY_EXHAUSTED = "redelivery_exhausted"
DLQ_REASON_POISON = "poison"
DLQ_REASON_HANDLER_ERROR = "handler_error"


@dataclass(frozen=True)
class MessagingConfig:
    servers: tuple[str, ...]
    connect_timeout_seconds: float = 3.0
    max_deliver: int = DEFAULT_MAX_DELIVER
    ack_wait_seconds: float = 30.0
    durable_name: str = "itsm-workflow"


class JetStreamPublisher:
    """Publishes to JetStream; returns only after broker ack."""

    def __init__(self, config: MessagingConfig) -> None:
        self._config = config
        self._nc: NatsClient | None = None
        self._js: JetStreamContext | None = None

    async def connect(self) -> None:
        if self._nc is None:
            self._nc = await asyncio.wait_for(
                nats.connect(
                    servers=list(self._config.servers),
                    connect_timeout=self._config.connect_timeout_seconds,
                    max_reconnect_attempts=0,
                    reconnect_time_wait=0.1,
                ),
                timeout=self._config.connect_timeout_seconds + 1.0,
            )
            self._js = self._nc.jetstream()

    async def close(self) -> None:
        if self._nc is not None and self._nc.is_closed is False:
            await self._nc.drain()
        self._nc = None
        self._js = None

    @property
    def is_connected(self) -> bool:
        return self._nc is not None and self._nc.is_connected

    async def ensure_stream(self) -> None:
        await self.connect()
        js = self._js
        assert js is not None
        await _ensure_stream(
            js,
            StreamConfig(
                name=EVENT_STREAM,
                subjects=[f"{EVENT_SUBJECT_PREFIX}>"],
                retention=RetentionPolicy.WORK_QUEUE,
            ),
        )
        await _ensure_stream(
            js,
            StreamConfig(
                name=DLQ_STREAM,
                subjects=["itsm.dlq.>"],
                retention=RetentionPolicy.LIMITS,
            ),
        )

    async def publish(
        self, subject: str, payload: bytes, *, headers: dict[str, str] | None = None
    ) -> PublishResult:
        await self.connect()
        js = self._js
        assert js is not None
        try:
            ack = await js.publish(subject, payload, headers=headers)
        except Exception:
            # The broker rejected or the connection failed: the caller decides
            # whether to retry, the adapter only records the failure.
            observe_tool_error(MESSAGING_ADAPTER, "publish_failed")
            raise
        return PublishResult(stream=ack.stream, sequence=ack.seq)


class JetStreamConsumer:
    """Durable pull consumer with bounded redelivery and DLQ path."""

    def __init__(self, config: MessagingConfig, subject: str = f"{EVENT_SUBJECT_PREFIX}>") -> None:
        self._config = config
        self._subject = subject
        self._nc: NatsClient | None = None
        self._js: JetStreamContext | None = None
        self._sub: JetStreamContext.PullSubscription | None = None

    async def connect(self) -> None:
        if self._nc is None:
            self._nc = await asyncio.wait_for(
                nats.connect(
                    servers=list(self._config.servers),
                    connect_timeout=self._config.connect_timeout_seconds,
                    max_reconnect_attempts=0,
                    reconnect_time_wait=0.1,
                ),
                timeout=self._config.connect_timeout_seconds + 1.0,
            )
            self._js = self._nc.jetstream()

    async def close(self) -> None:
        if self._nc is not None and self._nc.is_closed is False:
            await self._nc.drain()
        self._nc = None
        self._js = None
        self._sub = None

    async def ensure_consumer(self) -> None:
        """Idempotent get-or-create of the durable consumer.

        If the consumer already exists, bind to it WITHOUT resetting delivery
        state (preserves retry counts and redelivery history). If it does not
        exist, create it with the configured policy.

        This is safe to call on every worker startup: a restarted worker
        binds to the existing durable consumer instead of wiping its state.
        """
        await self.connect()
        js = self._js
        assert js is not None

        # Check whether the durable consumer already exists.
        exists = False
        try:
            await js.consumer_info(EVENT_STREAM, self._config.durable_name)
            exists = True
        except NotFoundError:
            exists = False

        if exists:
            # Bind to the existing consumer; do NOT override its config or
            # reset delivery state.
            logger.info(
                "binding to existing durable consumer %s (delivery state preserved)",
                self._config.durable_name,
            )
            self._sub = await js.pull_subscribe(
                self._subject,
                durable=self._config.durable_name,
            )
        else:
            # Create a new consumer with the configured policy.
            logger.info(
                "creating durable consumer %s (deliver_policy=ALL)",
                self._config.durable_name,
            )
            self._sub = await js.pull_subscribe(
                self._subject,
                durable=self._config.durable_name,
                config=ConsumerConfig(
                    durable_name=self._config.durable_name,
                    deliver_policy=DeliverPolicy.ALL,
                    ack_policy=AckPolicy.EXPLICIT,
                    max_deliver=self._config.max_deliver,
                    ack_wait=self._config.ack_wait_seconds,
                ),
            )

    async def reset_consumer(self) -> None:
        """Explicitly delete and recreate the durable consumer.

        This RESETS delivery state (redelivery counts, pending messages).
        Use ONLY in controlled test/reset scenarios — never in production
        startup. Prefer ``ensure_consumer()`` for idempotent startup.
        """
        await self.connect()
        js = self._js
        assert js is not None
        with contextlib.suppress(NotFoundError):
            await js.delete_consumer(EVENT_STREAM, self._config.durable_name)
        self._sub = await js.pull_subscribe(
            self._subject,
            durable=self._config.durable_name,
            config=ConsumerConfig(
                durable_name=self._config.durable_name,
                deliver_policy=DeliverPolicy.ALL,
                ack_policy=AckPolicy.EXPLICIT,
                max_deliver=self._config.max_deliver,
                ack_wait=self._config.ack_wait_seconds,
            ),
        )

    async def fetch(self, *, timeout_seconds: float, batch: int = 1) -> list[ConsumedMessage]:
        if self._sub is None:
            raise RuntimeError("consumer not started: call ensure_consumer() first")
        try:
            msgs = await self._sub.fetch(batch, timeout=timeout_seconds)
        except TimeoutError:
            observe_batch_size(0)
            return []
        observe_batch_size(len(msgs))
        self._observe_delivery(msgs)
        return [_to_consumed(m) for m in msgs]

    def _observe_delivery(self, msgs: list[Msg]) -> None:
        """Record the age, the lag and the remaining depth of a delivery.

        The broker timestamp is the age of the message when it reached this
        consumer; the pending count is the depth the durable consumer still
        has to drain. Neither is a tenant, subject or record identifier.
        """
        if not msgs:
            return
        now = datetime.now(UTC)
        lag = 0.0
        for msg in msgs:
            age = max(0.0, (now - msg.metadata.timestamp).total_seconds())
            observe_event_age(age)
            lag = max(lag, age)
        observe_consumer_lag(lag)
        observe_queue_depth("nats", msgs[0].metadata.num_pending)

    async def ack(self, message: ConsumedMessage) -> None:
        await _raw(message).ack()

    async def nak(self, message: ConsumedMessage, *, delay_seconds: float = 0.0) -> None:
        await _raw(message).nak(delay=delay_seconds)
        observe_retry("consume")
        observe_adapter_retry(MESSAGING_ADAPTER, "redelivered")

    async def dead_letter(
        self,
        message: ConsumedMessage,
        *,
        error: str,
        reason: str = DLQ_REASON_REDELIVERY_EXHAUSTED,
    ) -> None:
        """Publish the failed message + escalation event to the DLQ stream,
        then terminate redelivery for this message.

        ``reason`` is a bounded label (never the error text) so the exported
        series stay small; ``error`` is only written to the dead-letter
        payload.
        """
        await self.connect()
        js = self._js
        assert js is not None
        dlq_payload = json.dumps(
            {
                "original_subject": message.subject,
                "delivery_attempt": message.delivery_attempt,
                "error": error[:2000],
                "payload": message.payload.decode("utf-8", errors="replace"),
            }
        ).encode()
        await js.publish(DLQ_SUBJECT, dlq_payload)
        await js.publish(
            ESCALATION_SUBJECT,
            json.dumps(
                {
                    "event_type": "ESCALATION",
                    "reason": "REDELIVERY_EXHAUSTED",
                    "original_subject": message.subject,
                    "error": error[:2000],
                }
            ).encode(),
        )
        await _raw(message).term()
        observe_dead_letter(reason)


def _raw(message: ConsumedMessage) -> Msg:
    raw = getattr(message, "_nats_msg", None)
    if raw is None:
        raise RuntimeError("ConsumedMessage has no bound NATS message")
    return cast("Msg", raw)


def _to_consumed(msg: Msg) -> ConsumedMessage:
    metadata = msg.metadata
    consumed = ConsumedMessage(
        subject=msg.subject,
        payload=msg.data,
        headers=dict(msg.headers) if msg.headers else None,
        delivery_attempt=metadata.num_delivered,
        stream_sequence=metadata.sequence.stream,
    )
    setattr(consumed, "_nats_msg", msg)  # noqa: B010 - adapter-internal binding
    return consumed


async def _ensure_stream(js: JetStreamContext, config: StreamConfig) -> None:
    try:
        await js.add_stream(config)
    except JsError:
        # Stream exists; align config (idempotent ensure).
        await js.update_stream(config)


def new_message_id() -> str:
    return uuid4().hex


class DispatchOutcome(StrEnum):
    NONE = "NONE"
    PROCESSED = "PROCESSED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    DEAD_LETTERED = "DEAD_LETTERED"


async def dispatch_once(
    consumer: JetStreamConsumer,
    handler: Callable[[ConsumedMessage], Awaitable[None]],
    *,
    max_deliver: int = DEFAULT_MAX_DELIVER,
    timeout_seconds: float = 1.0,
    retry_delay_seconds: float = 0.05,
) -> DispatchOutcome:
    """Fetch one message and run the bounded-redelivery decision:

    - handler success -> ack (only after the handler's durable work committed),
    - handler failure before exhaustion -> nak (bounded redelivery),
    - handler failure at max_deliver -> dead-letter + escalation, then term.

    Handlers MUST be idempotent: redelivery after a crash between the
    durable transition and the ack is guaranteed by at-least-once delivery.
    """
    msgs = await consumer.fetch(timeout_seconds=timeout_seconds, batch=1)
    if not msgs:
        return DispatchOutcome.NONE
    message = msgs[0]
    try:
        await handler(message)
    except Exception as exc:
        if message.delivery_attempt >= max_deliver:
            logger.error(
                "redelivery exhausted subject=%s attempt=%s: %s",
                message.subject,
                message.delivery_attempt,
                exc,
            )
            await consumer.dead_letter(message, error=str(exc), reason=DLQ_REASON_HANDLER_ERROR)
            observe_consumer_message("dead_lettered")
            return DispatchOutcome.DEAD_LETTERED
        await consumer.nak(message, delay_seconds=retry_delay_seconds)
        observe_consumer_message("redelivered")
        return DispatchOutcome.RETRY_SCHEDULED
    else:
        await consumer.ack(message)
        observe_consumer_message("processed")
        return DispatchOutcome.PROCESSED
