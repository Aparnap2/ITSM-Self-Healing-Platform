"""Event bus ports (Phase 3, pinned for this build).

NATS JetStream adapter contract (ADR-0002):
- at-least-once delivery; consumers MUST deduplicate,
- explicit ack; ack only after the durable transition commits,
- bounded redelivery (max_deliver), then dead-letter + escalation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class ConsumedMessage:
    """Typed view of a delivered broker message (no raw dicts across boundaries)."""

    __slots__ = (
        "subject",
        "payload",
        "headers",
        "delivery_attempt",
        "stream_sequence",
        "_nats_msg",
    )

    def __init__(
        self,
        *,
        subject: str,
        payload: bytes,
        headers: dict[str, str] | None,
        delivery_attempt: int,
        stream_sequence: int,
    ) -> None:
        self.subject = subject
        self.payload = payload
        self.headers = headers
        self.delivery_attempt = delivery_attempt
        self.stream_sequence = stream_sequence


class PublishResult:
    """Typed result of a broker publish."""

    __slots__ = ("stream", "sequence")

    def __init__(self, *, stream: str, sequence: int) -> None:
        self.stream = stream
        self.sequence = sequence


@runtime_checkable
class EventBusPublisher(Protocol):
    async def ensure_stream(self) -> None:
        """Idempotently create the durable stream (and DLQ stream)."""

    async def publish(
        self, subject: str, payload: bytes, *, headers: dict[str, str] | None = None
    ) -> PublishResult:
        """Publish and return only after broker acknowledgement."""


@runtime_checkable
class EventBusConsumer(Protocol):
    async def ensure_consumer(self) -> None:
        """Idempotently create the durable pull consumer with bounded
        redelivery (max_deliver) and explicit ack policy."""

    async def fetch(self, *, timeout_seconds: float, batch: int = 1) -> list[ConsumedMessage]:
        """Fetch up to ``batch`` messages; empty list on timeout."""

    async def ack(self, message: ConsumedMessage) -> None:
        """Acknowledge after the durable transition has committed."""

    async def nak(self, message: ConsumedMessage, *, delay_seconds: float = 0.0) -> None:
        """Negative-acknowledge for bounded redelivery."""

    async def dead_letter(self, message: ConsumedMessage, *, error: str) -> None:
        """Publish to the DLQ subject with an escalation event, then
        terminate redelivery for this message."""


class MessageHandler(Protocol):
    async def __call__(self, message: ConsumedMessage) -> None: ...
