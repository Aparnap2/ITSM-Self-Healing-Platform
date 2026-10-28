"""FR-01 ingestion endpoint: webhook event acceptance.

Flow (durable-acceptance-first):
1. Enforce payload size limit (before parsing).
2. Verify HMAC-SHA256 signature over the raw body (constant-time).
3. Rate-limit by client key.
4. Parse + validate with the domain ``IncidentCreated`` contract
   (``extra="forbid"``) — ticket text is data, never instructions.
5. Assign/confirm correlation ID and idempotency key
   ``(source_system, external_event_id)``.
6. Hand the validated event to the injected ``IngestionSink`` (the
   durable inbox/outbox layer owned by the persistence agent). Only a
   sink commit produces ``202 accepted``.

Distinct responses: 202 accepted / 200 duplicate / 422 invalid /
503 temporarily unavailable. Security rejections map to 401/413/429.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Protocol

from fastapi import APIRouter, Request, Response
from pydantic import ValidationError

from itsm_agent.api import security
from itsm_agent.domain.events import IncidentCreated

router = APIRouter(prefix="/v1/incidents", tags=["ingestion"])


class SinkOutcome(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    UNAVAILABLE = "UNAVAILABLE"


class IngestionSink(Protocol):
    """Durable acceptance boundary; implemented by the persistence layer.

    Implementations must commit durably (inbox row) before returning
    ACCEPTED, and deduplicate on (source_system, external_event_id).
    """

    async def accept_incident(self, event: IncidentCreated) -> SinkOutcome:
        """Persist the event; return ACCEPTED, DUPLICATE, or UNAVAILABLE."""
        ...


class IngestionDeps:
    """Wired dependencies for the ingestion router (composition root)."""

    def __init__(
        self,
        *,
        sink: IngestionSink,
        webhook_secret: str,
        signature_header: str,
        max_body_bytes: int,
        rate_limiter: security.SlidingWindowRateLimiter,
        replay_cache: security.ReplayCache,
    ) -> None:
        self.sink = sink
        self.webhook_secret = webhook_secret
        self.signature_header = signature_header
        self.max_body_bytes = max_body_bytes
        self.rate_limiter = rate_limiter
        self.replay_cache = replay_cache


_deps: IngestionDeps | None = None


def configure_ingestion(deps: IngestionDeps) -> None:
    """Install dependencies (called once by the app factory)."""
    global _deps
    _deps = deps


def _get_deps() -> IngestionDeps:
    if _deps is None:
        raise RuntimeError("Ingestion router not configured")
    return _deps


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@router.post("/webhook")
async def ingest_incident_webhook(request: Request) -> Response:
    """Accept a signed incident webhook; ack only after durable commit."""
    deps = _get_deps()
    body = await request.body()

    # 1. Size limit before any parsing.
    if len(body) > deps.max_body_bytes:
        raise security.PayloadTooLargeError(deps.max_body_bytes)

    # 2. Signature verification (constant-time) + replay detection.
    provided = request.headers.get(deps.signature_header)
    security.verify_signature(
        secret=deps.webhook_secret,
        body=body,
        provided=provided,
        max_body_bytes=deps.max_body_bytes,
    )
    assert provided is not None  # verify_signature raises otherwise
    if not deps.replay_cache.check_and_record(provided.strip().lower()):
        raise security.ReplayedSignatureError()

    # 3. Rate limit per client.
    deps.rate_limiter.check(_client_key(request))

    # 4. Strict schema validation (extra="forbid").
    try:
        raw = json.loads(body)
        if not isinstance(raw, dict):
            raise security.SecurityRejection("INVALID_JSON", "Body must be a JSON object")
        event = IncidentCreated.model_validate(raw)
    except security.SecurityRejection:
        raise
    except (ValueError, ValidationError) as exc:
        raise security.SecurityRejection(
            "INVALID_PAYLOAD", f"Payload failed validation: {type(exc).__name__}"
        ) from exc

    # 5/6. Durable acceptance via the injected sink.
    outcome = await deps.sink.accept_incident(event)
    if outcome is SinkOutcome.ACCEPTED:
        return Response(
            content=(
                '{{"status": "accepted", "correlation_id": "{}", "idempotency_key": "{}"}}'.format(
                    event.correlation_id, f"{event.source_system}:{event.external_event_id}"
                )
            ),
            status_code=202,
            media_type="application/json",
        )
    if outcome is SinkOutcome.DUPLICATE:
        return Response(
            content=(
                '{{"status": "duplicate", "idempotency_key": "{}"}}'.format(
                    f"{event.source_system}:{event.external_event_id}"
                )
            ),
            status_code=200,
            media_type="application/json",
        )
    # UNAVAILABLE — sink could not durably commit; do NOT ack.
    return Response(
        content='{"status": "unavailable", "detail": "durable acceptance failed"}',
        status_code=503,
        media_type="application/json",
    )


__all__ = [
    "IngestionDeps",
    "IngestionSink",
    "SinkOutcome",
    "configure_ingestion",
    "ingest_incident_webhook",
    "router",
]
