"""FastAPI application factory (composition root for the API process).

Wires concrete dependencies into the ingestion router, installs security
exception handlers (typed rejections → HTTP statuses), and exposes
``/healthz`` plus the Prometheus ``/metrics`` endpoint.

Import rules: api may import domain, application, config, observability.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from itsm_agent.api import security
from itsm_agent.api.routes.ingestion import (
    IngestionDeps,
    IngestionSink,
    configure_ingestion,
)
from itsm_agent.api.routes.ingestion import (
    router as ingestion_router,
)
from itsm_agent.config import Settings
from itsm_agent.observability.metrics import get_metrics_registry


def create_app(
    *,
    settings: Settings,
    sink: IngestionSink,
) -> FastAPI:
    """Build the API app with the given durable ingestion sink."""
    app = FastAPI(
        title="ITSM Self-Healing Agent API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    configure_ingestion(
        IngestionDeps(
            sink=sink,
            webhook_secret=settings.webhook_secret,
            signature_header=settings.webhook_signature_header,
            max_body_bytes=settings.webhook_max_body_bytes,
            rate_limiter=security.SlidingWindowRateLimiter(
                max_requests=settings.rate_limit_requests,
                window_seconds=settings.rate_limit_window_seconds,
            ),
            replay_cache=security.ReplayCache(),
        )
    )
    app.include_router(ingestion_router)

    @app.exception_handler(security.SecurityRejection)
    async def security_rejection_handler(
        request: Request, exc: security.SecurityRejection
    ) -> Response:
        status_by_code: dict[str, int] = {
            "MISSING_SIGNATURE": 401,
            "INVALID_SIGNATURE": 401,
            "REPLAYED_SIGNATURE": 401,
            "PAYLOAD_TOO_LARGE": 413,
            "RATE_LIMITED": 429,
            "INVALID_JSON": 422,
            "INVALID_PAYLOAD": 422,
        }
        status = status_by_code.get(exc.code, 400)
        headers = {}
        if isinstance(exc, security.RateLimitExceededError):
            headers = {"retry-after": str(exc.retry_after_seconds)}
        body = f'{{"error": "{exc.code}", "detail": "{exc.message}"}}'
        return Response(
            content=body, status_code=status, media_type="application/json", headers=headers
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "env": settings.env}

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        if not settings.metrics_enabled:
            return PlainTextResponse("metrics disabled", status_code=404)
        registry = get_metrics_registry()
        return PlainTextResponse(
            generate_latest(registry).decode("utf-8"),
            media_type=CONTENT_TYPE_LATEST,
        )

    return app


__all__ = ["create_app"]
