"""FastAPI application factory (composition root for the API process).

Wires concrete dependencies into the ingestion router, installs security
exception handlers (typed rejections → HTTP statuses), and exposes
``/healthz`` plus the Prometheus ``/metrics`` endpoint.

Import rules: api may import domain, application, config, observability.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool
from starlette.middleware.base import RequestResponseEndpoint

from itsm_agent.adapters.persistence.privileges import verify_runtime_database
from itsm_agent.api import security
from itsm_agent.api.auth import Authenticator
from itsm_agent.api.routes.findings import (
    DecisionsStore,
    EvidenceReferencesReader,
    FindingsDeps,
    FindingsReader,
)
from itsm_agent.api.routes.findings import (
    router as findings_router,
)
from itsm_agent.api.routes.ingestion import (
    IngestionDeps,
    IngestionSink,
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
    findings_repo: FindingsReader | None = None,
    review_decisions_repo: DecisionsStore | None = None,
    evidence_references_repo: EvidenceReferencesReader | None = None,
    authenticator: Authenticator | None = None,
    database_pool: AsyncConnectionPool[AsyncConnection] | None = None,
) -> FastAPI:
    """Build the API app with the given durable ingestion sink.

    When ``database_pool`` is supplied the startup hook asserts that the
    runtime role cannot bypass tenant RLS and fails closed otherwise.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if database_pool is not None:
            await verify_runtime_database(database_pool)
        yield

    app = FastAPI(
        title="ITSM Self-Healing Agent API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
                "Content-Security-Policy": (
                    "default-src 'none'; base-uri 'none'; "
                    "form-action 'none'; frame-ancestors 'none'"
                ),
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        return response

    # Dependencies live on the app instance, never in a module global. Two
    # independently composed apps therefore cannot share mutable configuration.
    app.state.ingestion_deps = IngestionDeps(
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
    app.include_router(ingestion_router)

    app.state.findings_deps = None
    if findings_repo is not None and review_decisions_repo is not None:
        # The router is always mounted when the stores are wired; requests fail
        # closed with 503 if no authenticator was supplied, so a misconfigured
        # deployment cannot silently serve an unauthenticated findings API.
        app.state.findings_deps = FindingsDeps(
            findings_repo=findings_repo,
            review_decisions_repo=review_decisions_repo,
            evidence_references_repo=evidence_references_repo,
            authenticator=authenticator,
        )
        app.include_router(findings_router)

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
