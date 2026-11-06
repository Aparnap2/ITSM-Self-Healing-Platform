"""Unit tests for the API security-response headers.

Marker: ``unit``. These tests compose the real ``create_app`` factory with
in-memory fakes and assert the hardening headers are attached to every
response, including error responses. No network, PostgreSQL, or NATS.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from itsm_agent.api.app import create_app
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings

pytestmark = pytest.mark.unit

EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store, no-cache, must-revalidate, private",
    "content-security-policy": (
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}


class FakeSink:
    async def accept_incident(self, event: Any) -> SinkOutcome:
        return SinkOutcome.ACCEPTED


def _settings() -> Settings:
    return Settings.model_validate(
        {
            "env": "test",
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "webhook_secret": "test-webhook-secret-0123456789abcdef",
            "webhook_max_body_bytes": 2048,
            "rate_limit_requests": 100,
            "rate_limit_window_seconds": 60.0,
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )


def _app() -> FastAPI:
    return create_app(settings=_settings(), sink=FakeSink())


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test")


async def test_healthz_carries_hardening_headers() -> None:
    async with _client(_app()) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers[name] == value


async def test_error_response_carries_hardening_headers() -> None:
    # An unknown route exercises the 404 path through the middleware.
    async with _client(_app()) as client:
        response = await client.get("/does-not-exist")

    assert response.status_code == 404
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers[name] == value


async def test_rejected_webhook_carries_hardening_headers() -> None:
    # Missing HMAC signature must be rejected with 401, and the error response
    # must still carry the hardening headers.
    async with _client(_app()) as client:
        response = await client.post("/v1/incidents/webhook", json={})

    assert response.status_code == 401
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers[name] == value
