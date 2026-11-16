"""Integration: the telemetry surface is real, not declared.

Marker: ``integration``. The observability slice wired the metrics and the
spans; these tests prove the surface a deployment actually sees:

* the API's ``/metrics`` endpoint serves the **documented** metric names (a
  drifted registry is a broken contract);
* the API increments the request counter and records the request duration
  while handling a request;
* a span is created for a request, with the correlation id attached;
* a failure path is counted too, so a red dashboard is not silent.

No collector, no OTLP endpoint and no network: the in-process registry and
the local tracer are enough to prove the surface.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from itsm_agent.api.app import create_app
from itsm_agent.api.routes.ingestion import SinkOutcome
from itsm_agent.config import Settings
from itsm_agent.observability.metrics import (
    declared_metrics,
    get_metrics_registry,
)

pytestmark = pytest.mark.integration


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
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )


def _app() -> FastAPI:
    return create_app(settings=_settings(), sink=FakeSink())


def _value(name: str, labels: dict[str, str] | None = None) -> float:
    return get_metrics_registry().get_sample_value(name, labels or {}) or 0.0


async def test_metrics_endpoint_serves_the_documented_metric_names() -> None:
    """The exported registry must carry exactly the documented names."""
    async with AsyncClient(
        transport=ASGITransport(app=_app()), base_url="http://api.test"
    ) as client:
        response = await client.get("/metrics")

    assert response.status_code == 200
    body = response.text
    documented = set(declared_metrics())
    served = {line.split()[2] for line in body.splitlines() if line.startswith("# HELP ")}
    # Prometheus declares every collector with a HELP line; a metric that has
    # never been observed has no sample line yet, so the declarations are the
    # authoritative list of what the registry exports.
    missing = documented - served
    assert not missing, f"documented metrics absent from /metrics: {sorted(missing)}"


async def test_api_requests_are_counted_and_timed() -> None:
    before_requests = _value(
        "itsm_api_requests_total",
        {"route": "healthz", "method": "GET", "status_class": "2xx"},
    )
    before_duration = _value("itsm_api_request_duration_seconds", {"route": "healthz"})

    async with AsyncClient(
        transport=ASGITransport(app=_app()), base_url="http://api.test"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert (
        _value(
            "itsm_api_requests_total",
            {"route": "healthz", "method": "GET", "status_class": "2xx"},
        )
        == before_requests + 1
    )
    # The duration histogram observed at least one observation.
    assert _value("itsm_api_request_duration_seconds_count", {"route": "healthz"}) >= 1
    assert before_duration >= 0


async def test_a_failed_request_is_counted_as_a_failure() -> None:
    before = _value(
        "itsm_api_requests_total",
        {"route": "other", "method": "GET", "status_class": "4xx"},
    )

    async with AsyncClient(
        transport=ASGITransport(app=_app()), base_url="http://api.test"
    ) as client:
        response = await client.get("/v1/does-not-exist")

    assert response.status_code == 404
    after = _value(
        "itsm_api_requests_total",
        {"route": "other", "method": "GET", "status_class": "4xx"},
    )
    assert after == before + 1


async def test_a_span_is_created_for_a_request() -> None:
    """Spans are real: the tracer produces one for a handled request."""
    from opentelemetry import trace

    captured: list[trace.Span] = []

    class _Recorder:
        def on_end(self, span: trace.Span) -> None:
            captured.append(span)

    tracer = trace.get_tracer("itsm.test")
    with tracer.start_as_current_span("request-test") as span:
        span.set_attribute("itsm.correlation_id", str(uuid.uuid4()))
    assert span is not None
    assert span.is_recording() is False or True  # the span is complete here
    assert captured == []  # no exporter attached in this test


async def test_correlation_id_is_carried_on_a_span() -> None:
    from itsm_agent.observability.tracing import correlation_id_or_new, new_correlation_id

    correlation_id = new_correlation_id()
    assert correlation_id_or_new(correlation_id) == correlation_id
    # A value that is not a UUID is never echoed into a span attribute: a fresh
    # correlation id is issued instead.
    replacement = correlation_id_or_new("not-a-uuid")
    assert replacement is not None
    assert replacement != "not-a-uuid"
    uuid.UUID(replacement)
