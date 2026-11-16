"""OpenTelemetry tracer provider setup and correlation-ID propagation.

Correlation IDs travel in the ``itsm.correlation_id`` span attribute and
in the ``x-correlation-id`` header for outbound adapter calls. The
provider is idempotent: repeated setup calls are no-ops.

Exporter endpoint resolution
----------------------------
The canonical variable is ``ITSM_OTEL_EXPORTER_ENDPOINT`` (it matches the
rest of the ``ITSM_*`` configuration namespace). The OpenTelemetry standard
name ``OTEL_EXPORTER_OTLP_ENDPOINT`` is accepted as a fallback so a
deployment that only sets the standard variable still exports traces. The
same precedence is implemented in ``itsm_agent.config``; the two are kept in
step by a unit test.
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Mapping

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

logger = logging.getLogger(__name__)

CORRELATION_ID_ATTRIBUTE = "itsm.correlation_id"
CORRELATION_ID_HEADER = "x-correlation-id"

#: Canonical exporter endpoint variable.
EXPORTER_ENDPOINT_ENV = "ITSM_OTEL_EXPORTER_ENDPOINT"

#: OpenTelemetry standard exporter endpoint variable, accepted as a fallback.
OTLP_ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"

#: Default tracer name used by the platform's entrypoints.
TRACER_NAME = "itsm-agent"

_provider: TracerProvider | None = None


class _NoopExporter(SpanExporter):
    """In-memory discard exporter (default when no endpoint configured)."""

    def export(self, spans: object) -> SpanExportResult:
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def setup_tracing(
    *,
    service_name: str,
    exporter_endpoint: str | None = None,
) -> TracerProvider:
    """Configure the global TracerProvider once; return it."""
    global _provider
    if _provider is not None:
        return _provider
    _provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    if exporter_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            _provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=exporter_endpoint))
            )
        except Exception:  # pragma: no cover - optional dependency path
            logger.warning("OTLP exporter unavailable; tracing stays local-only")
    else:
        _provider.add_span_processor(BatchSpanProcessor(_NoopExporter()))
    trace.set_tracer_provider(_provider)
    return _provider


def get_tracer(name: str) -> trace.Tracer:
    """Return a tracer; sets up a local-only provider if none configured."""
    if _provider is None:
        setup_tracing(service_name=TRACER_NAME)
    return trace.get_tracer(name)


def resolve_exporter_endpoint(env: Mapping[str, str] | None = None) -> str | None:
    """Resolve the OTLP endpoint from the environment.

    ``ITSM_OTEL_EXPORTER_ENDPOINT`` wins; ``OTEL_EXPORTER_OTLP_ENDPOINT`` is
    the accepted fallback. Returns ``None`` when neither is set, which keeps
    the exporter local-only (spans are produced, nothing is shipped).
    """
    source = env if env is not None else os.environ
    value = source.get(EXPORTER_ENDPOINT_ENV) or source.get(OTLP_ENDPOINT_ENV)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def correlation_id_or_new(value: str | None) -> str:
    """Return ``value`` when it is a UUID, otherwise a fresh correlation ID.

    A correlation ID arriving from a client is untrusted input, so it is
    only echoed into a span attribute when it parses as a UUID.
    """
    if value:
        try:
            return str(uuid.UUID(value.strip()))
        except (ValueError, AttributeError):
            logger.debug("ignoring a malformed correlation id header")
    return new_correlation_id()


def new_correlation_id() -> str:
    """Generate a new correlation ID (UUID4 string)."""
    return str(uuid.uuid4())


def attach_correlation_id(span: trace.Span, correlation_id: str) -> None:
    """Stamp the correlation ID onto a span."""
    span.set_attribute(CORRELATION_ID_ATTRIBUTE, correlation_id)


def correlation_headers(correlation_id: str) -> dict[str, str]:
    """Outbound headers carrying the correlation ID."""
    return {CORRELATION_ID_HEADER: correlation_id}


__all__ = [
    "CORRELATION_ID_ATTRIBUTE",
    "CORRELATION_ID_HEADER",
    "EXPORTER_ENDPOINT_ENV",
    "OTLP_ENDPOINT_ENV",
    "TRACER_NAME",
    "attach_correlation_id",
    "correlation_headers",
    "correlation_id_or_new",
    "get_tracer",
    "new_correlation_id",
    "resolve_exporter_endpoint",
    "setup_tracing",
]
