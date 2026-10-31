"""OpenTelemetry tracer provider setup and correlation-ID propagation.

Correlation IDs travel in the ``itsm.correlation_id`` span attribute and
in the ``x-correlation-id`` header for outbound adapter calls. The
provider is idempotent: repeated setup calls are no-ops.
"""

from __future__ import annotations

import logging
import uuid

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
        setup_tracing(service_name="itsm-agent")
    return trace.get_tracer(name)


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
    "attach_correlation_id",
    "correlation_headers",
    "get_tracer",
    "new_correlation_id",
    "setup_tracing",
]
