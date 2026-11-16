"""Prometheus metrics for the ITSM agent.

One module-owned registry backs the API ``/metrics`` endpoint and the tests,
so a scrape and a test always observe the same series.

Every metric is declared in :data:`METRIC_SPECS` and documented in
``docs/observability.md``. ``tests/unit/test_observability.py`` fails when the
two lists drift apart, so the documentation can never silently fall behind the
code.

Cardinality policy: a label value must come from a closed, bounded vocabulary
(route templates, HTTP methods, status classes, outcome names, severities).
Tenant ids, reviewer ids, subject names, finding ids, event ids and
correlation ids are unbounded and are therefore never used as labels.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

MetricKind = Literal["counter", "gauge", "histogram"]


@dataclass(frozen=True)
class MetricSpec:
    """Declarative description of one exported metric."""

    name: str
    kind: MetricKind
    documentation: str
    labels: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()


#: Every metric this process exports. The order is stable so the generated
#: documentation and the drift guard read the same way.
METRIC_SPECS: tuple[MetricSpec, ...] = (
    MetricSpec(
        "itsm_queue_depth",
        "gauge",
        "Depth of a bounded work queue (outbox rows pending, JetStream messages pending)",
        ("queue",),
    ),
    MetricSpec(
        "itsm_outbox_backlog",
        "gauge",
        "Outbox rows that are still pending publication to the broker",
    ),
    MetricSpec(
        "itsm_outbox_published_total",
        "counter",
        "Outbox rows published to the broker, by outcome",
        ("outcome",),
    ),
    MetricSpec(
        "itsm_consumer_messages_total",
        "counter",
        "Broker messages handled by a consumer, by bounded outcome",
        ("outcome",),
    ),
    MetricSpec(
        "itsm_event_age_seconds",
        "histogram",
        "Age of a broker message at the moment it was delivered to the consumer",
        buckets=(1, 5, 15, 60, 300, 900, 3600),
    ),
    MetricSpec(
        "itsm_consumer_lag_seconds",
        "gauge",
        "Delivery lag of the most recently delivered broker message",
    ),
    MetricSpec(
        "itsm_batch_size",
        "gauge",
        "Number of messages in the most recent broker fetch",
    ),
    MetricSpec(
        "itsm_adapter_retries_total",
        "counter",
        "Bounded adapter retry attempts",
        ("adapter", "outcome"),
    ),
    MetricSpec(
        "itsm_retry_total",
        "counter",
        "Bounded redelivery or republish retries",
        ("stage",),
    ),
    MetricSpec(
        "itsm_dlq_total",
        "counter",
        "Messages dead-lettered after bounded redelivery was exhausted",
        ("reason",),
    ),
    MetricSpec(
        "itsm_tool_errors_total",
        "counter",
        "Tool and adapter errors by bounded result code",
        ("adapter", "result_code"),
    ),
    MetricSpec(
        "itsm_ingestion_events_total",
        "counter",
        "Ingestion webhook outcomes",
        ("outcome",),
    ),
    MetricSpec(
        "itsm_api_requests_total",
        "counter",
        "API requests handled, by route template, method and status class",
        ("route", "method", "status_class"),
    ),
    MetricSpec(
        "itsm_api_request_duration_seconds",
        "histogram",
        "API request handling duration",
        ("route",),
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    ),
    MetricSpec(
        "itsm_batch_processing_seconds",
        "histogram",
        "Duration of one consume-and-process cycle",
        ("outcome",),
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    ),
    MetricSpec(
        "itsm_workflow_duration_seconds",
        "histogram",
        "End-to-end remediation workflow duration",
        ("outcome",),
        buckets=(0.5, 1, 5, 15, 60, 300, 900),
    ),
    MetricSpec(
        "itsm_audit_events_total",
        "counter",
        "Source audit events handled by the detection consumer",
        ("outcome",),
    ),
    MetricSpec(
        "itsm_detection_findings_total",
        "counter",
        "Findings produced by deterministic detection",
        ("severity",),
    ),
    MetricSpec(
        "itsm_reviewer_transitions_total",
        "counter",
        "Reviewer lifecycle transitions applied or refused",
        ("outcome",),
    ),
    MetricSpec(
        "itsm_investigation_total",
        "counter",
        "Bounded agentic investigations by stage outcome",
        ("outcome",),
    ),
    MetricSpec(
        "itsm_investigation_latency_seconds",
        "histogram",
        "Duration of a bounded agentic investigation",
        ("outcome",),
        buckets=(0.5, 1, 2.5, 5, 10, 30, 60, 120),
    ),
    MetricSpec(
        "itsm_investigation_model_calls_total",
        "counter",
        "Model invocations made by the bounded agentic investigation stage",
    ),
)

_registry: CollectorRegistry | None = None
_collectors: dict[str, Counter | Gauge | Histogram] = {}


def exposed_name(spec: MetricSpec) -> str:
    """The name Prometheus publishes for this metric.

    ``prometheus_client`` strips a trailing ``_total`` from a counter name and
    re-appends it when the metric is rendered, so the published name of a
    counter always ends in ``_total``.
    """
    if spec.kind == "counter" and not spec.name.endswith("_total"):
        return f"{spec.name}_total"
    return spec.name


def declared_metrics() -> dict[str, MetricSpec]:
    """Published metric name -> its declaration, for the documentation guard."""
    return {exposed_name(spec): spec for spec in METRIC_SPECS}


def _build(spec: MetricSpec, registry: CollectorRegistry) -> Counter | Gauge | Histogram:
    if spec.kind == "counter":
        return Counter(spec.name, spec.documentation, spec.labels, registry=registry)
    if spec.kind == "gauge":
        return Gauge(spec.name, spec.documentation, spec.labels, registry=registry)
    return Histogram(
        spec.name,
        spec.documentation,
        spec.labels,
        buckets=spec.buckets,
        registry=registry,
    )


def get_metrics_registry() -> CollectorRegistry:
    """Return the process-wide metrics registry, initializing on first use."""
    global _registry
    if _registry is not None:
        return _registry

    _registry = CollectorRegistry()
    for spec in METRIC_SPECS:
        _collectors[spec.name] = _build(spec, _registry)
    return _registry


def _counter(name: str) -> Counter:
    collector = _collectors.get(name)
    if not isinstance(collector, Counter):
        raise LookupError(f"{name} is not a declared counter")
    return collector


def _gauge(name: str) -> Gauge:
    collector = _collectors.get(name)
    if not isinstance(collector, Gauge):
        raise LookupError(f"{name} is not a declared gauge")
    return collector


def _histogram(name: str) -> Histogram:
    collector = _collectors.get(name)
    if not isinstance(collector, Histogram):
        raise LookupError(f"{name} is not a declared histogram")
    return collector


def observe_queue_depth(queue: str, depth: int) -> None:
    """Record the current depth of a named work queue."""
    get_metrics_registry()
    _gauge("itsm_queue_depth").labels(queue=queue).set(depth)


def observe_outbox_backlog(pending: int) -> None:
    """Record the number of outbox rows still waiting for publication."""
    get_metrics_registry()
    _gauge("itsm_outbox_backlog").set(pending)


def observe_outbox_published(outcome: str) -> None:
    """Record one outbox publication attempt outcome."""
    get_metrics_registry()
    _counter("itsm_outbox_published_total").labels(outcome=outcome).inc()


def observe_consumer_message(outcome: str) -> None:
    """Record one broker message handled by a consumer."""
    get_metrics_registry()
    _counter("itsm_consumer_messages_total").labels(outcome=outcome).inc()


def observe_event_age(seconds: float) -> None:
    """Record the age of a message at delivery."""
    get_metrics_registry()
    _histogram("itsm_event_age_seconds").observe(seconds)


def observe_consumer_lag(seconds: float) -> None:
    """Record the delivery lag of the most recent message."""
    get_metrics_registry()
    _gauge("itsm_consumer_lag_seconds").set(seconds)


def observe_batch_size(size: int) -> None:
    """Record the size of the most recent broker fetch."""
    get_metrics_registry()
    _gauge("itsm_batch_size").set(size)


def observe_adapter_retry(adapter: str, outcome: str) -> None:
    """Record one bounded adapter retry attempt."""
    get_metrics_registry()
    _counter("itsm_adapter_retries_total").labels(adapter=adapter, outcome=outcome).inc()


def observe_retry(stage: str) -> None:
    """Record one bounded redelivery or republish retry."""
    get_metrics_registry()
    _counter("itsm_retry_total").labels(stage=stage).inc()


def observe_dead_letter(reason: str) -> None:
    """Record one message dead-lettered after bounded redelivery."""
    get_metrics_registry()
    _counter("itsm_dlq_total").labels(reason=reason).inc()


def observe_tool_error(adapter: str, result_code: str) -> None:
    """Record one tool or adapter error."""
    get_metrics_registry()
    _counter("itsm_tool_errors_total").labels(adapter=adapter, result_code=result_code).inc()


def observe_ingestion_event(outcome: str) -> None:
    """Record one ingestion webhook outcome."""
    get_metrics_registry()
    _counter("itsm_ingestion_events_total").labels(outcome=outcome).inc()


def observe_api_request(route: str, method: str, status_class: str, seconds: float) -> None:
    """Record one handled API request and its duration."""
    get_metrics_registry()
    _counter("itsm_api_requests_total").labels(
        route=route, method=method, status_class=status_class
    ).inc()
    _histogram("itsm_api_request_duration_seconds").labels(route=route).observe(seconds)


def observe_batch_processing(outcome: str, seconds: float) -> None:
    """Record the duration of one consume-and-process cycle."""
    get_metrics_registry()
    _histogram("itsm_batch_processing_seconds").labels(outcome=outcome).observe(seconds)


def observe_workflow_duration(outcome: str, seconds: float) -> None:
    """Record the duration of one remediation workflow run."""
    get_metrics_registry()
    _histogram("itsm_workflow_duration_seconds").labels(outcome=outcome).observe(seconds)


def observe_audit_event(outcome: str) -> None:
    """Record one source audit event handled by the detection consumer."""
    get_metrics_registry()
    _counter("itsm_audit_events_total").labels(outcome=outcome).inc()


def observe_detection_finding(severity: str) -> None:
    """Record one finding produced by deterministic detection."""
    get_metrics_registry()
    _counter("itsm_detection_findings_total").labels(severity=severity).inc()


def observe_reviewer_transition(outcome: str) -> None:
    """Record one reviewer lifecycle transition."""
    get_metrics_registry()
    _counter("itsm_reviewer_transitions_total").labels(outcome=outcome).inc()


def observe_investigation(outcome: str) -> None:
    """Record one investigation stage transition (``started``/``completed``/...)."""
    get_metrics_registry()
    _counter("itsm_investigation_total").labels(outcome=outcome).inc()


def observe_investigation_latency(outcome: str, seconds: float) -> None:
    """Record the duration of one bounded investigation."""
    get_metrics_registry()
    _histogram("itsm_investigation_latency_seconds").labels(outcome=outcome).observe(seconds)


def observe_model_call() -> None:
    """Record one model invocation made by the investigation stage."""
    get_metrics_registry()
    _counter("itsm_investigation_model_calls_total").inc()


__all__ = [
    "METRIC_SPECS",
    "MetricKind",
    "MetricSpec",
    "declared_metrics",
    "exposed_name",
    "get_metrics_registry",
    "observe_adapter_retry",
    "observe_api_request",
    "observe_audit_event",
    "observe_batch_processing",
    "observe_batch_size",
    "observe_consumer_lag",
    "observe_consumer_message",
    "observe_dead_letter",
    "observe_detection_finding",
    "observe_event_age",
    "observe_ingestion_event",
    "observe_investigation",
    "observe_investigation_latency",
    "observe_model_call",
    "observe_outbox_backlog",
    "observe_outbox_published",
    "observe_queue_depth",
    "observe_retry",
    "observe_reviewer_transition",
    "observe_tool_error",
    "observe_workflow_duration",
]
