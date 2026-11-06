"""Prometheus metrics for the ITSM agent.

Single module-owned registry so the /metrics endpoint and tests read the
same counters/gauges. Metric set per task scope: queue depth, event age,
retries, workflow duration, tool errors, approval wait, unresolved count.
"""

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

_registry: CollectorRegistry | None = None

_queue_depth: Gauge
_event_age_seconds: Histogram
_adapter_retries: Counter
_workflow_duration_seconds: Histogram
_tool_errors: Counter
_approval_wait_seconds: Histogram
_unresolved_incidents: Gauge
_ingestion_events: Counter


def get_metrics_registry() -> CollectorRegistry:
    """Return the process-wide metrics registry, initializing on first use."""
    global _registry
    if _registry is not None:
        return _registry

    _registry = CollectorRegistry()
    global _queue_depth, _event_age_seconds, _adapter_retries
    global _workflow_duration_seconds, _tool_errors, _approval_wait_seconds
    global _unresolved_incidents, _ingestion_events

    _queue_depth = Gauge(
        "itsm_queue_depth",
        "Current depth of the pending event queue",
        ["queue"],
        registry=_registry,
    )
    _event_age_seconds = Histogram(
        "itsm_event_age_seconds",
        "Age of events between creation and processing",
        buckets=(1, 5, 15, 60, 300, 900, 3600),
        registry=_registry,
    )
    _adapter_retries = Counter(
        "itsm_adapter_retries_total",
        "Bounded adapter retry attempts",
        ["adapter", "outcome"],
        registry=_registry,
    )
    _workflow_duration_seconds = Histogram(
        "itsm_workflow_duration_seconds",
        "End-to-end workflow duration",
        ["outcome"],
        buckets=(0.5, 1, 5, 15, 60, 300, 900),
        registry=_registry,
    )
    _tool_errors = Counter(
        "itsm_tool_errors_total",
        "Tool/adapter errors by code",
        ["adapter", "result_code"],
        registry=_registry,
    )
    _approval_wait_seconds = Histogram(
        "itsm_approval_wait_seconds",
        "Time incidents spend waiting for human approval",
        buckets=(1, 10, 60, 300, 900, 3600, 21600),
        registry=_registry,
    )
    _unresolved_incidents = Gauge(
        "itsm_unresolved_incidents",
        "Current count of unresolved incidents",
        registry=_registry,
    )
    _ingestion_events = Counter(
        "itsm_ingestion_events_total",
        "Ingestion webhook outcomes",
        ["outcome"],
        registry=_registry,
    )
    return _registry


def observe_queue_depth(queue: str, depth: int) -> None:
    get_metrics_registry()
    _queue_depth.labels(queue=queue).set(depth)


def observe_event_age(seconds: float) -> None:
    get_metrics_registry()
    _event_age_seconds.observe(seconds)


def observe_adapter_retry(adapter: str, outcome: str) -> None:
    get_metrics_registry()
    _adapter_retries.labels(adapter=adapter, outcome=outcome).inc()


def observe_workflow_duration(outcome: str, seconds: float) -> None:
    get_metrics_registry()
    _workflow_duration_seconds.labels(outcome=outcome).observe(seconds)


def observe_tool_error(adapter: str, result_code: str) -> None:
    get_metrics_registry()
    _tool_errors.labels(adapter=adapter, result_code=result_code).inc()


def observe_approval_wait(seconds: float) -> None:
    get_metrics_registry()
    _approval_wait_seconds.observe(seconds)


def set_unresolved_incidents(count: int) -> None:
    get_metrics_registry()
    _unresolved_incidents.set(count)


def observe_ingestion_event(outcome: str) -> None:
    get_metrics_registry()
    _ingestion_events.labels(outcome=outcome).inc()


__all__ = [
    "get_metrics_registry",
    "observe_adapter_retry",
    "observe_approval_wait",
    "observe_event_age",
    "observe_ingestion_event",
    "observe_queue_depth",
    "observe_tool_error",
    "observe_workflow_duration",
    "set_unresolved_incidents",
]
