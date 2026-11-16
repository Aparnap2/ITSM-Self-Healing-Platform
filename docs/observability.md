# Observability

The platform exports Prometheus metrics from a module-owned registry and
OpenTelemetry traces through the configured OTLP endpoint. This document is
the contract: **the metric names below are the ones the code declares**, and
a test fails the build if the two ever diverge.

## Structured logging

- structlog only; no print/console.log in committed code.

## Prometheus metrics

The API serves the registry on `GET /metrics` (`src/itsm_agent/api/app.py`).
Every metric is declared once, in `src/itsm_agent/observability/metrics.py`
(`METRIC_SPECS`), with a bounded label set — no metric is labelled with a
tenant id, a subject, a finding id or any other unbounded value, so the
series count stays bounded.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `itsm_queue_depth` | gauge | queue | Depth of a bounded work queue (outbox rows pending, JetStream messages pending) |
| `itsm_outbox_backlog` | gauge | - | Outbox rows that are still pending publication to the broker |
| `itsm_outbox_published_total` | counter | outcome | Outbox rows published to the broker, by outcome |
| `itsm_consumer_messages_total` | counter | outcome | Broker messages handled by a consumer, by bounded outcome |
| `itsm_event_age_seconds` | histogram | - | Age of a broker message at the moment it was delivered to the consumer |
| `itsm_consumer_lag_seconds` | gauge | - | Delivery lag of the most recently delivered broker message |
| `itsm_batch_size` | gauge | - | Number of messages in the most recent broker fetch |
| `itsm_adapter_retries_total` | counter | adapter, outcome | Bounded adapter retry attempts |
| `itsm_retry_total` | counter | stage | Bounded redelivery or republish retries |
| `itsm_dlq_total` | counter | reason | Messages dead-lettered after bounded redelivery was exhausted |
| `itsm_tool_errors_total` | counter | adapter, result_code | Tool and adapter errors by bounded result code |
| `itsm_ingestion_events_total` | counter | outcome | Ingestion webhook outcomes |
| `itsm_api_requests_total` | counter | route, method, status_class | API requests handled, by route template, method and status class |
| `itsm_api_request_duration_seconds` | histogram | route | API request handling duration |
| `itsm_batch_processing_seconds` | histogram | outcome | Duration of one consume-and-process cycle |
| `itsm_workflow_duration_seconds` | histogram | outcome | End-to-end remediation workflow duration |
| `itsm_audit_events_total` | counter | outcome | Source audit events handled by the detection consumer |
| `itsm_detection_findings_total` | counter | severity | Findings produced by deterministic detection |
| `itsm_reviewer_transitions_total` | counter | outcome | Reviewer lifecycle transitions applied or refused |
| `itsm_investigation_total` | counter | outcome | Bounded agentic investigations by stage outcome |
| `itsm_investigation_latency_seconds` | histogram | outcome | Duration of a bounded agentic investigation |
| `itsm_investigation_model_calls_total` | counter | - | Model invocations made by the bounded agentic investigation stage |

The `route` label is a **bounded route template**, not a raw path
(`src/itsm_agent/observability/http_boundary.py`): unknown paths collapse to
`other`, so a new endpoint cannot silently widen the label space.

## OpenTelemetry

- Spans cover ingestion, detection, investigation, reviewer transitions and
  the worker consume loops (`src/itsm_agent/observability/tracing.py`).
- The exporter endpoint is read from `ITSM_OTEL_EXPORTER_ENDPOINT` (the
  canonical name) and falls back to the OpenTelemetry standard
  `OTEL_EXPORTER_OTLP_ENDPOINT`. Compose sets the standard name, so both
  sides agree (`src/itsm_agent/config.py`).
- Tracing is opt-in: with no endpoint configured the spans are not exported,
  and the platform still runs.

## Prometheus scrape

`observability/prometheus/prometheus.yml` scrapes:

- `prometheus` (self), `otel-collector:8888` and `otel-collector:8889`;
- `api:8000` — the API's own `/metrics` endpoint.

The worker processes (audit consumer, remediation worker, outbox relay,
retention scheduler) have **no HTTP listener**: they are not web servers and
no exporter is mounted into them, so there is deliberately no `worker` scrape
job. Their counters reach Prometheus through the OTLP path.

## Health and readiness

- `/healthz` returns liveness.
- Readiness (database and broker connectivity) is not wired yet; see the
  limitations below.

## Known limitations

- Readiness probes do not yet check database or broker connectivity.
- Metric names are asserted against the documentation by a test
  (`tests/unit/test_observability.py`), but there is no alert rule set: the
  metrics are exported and scraped, not acted upon.
- Traces are exported only when an OTLP endpoint is configured; the local
  stack's collector is wired for the API and the workers, but no trace
  retention or sampling policy is defined.
