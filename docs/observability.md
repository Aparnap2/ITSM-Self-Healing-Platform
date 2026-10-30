# Observability (Task 16)

## Structured logging

- structlog only; no print/console.log in committed code.

## OpenTelemetry

- Traces: ingestion, detection, investigation, verification.
- Metrics: itsm_audit_events_total, itsm_detection_findings_total, itsm_batch_size,
  itsm_batch_processing_seconds, itsm_outbox_backlog, itsm_consumer_lag,
  itsm_retry_total, itsm_dlq_total, itsm_investigation_latency_seconds,
  itsm_investigation_tokens_total.

## Health and readiness

- /healthz endpoint (existing) returns liveness.
- Readiness: DB + NATS connectivity (to be wired).

## Known limitations

- Full OTel wiring is incremental; metric names are targets.
