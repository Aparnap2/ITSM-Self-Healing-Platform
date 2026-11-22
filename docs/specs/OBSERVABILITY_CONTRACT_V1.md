# Observability Contract v1.0

**Status:** H0 inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`

---

## 1. Layers

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Metrics | Prometheus | Quantitative health and performance |
| Logs | Structured JSON | Event-level diagnosis |
| Traces | OpenTelemetry | Cross-service execution path |
| Dashboards | Grafana | Human operational visibility |
| CI reports | GitHub Actions | Qualification and failure evidence |

## 2. Required metrics

### 2.1 API metrics

| Metric | Type | Description |
|--------|------|-------------|
| `itsm_api_requests_total` | Counter | Request count (method, route, status_class) |
| `itsm_api_request_duration_seconds` | Histogram | Request latency |
| `itsm_ingestion_events_total` | Counter | Ingestion webhook outcomes |

### 2.2 Consumer/messaging metrics

| Metric | Type | Description |
|--------|------|-------------|
| `itsm_consumer_messages_total` | Counter | Consumer message outcomes |
| `itsm_consumer_lag_seconds` | Gauge | Consumer lag |
| `itsm_batch_size` | Histogram | Batch size |
| `itsm_event_age_seconds` | Histogram | Event age |
| `itsm_outbox_backlog` | Gauge | Pending outbox rows |
| `itsm_outbox_oldest_pending_age` | Gauge | Oldest pending outbox age |

### 2.3 Investigation metrics

| Metric | Type | Description |
|--------|------|-------------|
| `itsm_investigation_model_calls_total` | Counter | Model call count |
| `itsm_investigation_model_calls_created` | Counter | Model call creation |

### 2.4 Review metrics

| Metric | Type | Description |
|--------|------|-------------|
| `itsm_reviewer_transitions_total` | Counter | Reviewer transition count |
| `itsm_reviewer_transitions_created` | Counter | Transition creation |

### 2.5 Runtime metrics

| Metric | Type | Description |
|--------|------|-------------|
| `itsm_batch_size` | Histogram | Processing batch size |

### 2.6 Metric label policy

- Use bounded labels only (operation, status, job, method, route, status_class).
- Do NOT use event IDs, user IDs, raw evidence references, tenant-specific secrets, or high-cardinality dimensions as labels.
- Use controlled identifiers and keep sensitive dimensions out of metric labels.

## 3. Structured logging

Required JSON fields:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 UTC |
| `level` | DEBUG/INFO/WARNING/ERROR |
| `service` | Service name |
| `environment` | Environment identifier |
| `run_id` | Staging run ID (where applicable) |
| `trace_id` | OpenTelemetry trace ID |
| `span_id` | OpenTelemetry span ID |
| `event_id` | Event ID (where safe) |
| `tenant_id` | Tenant ID (where policy permits) |
| `operation` | Operation name |
| `duration_ms` | Duration in milliseconds |
| `error_code` | Classified error code |
| `retry_count` | Retry count |

Do not log: secrets, authentication tokens, raw source payloads, unredacted sensitive evidence.

## 4. Distributed tracing

### 4.1 Required trace propagation

```
API ingestion → database transaction → outbox relay → NATS → consumer → detection → investigation → evidence persistence → reviewer decision
```

### 4.2 Required spans

- `ingestion.webhook` — webhook receipt and validation
- `ingestion.persist` — source event + outbox persistence
- `outbox.relay` — outbox polling and NATS publish
- `messaging.publish` — NATS publish
- `messaging.consume` — NATS consume
- `detection.evaluate` — detection rule evaluation
- `investigation.run` — investigation stage
- `evidence.persist` — evidence reference persistence
- `reviewer.transition` — reviewer lifecycle transition

### 4.3 Trace validation

- Collector startup is NOT proof of telemetry.
- Assert that actual expected spans arrive with correct parent-child relationships.
- Missing required spans → qualification FAIL.

## 5. Dashboards (8 required)

1. Platform overview
2. API health
3. Database health
4. Outbox and messaging
5. Consumer processing
6. Detection and investigation
7. Reviewer lifecycle
8. Resilience and fault tests

## 6. Alerts (11 required)

| Alert | Severity | Condition |
|-------|----------|-----------|
| API unavailable | Critical | `/healthz` non-200 for > 30s |
| PostgreSQL unavailable | Critical | Connection failure |
| NATS unavailable | Critical | NATS connection failure |
| Durable consumer missing | Critical | Durable consumer not found in /jsz |
| Outbox backlog above threshold | Warning | Pending rows > threshold |
| Oldest pending outbox exceeds threshold | Warning | Oldest pending age > threshold |
| Consumer repeatedly failing | Critical | Error rate > threshold |
| DLQ count increases | Warning | DLQ message count increases |
| Investigation provider unavailable | Warning | Provider timeout/error rate |
| Telemetry pipeline unavailable | Warning | Collector unreachable |
| Required trace spans missing | Warning | Expected spans not found |

Thresholds must be defined in configuration and validated during staging. Do not choose arbitrary production SLOs based on a short demo run.

## 7. Telemetry surface (verified)

Integration test: `tests/integration/test_telemetry_surface.py` (57 contract tests).

OTLP collector: `otel-collector` service (ports 4317 gRPC, 4318 HTTP).
Prometheus scrape targets: `api`, `otel-collector`, `otel-exported-app-metrics`, `prometheus`.

## 8. Known gaps

- Real OTLP trace-content assertion: missing (metrics asserted, traces not).
- Trace propagation across all services: partially implemented.
- Alert thresholds: not yet defined in configuration.
- Grafana dashboards: not yet provisioned as code.