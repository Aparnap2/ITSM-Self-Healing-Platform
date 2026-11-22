# Runtime and Configuration v1.0

**Status:** H0 inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`

---

## 1. Process entrypoints

| Process | Command | Purpose | Health check |
|---------|---------|---------|-------------|
| API | `python -m itsm_agent.api` | HTTP service (port 8000) | `GET /healthz` → 200 |
| Audit consumer | `python -m itsm_agent.workers.audit_consumer` | Durable source event processing + investigation | Process health + durable consumer progress |
| Remediation consumer | `python -m itsm_agent.workers.consumer` | Remediation workflow processing | Process health + durable consumer progress |
| Outbox relay | `python -m itsm_agent.workers.relay` | PostgreSQL outbox → NATS | Process health + backlog |
| Retention scheduler | `python -m itsm_agent.workers.retention` | Erasure/retention scheduling | Process health |
| Identity simulator | `python -m itsm_agent.simulators.identity` | OIDC/JWT simulator | TLS + discovery |
| Provision reviewer | `python tools/provision_reviewer.py` | Reviewer directory provisioning | Exit code 0 |
| Demo readiness | `python tools/demo_readiness.py` | Staging readiness gate | Gate verdict |
| E2E rehearsal | `python tools/e2e_staging_run.py` | Full E2E rehearsal | Report + exit code |
| Demo capture | `python tools/demo_capture.py` | Evidence capture | Exit code 0 |

## 2. Configuration (typed, fail-fast)

Source: `src/itsm_agent/config.py` (`Settings` model, `load_settings()`).

All settings are validated by Pydantic v2 at startup. Missing required keys raise `ConfigError`.

### 2.1 Required environment variables

| Variable | Type | Description |
|----------|------|-------------|
| `ITSM_ENV` | `local\|test\|staging` | Environment identifier |
| `ITSM_WEBHOOK_SECRET` | str (min 16) | Webhook signature secret |
| `ITSM_MOCKOON_ITSM_BASE_URL` | URL | ITSM simulator base URL |
| `ITSM_MOCKOON_IDENTITY_BASE_URL` | URL | Identity simulator base URL |
| `ITSM_MOCKOON_INFRASTRUCTURE_BASE_URL` | URL | Infrastructure simulator base URL |

### 2.2 Optional with defaults

| Variable | Default | Description |
|----------|---------|-------------|
| `ITSM_API_HOST` | `127.0.0.1` | API bind host |
| `ITSM_API_PORT` | `8000` | API bind port |
| `ITSM_AUTH_MODE` | `hmac` | `hmac` or `oidc` (hmac refused in staging) |
| `ITSM_AUTH_HMAC_SECRET` | None | HMAC secret (min 16, required if hmac mode) |
| `ITSM_OIDC_ISSUER` | None | OIDC issuer URL |
| `ITSM_OIDC_AUDIENCE` | None | OIDC audience |
| `ITSM_OIDC_JWKS_URL` | None | JWKS endpoint URL |
| `ITSM_OIDC_JWKS_CA_FILE` | None | Pinned CA bundle for JWKS |
| `ITSM_OIDC_ALGORITHMS` | `RS256,ES256` | Allowed algorithms |
| `ITSM_OIDC_LEEWAY_SECONDS` | `30.0` | Token leeway |
| `ITSM_OIDC_MAX_TOKEN_AGE_SECONDS` | `3600.0` | Max token age |
| `ITSM_WEBHOOK_SIGNATURE_HEADER` | `x-itsm-signature` | Signature header name |
| `ITSM_WEBHOOK_MAX_BODY_BYTES` | `65536` | Max request body |
| `ITSM_RATE_LIMIT_REQUESTS` | `60` | Rate limit count |
| `ITSM_RATE_LIMIT_WINDOW_SECONDS` | `60.0` | Rate limit window |
| `ITSM_ADAPTER_TIMEOUT_SECONDS` | `5.0` | Adapter timeout |
| `ITSM_ADAPTER_MAX_RETRIES` | `2` | Adapter retries |
| `ITSM_GROQ_BASE_URL` | `https://api.groq.com/openai/v1` | Groq base URL |
| `ITSM_GROQ_MODEL` | `openai/gpt-oss-120b` | Groq model |
| `ITSM_GROQ_API_KEY` | None | Groq API key |
| `ITSM_GROQ_MAX_TOKENS` | `2000` | Max tokens |
| `ITSM_GROQ_TIMEOUT_SECONDS` | `30.0` | Groq timeout |
| `ITSM_INVESTIGATION_ENABLED` | `false` | Enable investigation stage |
| `ITSM_INVESTIGATION_MAX_MODEL_CALLS` | `2` | Max model calls per request |
| `ITSM_INVESTIGATION_MAX_TOOL_CALLS` | `5` | Max tool calls per request |
| `ITSM_INVESTIGATION_LLM_BUDGET_CALLS` | `3` | LLM budget (operator tooling) |
| `ITSM_OTEL_SERVICE_NAME` | `itsm-agent` | OTel service name |
| `ITSM_OTEL_EXPORTER_ENDPOINT` | None | OTLP endpoint (canonical) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | None | OTLP endpoint (fallback) |
| `ITSM_METRICS_ENABLED` | `true` | Enable metrics |
| `ITSM_SIMULATOR_SEED` | `42` | Simulator seed |

### 2.3 Database and messaging (env-level)

| Variable | Default | Description |
|----------|---------|-------------|
| `ITSM_POSTGRES_DSN` / `DATABASE_URL` | — | PostgreSQL DSN |
| `ITSM_NATS_URL` / `NATS_URL` | — | NATS server URL |
| `ITSM_NATS_MONITOR_URL` | `http://127.0.0.1:8223` | NATS monitor URL |
| `ITSM_API_BASE_URL` | — | API base URL |
| `ITSM_IDENTITY_BASE_URL` | — | Identity base URL |
| `ITSM_IDENTITY_CA_FILE` | — | Identity CA file |
| `ITSM_PROMETHEUS_URL` | — | Prometheus URL |

### 2.4 Docker Compose environment (.env)

See `tools/demo_env.py` for the full list of generated keys. Key groups: ports (DEMO_PORTS), static values (STATIC_VALUES), secrets (SECRET_KEYS), host URLs (derived).

### 2.5 Runtime roles

| Role | Purpose | Privileges |
|------|---------|-----------|
| `itsm` (admin/migration owner) | Migrations, test seeding | Superuser (test only) |
| `itsm_app` | Application runtime | Least-privilege: SELECT/INSERT on most tables, append-only restrictions, no UPDATE/DELETE/TRUNCATE on append-only tables, SELECT-only on reviewer_authorizations, SELECT+INSERT on tenants |
| `itsm_migrator` | Migration application (production) | Schema owner, migration DDL |

## 3. Runtime service topology

### 3.1 Compose services

| Service | Image/Build | Ports | Health check | Purpose |
|---------|------------|-------|-------------|---------|
| postgres | postgres:16 | 5432 | pg_isready | Durable state |
| nats | nats:2.12.10-alpine | 4222, 8222 | /jsz | JetStream |
| demo-init | (init) | — | completed | Migration/seed |
| identity | (build) | 8443 | TLS + discovery | OIDC simulator |
| migrate | (build) | — | completed | Migrations |
| mockoon | mockoon/cli | 3001 | HTTP | API simulators |
| otel-collector | otel/collector | 4317, 4318 | — | Telemetry |
| prometheus | prom/prometheus | 9090 | /-/healthy | Metrics |
| api | (build) | 8000 | /healthz | Application API |
| worker | (build) | — | — | Remediation consumer |
| relay | (build) | — | — | Outbox relay |
| retention | (build) | — | — | Retention scheduler |
| localstack | localstack | 4566 | — | Optional AWS sim |

### 3.2 Health check endpoints

| Service | Endpoint | Expected |
|---------|----------|----------|
| API | `GET /healthz` | 200 |
| NATS | `GET /jsz` (monitor port 8222) | streams ≥ 1, durable consumer present |
| PostgreSQL | `pg_isready` | accepting connections |
| Prometheus | `GET /-/healthy` | 200 |
| Mockoon | `GET /health` | 200 |
| Identity | `GET /.well-known/openid-configuration` | 200 (TLS) |

## 4. Dockerfile

- `Dockerfile` — main application image (Python, uv, dependencies, `--no-dev` image fix applied)
- `Dockerfile.mockoon` — Mockoon simulator image (if present)

## 5. Makefile targets

See `Makefile` for full list. Key groups:

- **Verification:** `verify`, `verify-ci`, `verify-fast`, `format`, `format-check`, `lint`, `typecheck`, `sast`
- **Testing:** `test-unit`, `test-contract`, `test-security`, `test-fault-injection`, `test-integration`, `test-scenarios`, `test-e2e`, `test`
- **Demo:** `demo-env`, `demo-up`, `demo-verify`, `demo-run`, `demo-evidence`, `demo-evidence-run`, `demo-worker-restart`, `demo-down`, `demo-reset`
- **Compose:** `compose-up`, `compose-down`, `compose-reset`
- **CI local:** `act-ci`, `verify-pre-push`, `hooks-install`