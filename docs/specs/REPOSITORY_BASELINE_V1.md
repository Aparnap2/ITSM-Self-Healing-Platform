# Repository Baseline v1.0 (H0)

**Status:** H0 in progress — read-only inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`
**H1 SHA (PR #30, unmerged):** `1064551`
**Date:** 2026-11-22

---

## 1. Application inventory

### 1.1 Python modules (src/itsm_agent/)

| Module | Purpose | Key types/functions |
|--------|---------|-------------------|
| `adapters/http.py` | HTTP client wrapper | HTTP client with timeout |
| `adapters/identity/mockoon_identity.py` | Identity adapter (Mockoon) | Mockoon identity client |
| `adapters/infrastructure/mockoon_infra.py` | Infrastructure adapter (Mockoon) | Mockoon infra client |
| `adapters/itsm/mockoon_itsm.py` | ITSM adapter (Mockoon) | Mockoon ITSM client |
| `adapters/llm/groq.py` | Groq LLM adapter | GroqInvestigationModel |
| `adapters/messaging/nats_bus.py` | NATS JetStream bus | JetStreamPublisher, JetStreamConsumer, MessagingConfig |
| `adapters/messaging/outbox_relay.py` | Outbox relay | OutboxRelay |
| `adapters/persistence/audit_port.py` | Audit port | PsycopgAuditPort |
| `adapters/persistence/ingestion_sink.py` | Ingestion sink | PsycopgIngestionSink |
| `adapters/persistence/migrations.py` | Migration applier | apply_migrations |
| `adapters/persistence/pool.py` | Connection pool | create_pool, PersistenceConfig |
| `adapters/persistence/privileges.py` | Runtime safety checks | assert_runtime_database_safety, verify_runtime_database, APPEND_ONLY_TABLES |
| `adapters/persistence/repositories.py` | Repository bundle | RepositoryBundle, Psycopg*Repository classes |
| `adapters/persistence/reviewer_admin.py` | Reviewer provisioning | provision_reviewer |
| `adapters/persistence/tenant.py` | Tenant repository | PsycopgTenantRepository |
| `adapters/persistence/workflow_intents.py` | Workflow intent store | WorkflowIntentStore |
| `api/app.py` | FastAPI application | create_app |
| `api/auth.py` | Authentication | OIDC/HMAC auth |
| `api/oidc.py` | OIDC relying party | JWKS fetching, token validation |
| `api/rbac.py` | Role-based access control | Permission enum, authorization |
| `api/routes/findings.py` | Findings API routes | CRUD, transitions, bundle |
| `api/routes/ingestion.py` | Ingestion API routes | Webhook ingestion |
| `api/security.py` | Security headers/middleware | Security middleware |
| `application/audit_consumer.py` | Audit consumer logic | consume_source_event |
| `application/commands.py` | Workflow commands | WorkflowDeps, ExecutionLimits |
| `application/nodes.py` | LangGraph nodes | Workflow nodes |
| `application/replay.py` | Replay logic | Replay functions |
| `application/services.py` | Application services | Service classes |
| `application/worker.py` | Remediation worker | consume_one |
| `application/workflow.py` | Workflow orchestration | Workflow orchestration |
| `collectors/aws/cloudtrail.py` | CloudTrail collector | CloudTrail normalization |
| `collectors/github/audit_log.py` | GitHub audit collector | GitHub audit normalization |
| `collectors/postgresql/pgaudit.py` | PostgreSQL audit collector | PgAudit normalization |
| `config.py` | Typed configuration | Settings, load_settings |
| `detection/engine.py` | Detection engine | Deterministic detection rules |
| `domain/errors.py` | Domain errors | Error types |
| `domain/events.py` | Domain events | Event models |
| `domain/finding_lifecycle.py` | Finding lifecycle | FindingStatus, transitions |
| `domain/identity_resolution.py` | Identity resolution | Identity mapping |
| `domain/investigation_policy.py` | Investigation policy | Policy constants |
| `domain/models.py` | Domain models | Finding, EvidenceReference, ReviewDecision, etc. |
| `domain/policies.py` | Policy matrix | default_policy_snapshot |
| `domain/tenancy.py` | Tenancy domain | Tenant logic |
| `domain/transitions.py` | Transition logic | Transition validation |
| `investigations/groq_model.py` | Groq model adapter | GroqInvestigationModel |
| `investigations/orchestrator.py` | Investigation orchestrator | Orchestration logic |
| `investigations/service.py` | Investigation service | InvestigationService |
| `observability/http_boundary.py` | HTTP boundary observability | Boundary tracing |
| `observability/metrics.py` | Prometheus metrics | Metric definitions |
| `observability/tracing.py` | OpenTelemetry tracing | Tracing setup |
| `ports/*.py` | Port interfaces | Abstract interfaces |
| `privacy/redaction.py` | Redaction | Secret redaction |
| `privacy/retention.py` | Retention policy | Retention logic |
| `privacy/scheduler.py` | Retention scheduler | Scheduler |
| `reporting/evidence_bundle.py` | Evidence bundle | build_evidence_bundle |
| `simulators/identity/*` | Identity simulator | JWT minting, TLS |
| `simulators/infrastructure/*` | Infrastructure simulator | Simulated infra |
| `workers/audit_consumer.py` | Audit consumer process | consume_source_event loop |
| `workers/consumer.py` | Remediation consumer process | consume_one loop |
| `workers/relay.py` | Outbox relay process | Relay loop |
| `workers/retention.py` | Retention process | Retention loop |

### 1.2 Entrypoints

| Entrypoint | Command | Purpose |
|-----------|---------|---------|
| API | `python -m itsm_agent.api` | HTTP service (port 8000) |
| Audit consumer | `python -m itsm_agent.workers.audit_consumer` | Durable source event processing + investigation |
| Remediation consumer | `python -m itsm_agent.workers.consumer` | Remediation workflow processing |
| Outbox relay | `python -m itsm_agent.workers.relay` | PostgreSQL outbox → NATS |
| Retention scheduler | `python -m itsm_agent.workers.retention` | Erasure/retention scheduling |
| Identity simulator | `python -m itsm_agent.simulators.identity` | OIDC/JWT simulator |
| Provision reviewer | `python tools/provision_reviewer.py` | Reviewer directory provisioning |
| Demo readiness | `python tools/demo_readiness.py` | Staging readiness gate |
| E2E rehearsal | `python tools/e2e_staging_run.py` | Full E2E rehearsal |
| Demo capture | `python tools/demo_capture.py` | Evidence capture |

### 1.3 Configuration variables

See `src/itsm_agent/config.py` (`Settings` model) for the full typed configuration. Key variables:

- `ITSM_ENV` (local/test/staging)
- `ITSM_WEBHOOK_SECRET` (min 16 chars)
- `ITSM_AUTH_MODE` (hmac/oidc; hmac refused in staging)
- OIDC: `ITSM_OIDC_ISSUER`, `ITSM_OIDC_AUDIENCE`, `ITSM_OIDC_JWKS_URL`, `ITSM_OIDC_JWKS_CA_FILE`, `ITSM_OIDC_ALGORITHMS`, `ITSM_OIDC_LEEWAY_SECONDS`, `ITSM_OIDC_MAX_TOKEN_AGE_SECONDS`
- Mockoon: `ITSM_MOCKOON_ITSM_BASE_URL`, `ITSM_MOCKOON_IDENTITY_BASE_URL`, `ITSM_MOCKOON_INFRASTRUCTURE_BASE_URL`
- LLM: `ITSM_GROQ_API_KEY`, `ITSM_GROQ_BASE_URL`, `ITSM_GROQ_MODEL`, `ITSM_GROQ_MAX_TOKENS`, `ITSM_GROQ_TIMEOUT_SECONDS`
- Investigation: `ITSM_INVESTIGATION_ENABLED`, `ITSM_INVESTIGATION_MAX_MODEL_CALLS`, `ITSM_INVESTIGATION_MAX_TOOL_CALLS`, `ITSM_INVESTIGATION_LLM_BUDGET_CALLS`
- Observability: `ITSM_OTEL_SERVICE_NAME`, `ITSM_OTEL_EXPORTER_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `ITSM_METRICS_ENABLED`
- Database: `ITSM_POSTGRES_DSN` or `DATABASE_URL`
- Messaging: `ITSM_NATS_URL` or `NATS_URL`

### 1.4 Dependencies

Python: `uv` package manager. Key dependencies: FastAPI, Pydantic v2, psycopg, nats-py, httpx, cryptography, opentelemetry, prometheus-client, langgraph (optional). See `pyproject.toml` and `uv.lock`.

JavaScript: none (Python-only backend).

## 2. Database inventory

See `docs/specs/SCHEMA_CATALOG_V1.md` for full schema. Summary: 16 migrations (001–016) on baseline; ~24 tables, RLS on 23 tenant-owned tables, runtime role `itsm_app` with least-privilege grants. Migration 017 proposed (PR #30).

## 3. Messaging inventory

- **Stream:** `ITSM_EVENTS` (subjects `itsm.events.>`)
- **DLQ stream:** `ITSM_DLQ` (subjects `itsm.dlq.>`)
- **DLQ subject:** `itsm.dlq.events`
- **Escalation subject:** `itsm.dlq.escalation`
- **Durable consumer:** `itsm-workflow` (get-or-create; H2 will fix delete-and-recreate)
- **Max deliver:** 5
- **ACK wait:** 30 seconds
- **ACK policy:** explicit
- **Delivery:** at-least-once
- **NATS server config:** `ci/nats.conf` (port 4222, monitor 8222)
- **NATS image (CI):** `nats:2.12.10-alpine` with `-c /etc/nats/nats-server.conf -js`

## 4. Infrastructure inventory

### 4.1 Compose services

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

### 4.2 Dockerfiles

- `Dockerfile` — main application image (Python, uv, dependencies)
- `Dockerfile.mockoon` — Mockoon simulator image (if present)

### 4.3 Volumes

- `postgres-data` — PostgreSQL data
- `nats-data` — NATS JetStream data (or /tmp in CI)
- `./demo-state/identity` — bind-mounted identity TLS material

## 5. CI/CD inventory

### 5.1 Workflows

| File | Jobs | Trigger |
|------|------|---------|
| `.github/workflows/ci.yml` | 15 (lint, typecheck, secret-scan, supply-chain, workflow-security, unit-tests, contract-tests, security-invariants, build, dast, integration-tests, fault-injection-tests, e2e-tests, scenarios, ci-summary) | PR, push |
| `.github/workflows/release.yml` | Release workflow | (varies) |
| `.github/workflows/localstack-iam-spike.yml` | Dispatch-only spike | workflow_dispatch |

### 5.2 Branch protection (main)

- Required status checks: 15 (all CI jobs)
- Strict: true (branch must be up to date)
- Enforce admins: true
- Required reviews: 0 (but conversation resolution required)
- Force pushes: disabled
- Deletions: disabled

### 5.3 Makefile targets

See `Makefile` for full list. Key targets: `verify`, `verify-ci`, `verify-fast`, `demo-up`, `demo-verify`, `demo-run`, `demo-evidence`, `demo-evidence-run`, `demo-down`, `demo-reset`, `compose-up`, `compose-down`, `compose-reset`.

## 6. Testing inventory

| Marker | Count | Requires |
|--------|-------|----------|
| unit | 557 | None (offline) |
| contract | 57 | Simulators (offline) |
| security | 45 | PostgreSQL |
| fault_injection | 20 | PostgreSQL + NATS |
| integration | 161 | PostgreSQL + NATS |
| scenarios | 24 | None (offline) |
| e2e | 12 | PostgreSQL + NATS + simulators |

Total: 876 tests (at 3e3a2a0). All pass.

### 6.1 Test files by category

- `tests/unit/` — 60+ unit test files (domain, API, detection, investigation, etc.)
- `tests/contract/` — 8 contract test files (simulators, offline)
- `tests/integration/` — 25 integration test files (PG, NATS, pipeline, etc.)
- `tests/security/` — 1 security test file (webhook security)
- `tests/fault_injection/` — 6 fault injection test files
- `tests/scenarios/` — 1 scenario harness (24 scenarios)
- `tests/e2e/` — 4 E2E test files

## 7. Documentation inventory

See `docs/specs/DOCUMENTATION_REGISTER_V1.md` for full status. Summary of key documents:

| Document | Status (preliminary) |
|----------|---------------------|
| `README.md` | CONTRADICTORY (migration count, finding transitions, audit consumer entrypoint) |
| `PRD.md` | OUTDATED (says qualification in progress) |
| `docs/architecture.md` | OUTDATED (describes pivot as in progress) |
| `docs/security-boundaries.md` | OUTDATED (refers to old feature branch) |
| `IMPLEMENTATION_PLAN.md` | OUTDATED (November 17 baseline) |
| `docs/staging-demo-qualification.md` | CONTRADICTORY (incorrect CI run reference) |
| `docs/adr/0001–0015` | CURRENT (accepted decisions) |
| `docs/runbooks/SOP-01–SOP-06` | MIXED (some outdated) |

## 8. Evidence inventory

### 8.1 Qualification reports

- `evals/reports/staging/readiness-20261121T120527Z.json` — STAGING_READY PASS (14 checks, commit a6e76a0)
- `evals/reports/staging/staging-run-eff4e010-4045-481f-89e0-aa16a7058c45-20261121T120153Z.json` — DEMO_QUALIFIED PASS (commit a6e76a0)
- `evals/reports/staging/evidence/readiness-20261121T120159Z/` — phase A evidence
- `evals/reports/staging/evidence/rehearsal-20261121T120206Z/` — phase B evidence

### 8.2 Historical evidence (preserved, not current)

- `evals/reports/staging/readiness-20261119T052345Z.json` — deleted (superseded)
- `evals/reports/staging/failures/readiness-20261118T121638Z.json` — retained failure evidence

### 8.3 CI artifacts

CI run 44903863383 (on 3e3a2a0): 15/15 PASS. 11 retained artifacts including 7 JUnit reports.

## 9. SOP inventory

| SOP | Title | Status (preliminary) |
|-----|-------|---------------------|
| SOP-01 | Start environment | OUTDATED (worker description) |
| SOP-02 | Ingestion failure | UNVERIFIED |
| SOP-03 | DLQ replay | UNVERIFIED |
| SOP-04 | Checkpoint recovery | UNVERIFIED |
| SOP-05 | Tenant provisioning | UNVERIFIED |
| SOP-06 | Staging E2E run | CONTRADICTORY (reviewer token references) |

## 10. ADR inventory

15 ADRs (0001–0015) covering: hexagonal ports/adapters, inbox/outbox, Moto vs LocalStack, LangGraph checkpointing, deny-by-default policy, Python-first, PostgreSQL canonical store, event-driven architecture, event sourcing/evidence preservation, selective agentic reasoning, Pydantic at boundaries, LocalStack testing, compliance-not-certification, explicit CI gates, LocalStack Explainable IAM.

All ADRs are in `docs/adr/`.

## 11. Known limitations (verified)

1. WP-J (independent human review): NOT SATISFIED.
2. Container-managed audit consumer: NOT RUN (in-process only).
3. System outbox rows with `tenant_id IS NULL`: 9 undrained.
4. OIDC intermittent failure: unexplained.
5. PostgreSQL runtime privileges: not exhaustively asserted.
6. Throughput/load testing: missing.
7. Real OTLP trace-content assertion: missing.
8. PostgreSQL/NATS failover: missing (single-node).
9. Release workflow: no successful execution after YAML fix.
10. LocalStack Explainable IAM: not executed.

## 12. Contradictions summary (preliminary)

| # | Location | Claim | Reality | Severity |
|---|----------|-------|---------|----------|
| C1 | README.md:112 | No finding status transitions | Finding lifecycle with ACKNOWLEDGED/VERIFIED exists (migration 015) | High |
| C2 | README.md:159 | Migrations 001–006 | 16 migrations (001–016) | High |
| C3 | README.md:290–291 | Audit consumer has no packaged entrypoint | `python -m itsm_agent.workers.audit_consumer` exists | Medium |
| C4 | PRD.md:5,12 | Qualification in progress | STAGING_READY and DEMO_QUALIFIED passed | Medium |
| C5 | docs/architecture.md:76 | Pivot in progress | Pivot complete | Medium |
| C6 | docs/security-boundaries.md:3 | Refers to old feature branch | Should reference main | Low |
| C7 | IMPLEMENTATION_PLAN.md | November 17 baseline | Outdated | Medium |
| C8 | docs/staging-demo-qualification.md | Links CI run 44464855386 to a6e76a0 | Run 44464855386 was on b9644e4 | High |
| C9 | docs/staging-demo-qualification.md | 856 executions | Final verification says 876 | Medium |
| C10 | docs/staging-demo-qualification.md | References November 19 artifacts | Newer November 21 artifacts present | Low |

Full contradiction register in `docs/specs/DOCUMENTATION_REGISTER_V1.md`.