# Production-Parity Baseline v1.0

**Status:** FROZEN — specification milestone. No implementation beyond H1 has begun.
**Starting SHA (verified):** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`
**H1 SHA (unmerged PR #30):** `1064551`
**Date:** 2026-11-22
**Authority:** This document is the frozen architecture and requirements specification for the production-parity staging and operational-readiness milestone. Changes require approval per `docs/specs/CHANGE_CONTROL.md`.

---

## 1. Mission

Harden the existing Event-Driven, Evidence-First Agentic Security Audit System and make its operational lifecycle reproducible through GitHub Actions. Do not add new product features.

The staging environment must exercise the actual application components and operational entrypoints — not a simplified test-only substitute.

## 2. Frozen architecture

### 2.1 Application architecture (modular monolith)

| Component | Technology | Role |
|-----------|-----------|------|
| HTTP API | FastAPI | Ingestion and reviewer endpoints |
| Validation | Pydantic v2 | Input/output contracts at trust boundaries |
| Database | PostgreSQL | Canonical state and evidence store |
| Messaging | NATS JetStream | Asynchronous transport (at-least-once) |
| Detection | Deterministic rules | Security finding creation |
| Authorization | Deterministic policy | Action authorization (LLM proposes, never authorizes) |
| Investigation | Optional LLM adapter | Evidence-grounded advisory investigation |
| Observability | OpenTelemetry | Traces, metrics, structured logs |

Processes: API (`python -m itsm_agent.api`), outbox relay (`python -m itsm_agent.workers.relay`), audit consumer (`python -m itsm_agent.workers.audit_consumer`), remediation consumer (`python -m itsm_agent.workers.consumer`), retention scheduler (`python -m itsm_agent.workers.retention`).

**Prohibited without approval:** Kubernetes, Kafka, Redis, Temporal, microservices, additional databases, additional observability platforms.

### 2.2 Infrastructure (Docker Compose)

Services in `compose.yaml`: `postgres`, `nats`, `demo-init`, `identity`, `migrate`, `mockoon`, `otel-collector`, `prometheus`, `api`, `worker`, `relay`, `retention`, `localstack` (opt-in profile).

Test services: `itsm-test-pg` (port 5544), `itsm-test-nats` (port 4224).

### 2.3 CI/CD and staging (GitHub Actions)

Workflows: `ci.yml` (15 jobs), `integration.yml`, `staging-parity.yml` (to be created), `staging-faults.yml` (to be created), `staging-observability.yml` (to be created), `release-qualification.yml` (to be created).

## 3. Frozen data model

### 3.1 Logical entities and mutation policies

| Entity | Purpose | Mutation policy |
|--------|---------|-----------------|
| `tenants` | Tenant identity | Controlled |
| `source_connections` | Configured evidence sources | Controlled |
| `source_events` | Normalized source events | Append-only |
| `raw_evidence` | Original evidence and provenance | Append-only |
| `outbox` (outbox_events) | Transactional event publication | Controlled lifecycle |
| `access_facts` | Resolved access facts | Versioned/rebuildable |
| `findings` | Detected security findings | Versioned lifecycle |
| `finding_transitions` | Finding status history | Append-only |
| `evidence_references` | Finding-to-evidence linkage | Append-only |
| `investigation_requests` | LLM/deterministic investigation requests | Append-only |
| `investigation_proposals` | Investigation proposals | Append-only |
| `review_decisions` | Human reviewer decisions | Append-only |
| `reviewer_authorizations` | Reviewer permissions | Controlled (read-only at runtime) |
| `audit_events` | Security-sensitive action history | Append-only |
| `erasure_tombstones` | Deletion/retention evidence | Append-only |

### 3.2 Database conventions (frozen)

- UUID primary keys.
- `tenant_id UUID NOT NULL` on every tenant-owned entity.
- `TIMESTAMPTZ` for timestamps.
- Explicit `created_at` and, where appropriate, `observed_at`, `event_at`, `updated_at`.
- JSONB only for variable source payloads and structured metadata.
- Explicit foreign keys.
- Tenant-bound composite unique constraints and foreign keys.
- RLS (ENABLE + FORCE) for tenant isolation.
- Runtime database role (`itsm_app`) separated from migration owner.
- No runtime ownership of protected tables.
- Explicit append-only enforcement (privileges + triggers).
- Forward-only, versioned schema migrations.

### 3.3 Migration inventory (verified on main at 3e3a2a0)

Migrations 001–016 applied. H1 adds 017 (on branch `fix/h1-audit-immutability`, PR #30, unmerged).

| # | File | Purpose |
|---|------|---------|
| 001 | `001_initial_schema.sql` | Initial schema |
| 002 | `002_source_events.sql` | Source events |
| 003 | `003_identity_mappings.sql` | Identity mappings |
| 004 | `004_detection.sql` | Detection |
| 005 | `005_review_decisions.sql` | Review decisions |
| 006 | `006_audit_processing.sql` | Audit processing |
| 007 | `007_tenant_isolation.sql` | Tenant isolation (RLS) |
| 008 | `008_retention_erasure.sql` | Retention/erasure |
| 009 | `009_tenant_scoped_inbox.sql` | Tenant-scoped inbox |
| 010 | `010_runtime_role.sql` | Runtime role |
| 011 | `011_tenant_owned_workflow.sql` | Tenant-owned workflow |
| 012 | `012_retention_scheduler.sql` | Retention scheduler |
| 013 | `013_least_privilege_schema_migrations.sql` | Least-privilege schema migrations |
| 014 | `014_least_privilege_tenant_registry.sql` | Least-privilege tenant registry |
| 015 | `015_findings_lifecycle.sql` | Findings lifecycle |
| 016 | `016_investigation_ledger.sql` | Investigation ledger (append-only) |
| 017 | `017_review_decisions_append_only.sql` | H1: review_decisions append-only (PR #30) |

### 3.4 Actual tables (from migrations)

Tenant-owned (RLS): `source_events`, `source_checkpoints`, `identity_mappings`, `access_facts`, `findings`, `evidence_references`, `coverage_status`, `review_decisions`, `processing_records`, `event_inbox`, `outbox`, `incidents`, `workflow_state`, `action_intents`, `approvals`, `audit_events`, `erasure_requests`, `erasure_tombstones`, `retention_policies`, `legal_holds`, `finding_transitions`, `investigation_requests`, `investigation_proposals`.

Controlled: `tenants`, `reviewer_authorizations`.

Append-only (privileges + triggers): `source_events`, `audit_events`, `erasure_tombstones`, `finding_transitions`, `investigation_requests`, `investigation_proposals`, `review_decisions` (after H1).

## 4. Frozen event contract

Canonical event envelope (target — reconcile with existing `domain/events.py`):

```python
class CanonicalEvent(BaseModel):
    event_id: UUID
    tenant_id: UUID
    source_type: Literal["aws_cloudtrail", "postgresql_pgaudit", "github_audit", "identity"]
    source_event_id: str
    source_schema_version: str
    canonical_schema_version: str
    event_type: str
    event_time: datetime  # UTC, no naive timestamps
    observed_at: datetime
    ingested_at: datetime
    actor_id: str | None
    resource_id: str | None
    provenance: dict[str, object]
    payload: dict[str, object]
    idempotency_key: str
```

Requirements:
- Reject naive timestamps; normalize to UTC.
- Validate source provenance.
- Reject unknown schema versions or quarantine explicitly.
- Enforce tenant-scoped uniqueness.
- Preserve raw source evidence separately.
- LLMs must never modify canonical source evidence.

## 5. Frozen runtime topology

```
                 GitHub Actions / Operator
                           |
                           v
                    FastAPI service
                           |
               +-----------+-----------+
               |                       |
               v                       v
          PostgreSQL              Authentication
               |
        Transactional outbox
               |
               v
          Outbox relay
               |
               v
          NATS JetStream
               |
               v
        Durable audit consumer
               |
        +------+------+
        |             |
        v             v
    Detection    Investigation
        |             |
        +------+------+
               |
               v
         PostgreSQL
               |
               v
       Reviewer workflow
               |
               v
         Evidence report
```

### Process contracts

| Process | Entrypoint | Health requirement |
|---------|-----------|-------------------|
| API | `python -m itsm_agent.api` | HTTP readiness + metrics |
| Outbox relay | `python -m itsm_agent.workers.relay` | Process health + backlog |
| Audit consumer | `python -m itsm_agent.workers.audit_consumer` | Durable subscription + progress |
| Remediation consumer | `python -m itsm_agent.workers.consumer` | Durable subscription + progress |
| Retention scheduler | `python -m itsm_agent.workers.retention` | Process health |
| OTel Collector | (container) | Collector health + telemetry verification |
| Prometheus | (container) | Target health + queryable metrics |
| Grafana | (container) | Provisioned dashboard availability |

No critical worker may exist only inside a test harness.

## 6. Frozen NATS semantics

| Setting | Contract |
|---------|----------|
| Delivery | At-least-once |
| ACK | Explicit |
| Durable consumer | Named and persistent (`itsm-workflow`) |
| Consumer creation | Get-or-create (H2: fix current delete-and-recreate) |
| Consumer deletion | Explicit administrative reset only |
| Idempotency | PostgreSQL uniqueness/processing state |
| Retry | Bounded (`DEFAULT_MAX_DELIVER = 5`) |
| DLQ | Required (`ITSM_DLQ` stream) |
| Poison message | Eventually dead-lettered |
| Restart | Must preserve delivery state (H2) |
| Replay | Must not duplicate immutable evidence or reviewer decisions |

### Actual configuration (from code)

- Stream: `ITSM_EVENTS`, subjects `itsm.events.>`
- DLQ stream: `ITSM_DLQ`, subjects `itsm.dlq.>`
- DLQ subject: `itsm.dlq.events`
- Escalation subject: `itsm.dlq.escalation`
- Subject prefix: `itsm.events.`
- Durable name: `itsm-workflow`
- Max deliver: 5
- ACK wait: 30 seconds
- NATS server config: `ci/nats.conf` (port 4222, monitor 8222, store_dir `/tmp/nats-jetstream`)

## 7. Frozen observability contract

### Layers

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Metrics | Prometheus | Quantitative health and performance |
| Logs | Structured JSON | Event-level diagnosis |
| Traces | OpenTelemetry | Cross-service execution path |
| Dashboards | Grafana | Human operational visibility |
| CI reports | GitHub Actions | Qualification and failure evidence |

### Required dashboards (8)

1. Platform overview
2. API health
3. Database health
4. Outbox and messaging
5. Consumer processing
6. Detection and investigation
7. Reviewer lifecycle
8. Resilience and fault tests

### Required alerts (11)

- API unavailable
- PostgreSQL unavailable
- NATS unavailable
- Durable consumer missing
- Outbox backlog above threshold
- Oldest pending outbox event exceeds threshold
- Consumer repeatedly failing
- DLQ count increases
- Investigation provider unavailable
- Telemetry pipeline unavailable
- Required trace spans missing

## 8. Frozen workflow inventory

| File | Purpose | Status |
|------|---------|--------|
| `.github/workflows/ci.yml` | Static checks, unit tests, security checks (15 jobs) | Exists |
| `.github/workflows/integration.yml` | Real PostgreSQL and NATS tests | Exists (part of ci.yml) |
| `.github/workflows/staging-parity.yml` | Full Compose lifecycle | To be created (H8) |
| `.github/workflows/staging-faults.yml` | Failure injection and recovery | To be created (H8/H10) |
| `.github/workflows/staging-observability.yml` | Metrics, logs and traces | To be created (H8/H9) |
| `.github/workflows/release-qualification.yml` | Exact-SHA qualification | To be created (H6) |

No seventh workflow without approved requirement.

### Fixed workflow phases

```
preflight → build → infrastructure → migrations → security → ingestion
  → messaging → detection → investigation → reviewer lifecycle
  → observability → fault injection → evidence validation → cleanup
```

## 9. Frozen qualification gates

| Gate | Required |
|------|----------|
| `BUILD_QUALIFIED` | Yes |
| `DATABASE_QUALIFIED` | Yes |
| `MESSAGING_QUALIFIED` | Yes |
| `PIPELINE_QUALIFIED` | Yes |
| `INVESTIGATION_QUALIFIED` | Yes |
| `REVIEW_QUALIFIED` | Yes |
| `OBSERVABILITY_QUALIFIED` | Yes |
| `RESILIENCE_QUALIFIED` | Yes |
| `STAGING_READY` | Yes |
| `DEMO_QUALIFIED` | Yes |
| `RELEASE_CANDIDATE_QUALIFIED` | Yes |

Rules:
- Every gate must have machine-readable evidence.
- Missing evidence means `NOT_RUN`.
- Any required failed gate means `FAIL`.
- No manual override may convert a failed technical gate into PASS.
- Independent human review remains separate.
- All reports must refer to the exact candidate SHA.
- Production readiness remains a separate qualification.

## 10. Frozen scope-control mechanism

The agent maintains three documents:
- `docs/specs/PRODUCTION_PARITY_V1.md` — this document (frozen architecture and requirements).
- `docs/specs/ACCEPTANCE_MATRIX_V1.yaml` — machine-readable acceptance criteria.
- `docs/specs/CHANGE_CONTROL.md` — approved changes and exceptions.

Every task must reference an acceptance criterion ID (e.g., `DB-IMM-001`).

The agent classifies findings as:
- `BLOCKER`: violates an existing requirement.
- `DEFECT`: implementation does not meet acceptance criteria.
- `DEFERRED`: improvement outside the frozen baseline.
- `RISK`: known limitation with explicit owner and disposition.

Only blockers and defects within the frozen baseline are automatically actionable. New features, architectural changes, new dependencies, extra infrastructure and changes to acceptance criteria require approval.

## 11. Stopping rule

The milestone ends when:
1. All approved acceptance criteria pass.
2. All required integration and fault-injection tests pass.
3. The full staging workflow passes on the exact candidate SHA.
4. Required metrics, logs and traces are verified.
5. Evidence artifacts are complete and reproducible.
6. Documentation matches actual implementation.
7. Known limitations are recorded.
8. Independent human review is completed or explicitly remains a release blocker.

After that, the baseline is frozen. A new audit may identify risks, but it does not automatically reopen completed work. Only a demonstrated regression, security defect, failed acceptance criterion or explicitly approved new requirement reopens the relevant scope.

## 12. Known starting state

- **Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5` (verified clean on main).
- **H1 SHA (unmerged):** `1064551` on branch `fix/h1-audit-immutability` (PR #30).
- **Test counts at 3e3a2a0:** 557 unit, 57 contract, 45 security, 20 fault-injection, 161 integration, 24 scenarios, 12 e2e = 876 total.
- **CI:** 15/15 green on run 44903863383.
- **Independent human review:** NOT SATISFIED.
- **Container-managed audit consumer:** NOT RUN (in-process only).
- **System outbox rows with tenant_id IS NULL:** 9 undrained.
- **OIDC transient:** unexplained.

## 13. Implementation order (frozen)

1. H1 (PR #30 — already implemented, awaiting review).
2. H2 (NATS lifecycle + readiness).
3. H3 (Tenant integrity).
4. H4 (Container-managed consumer).
5. H8 (GitHub Actions staging).
6. H9 (Observability).
7. H10 (Resilience).
8. H5 (Documentation cleanup).
9. H6 (Requalification).
10. H7 (Independent human review — parallel).

Do not start dependent work if its prerequisite has failed.
