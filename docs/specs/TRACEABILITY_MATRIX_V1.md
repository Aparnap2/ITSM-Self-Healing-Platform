# Traceability Matrix v1.0

**Status:** H0 inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`

---

## 1. Purpose

Every requirement must map to implementation, database/runtime configuration, automated test, CI workflow, documentation, and retained qualification evidence. No requirement may be marked complete without a verification path.

## 2. Core requirement traceability

| Req ID | Requirement | Code | Database | Test | Workflow | Documentation | Evidence |
|--------|------------|------|----------|------|----------|-----------------|----------|
| DB-IMM-001 | review_decisions cannot be updated by itsm_app | `privileges.py` | Migration 017 | `test_review_decisions_runtime_role_cannot_mutate` | integration.yml | security-boundaries.md | Runtime safety test |
| DB-IMM-002 | review_decisions cannot be deleted by itsm_app | `privileges.py` | Migration 017 | `test_review_decisions_runtime_role_cannot_mutate` | integration.yml | security-boundaries.md | Runtime safety test |
| DB-IMM-003 | review_decisions cannot be truncated by itsm_app | `privileges.py` | Migration 017 | `test_review_decisions_runtime_role_cannot_mutate` | integration.yml | security-boundaries.md | Runtime safety test |
| DB-IMM-004 | Append-only trigger rejects UPDATE/DELETE | Migration 017 | `pg_trigger` | `test_review_decisions_cannot_be_updated_or_deleted` | integration.yml | security-boundaries.md | Integration test |
| DB-IMM-005 | Safety verifier detects UPDATE grant on append-only table | `privileges.py` | `has_table_privilege` | `test_review_decisions_append_only_grant_is_rejected` | integration.yml | — | Integration test |
| TENANT-001 | Cross-tenant finding reference rejected | `repositories.py` | Composite FK (migration 007) | `test_cross_tenant_decision_reference_is_rejected` | integration.yml | security-boundaries.md | Integration test |
| TENANT-002 | RLS enabled and forced on all tenant tables | `privileges.py` | RLS policies (migration 007) | `test_runtime_database_safety.py` | integration.yml | security-boundaries.md | Integration test |
| NATS-DUR-001 | Durable consumer survives worker restart | `nats_bus.py` | JetStream | `test_nats_consumer.py` | staging-faults.yml (H8) | nats-stream-config.md | Fault injection (H10) |
| NATS-DUR-002 | Readiness fails if durable consumer absent | `demo_readiness.py` | JetStream /jsz | `test_demo_readiness.py` | staging-parity.yml (H8) | SOP-01 | Readiness report |
| NATS-POISON-001 | Poison message reaches DLQ | `nats_bus.py` | JetStream DLQ | `test_dlq.py` | fault-injection | — | Fault injection |
| PIPE-001 | Event persistence + outbox atomic | `ingestion_sink.py` | `source_events` + `outbox` | `test_atomicity_rollback.py` | integration.yml | architecture.md | Integration test |
| PIPE-002 | Outbox relay publishes committed records | `outbox_relay.py` | `outbox` | `test_outbox_relay.py` | integration.yml | — | Integration test |
| PIPE-003 | Duplicate delivery is idempotent | `audit_consumer.py` | `processing_records` | `test_inbox_dedup.py` | integration.yml | — | Integration test |
| DET-001 | Detection creates findings | `detection/engine.py` | `findings` | `test_detection.py` | ci.yml (unit) | — | Unit test |
| DET-002 | Unknown identity → uncertain, not confirmed | `detection/engine.py` | `findings` | `test_detection_precision.py` | ci.yml (unit) | security-boundaries.md | Unit test |
| INV-001 | Investigation proposes, never authorizes | `investigations/service.py` | `investigation_proposals` | `test_investigation.py` | ci.yml (unit) | architecture.md | Unit test |
| INV-002 | Evidence grounding: both booleans required | `e2e_staging_run.py` | `evidence_references` | `test_e2e_staging_runner.py` | staging-parity.yml (H8) | staging-demo-qualification.md | Rehearsal report |
| REV-001 | Authenticated reviewer lifecycle | `api/routes/findings.py` | `review_decisions` | `test_findings_transition_api.py` | integration.yml | findings-api.md | Integration test |
| REV-002 | Reviewer separation (distinct verifier) | `api/routes/findings.py` | `finding_transitions` | `test_review_decisions.py` | staging-parity.yml (H8) | staging-demo-qualification.md | Rehearsal report |
| REV-003 | Unauthorized transition rejected + audited | `api/routes/findings.py` | `audit_events` | `test_findings_transition_api.py` | integration.yml | security-boundaries.md | Integration test |
| OBS-001 | Metrics endpoint exposes required families | `observability/metrics.py` | — | `test_telemetry_surface.py` | ci.yml (unit) | observability.md | Unit test |
| OBS-002 | Trace propagation across services | `observability/tracing.py` | — | `test_telemetry_surface.py` | staging-observability.yml (H8/H9) | observability.md | NOT RUN (gap) |
| AUTH-001 | OIDC token validation (RS256) | `api/oidc.py` | `reviewer_authorizations` | `test_oidc_security.py` | ci.yml (unit) | security-boundaries.md | Unit test |
| AUTH-002 | HMAC refused in staging | `config.py` | — | `test_api_entrypoint.py` | ci.yml (unit) | config.py | Unit test |
| PRIV-001 | Secret redaction in logs/audit | `privacy/redaction.py` | — | `test_redaction.py` | ci.yml (unit) | security-boundaries.md | Unit test |
| EVID-001 | Evidence bundle deterministic | `reporting/evidence_bundle.py` | `evidence_references` | `test_evidence_bundle.py` | ci.yml (unit) | findings-api.md | Unit test |
| MIG-001 | Migrations forward-only and idempotent | `migrations/apply.py` | `schema_migrations` | `test_migration_safety.py` | integration.yml | migration-safety.md | Integration test |

## 3. Critical code paths without requirements

The following code paths exist but have no explicit requirement ID. They should either be assigned a requirement or documented as internal infrastructure:

| Code path | Reason for existence | Disposition |
|-----------|---------------------|-------------|
| `privacy/retention.py` | Data retention policy enforcement | DEFERRED: needs requirement ID |
| `privacy/scheduler.py` | Retention scheduler | DEFERRED: needs requirement ID |
| `simulators/identity/` | OIDC/JWT simulator for local dev | DEFERRED: test infrastructure, not production |
| `simulators/infrastructure/` | Infrastructure simulator | DEFERRED: test infrastructure |
| `collectors/github/audit_log.py` | GitHub audit log collector | DEFERRED: needs requirement ID |
| `collectors/postgresql/pgaudit.py` | PostgreSQL audit collector | DEFERRED: needs requirement ID |

## 4. Operational claims without verification

| Claim | Location | Verification method | Status |
|-------|----------|-------------------|--------|
| "Reviewer decisions are append-only" | README, PRD | DB privilege + trigger test | VERIFIED (H1, PR #30) |
| "Tenant isolation via RLS" | security-boundaries.md | Integration test + catalog assertion | VERIFIED |
| "At-least-once delivery" | architecture.md | Integration test + DLQ test | VERIFIED |
| "Deterministic authorization" | security-boundaries.md | Unit test + policy matrix | VERIFIED |
| "Evidence-grounded investigation" | staging-demo-qualification.md | E2E rehearsal | VERIFIED (application-level) |
| "Container-managed consumer" | README | NOT RUN | NOT RUN |
| "Production-ready" | — | NOT CLAIMED | N/A |

## 5. Test coverage gaps

| Gap | Description | Disposition |
|-----|-------------|-------------|
| Trace content assertion | Metrics asserted, traces not | DEFECT (OBS-002) |
| Throughput/load testing | No performance gate | DEFERRED |
| PostgreSQL/NATS failover | Single-node only | DEFERRED |
| Runtime privilege exhaustiveness | Not all grants asserted | DEFECT (H1 extends) |
| Container-managed consumer | Not tested | DEFECT (H4) |
| Cross-tenant DB insertion | Application-level only | DEFECT (H3) |
| NATS consumer restart preserves delivery state | Not tested | DEFECT (H2) |