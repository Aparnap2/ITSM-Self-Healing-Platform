# Schema Catalog v1.0

**Status:** H0 inventory — reconciled against actual migrations on main at `3e3a2a0`.
**Source of truth:** `migrations/001`–`017` (017 on branch `fix/h1-audit-immutability`, PR #30).

---

## 1. Migration inventory

17 migrations. Forward-only. Applied via `apply_migrations()` (async) or `migrations/apply.py` (sync). Bookkeeping table: `schema_migrations`.

| # | File | Purpose |
|---|------|---------|
| 001 | `001_initial_schema.sql` | Initial schema (incidents, workflow_state, etc.) |
| 002 | `002_source_events.sql` | Source events + checkpoints |
| 003 | `003_identity_mappings.sql` | Identity mappings |
| 004 | `004_detection.sql` | Detection findings |
| 005 | `005_review_decisions.sql` | Review decisions |
| 006 | `006_audit_processing.sql` | Audit processing records |
| 007 | `007_tenant_isolation.sql` | Tenant isolation (RLS + composite FKs) |
| 008 | `008_retention_erasure.sql` | Retention/erasure + tombstones |
| 009 | `009_tenant_scoped_inbox.sql` | Tenant-scoped inbox |
| 010 | `010_runtime_role.sql` | Runtime role (itsm_app) grants |
| 011 | `011_tenant_owned_workflow.sql` | Tenant-owned workflow |
| 012 | `012_retention_scheduler.sql` | Retention scheduler |
| 013 | `013_least_privilege_schema_migrations.sql` | Least-privilege schema_migrations |
| 014 | `014_least_privilege_tenant_registry.sql` | Least-privilege tenant registry |
| 015 | `015_findings_lifecycle.sql` | Findings lifecycle (status vocabulary, transitions) |
| 016 | `016_investigation_ledger.sql` | Investigation ledger (append-only) |
| 017 | `017_review_decisions_append_only.sql` | H1: review_decisions append-only (PR #30) |

## 2. Table catalog

### 2.1 Tenant-owned tables (RLS: ENABLE + FORCE)

All have `tenant_id UUID NOT NULL` and RLS policy: `tenant_id = NULLIF(current_setting('itsm.tenant_id', true), '')::uuid`.

| Table | PK | Key columns | Mutation policy |
|-------|-----|------------|-----------------|
| `source_events` | `id UUID` | tenant_id, source_type, source_event_id, canonical_schema_version, event_time, ingested_at, payload JSONB, idempotency_key | Append-only |
| `source_checkpoints` | `id UUID` | tenant_id, source_type, checkpoint_value, updated_at | Controlled |
| `identity_mappings` | `id UUID` | tenant_id, external_id, internal_id | Controlled |
| `access_facts` | `id UUID` | tenant_id, finding_id (FK), fact_type, fact_value | Versioned |
| `findings` | `id UUID` | tenant_id, finding_type, severity, status, title, description, detected_at, rule_version, risk_score, outcome, verified_by, verified_at | Versioned lifecycle |
| `evidence_references` | `id UUID` | tenant_id, finding_id (composite FK), source_event_id, access_fact_id, content_hash, excerpt, trust_level, collected_at | Append-only |
| `coverage_status` | `id UUID` | tenant_id, source_type, coverage_level, last_checked | Controlled |
| `review_decisions` | `id UUID` | tenant_id, finding_id (composite FK), reviewer_id, decision, decided_at, rationale, evidence_pack_ref | Append-only (H1) |
| `processing_records` | `id UUID` | tenant_id, event_id, status, processed_at | Controlled |
| `event_inbox` | `id UUID` | tenant_id, event_id, status, received_at | Controlled |
| `outbox` | `id UUID` | tenant_id, aggregate_type, aggregate_id, event_type, payload JSONB, status, created_at, published_at | Controlled lifecycle |
| `incidents` | `id UUID` | tenant_id, title, status, severity, created_at | Controlled |
| `workflow_state` | `id UUID` | tenant_id, incident_id, state, updated_at | Controlled |
| `action_intents` | `id UUID` | tenant_id, intent_type, target, status, created_at | Controlled |
| `approvals` | `id UUID` | tenant_id, action_intent_id, approver, status, decided_at | Controlled |
| `audit_events` | `id UUID` | tenant_id, event_type, actor, resource, action, timestamp, metadata JSONB | Append-only |
| `erasure_requests` | `id UUID` | tenant_id, data_class, status, requested_at | Controlled |
| `erasure_tombstones` | `id UUID` | tenant_id, data_class, record_id, integrity_hash, detail, erase_request_id (FK), erased_at | Append-only |
| `retention_policies` | `id UUID` | tenant_id, data_class, retention_days, created_at | Controlled |
| `legal_holds` | `id UUID` | tenant_id, data_class, reason, created_at | Controlled |
| `finding_transitions` | `id UUID` | tenant_id, finding_id (composite FK), from_status, to_status, actor_id, verifier_id, reason, transitioned_at | Append-only |
| `investigation_requests` | `id UUID` | tenant_id, finding_id (FK), requested_by, question, evidence_snapshot_ids, max_tool_calls, max_model_calls, status, created_at | Append-only |
| `investigation_proposals` | `id UUID` | tenant_id, request_id (FK), finding_id, hypothesis, supporting_evidence, contradicting_evidence, missing_evidence, uncertainty, created_at | Append-only |

### 2.2 Controlled tables (no RLS or admin-only)

| Table | Purpose | Mutation |
|-------|---------|----------|
| `tenants` | Tenant registry | Controlled (runtime: SELECT+INSERT only) |
| `reviewer_authorizations` | Reviewer directory | Read-only at runtime (SELECT only) |
| `schema_migrations` | Migration bookkeeping | Admin only |

### 2.3 Composite foreign keys (tenant-bound)

| Constraint | Table | Columns | References |
|-----------|-------|---------|------------|
| `fk_review_decisions_tenant_finding` | `review_decisions` | (tenant_id, finding_id) | `findings(tenant_id, id)` |
| `fk_evidence_references_tenant_finding` | `evidence_references` | (tenant_id, finding_id) | `findings(tenant_id, id)` |
| `fk_finding_transitions_tenant_finding` | `finding_transitions` | (tenant_id, finding_id) | `findings(tenant_id, id)` |
| `fk_investigation_requests_finding` | `investigation_requests` | (tenant_id, finding_id) | `findings(tenant_id, id)` |
| `fk_investigation_proposals_request` | `investigation_proposals` | (tenant_id, request_id) | `investigation_requests(tenant_id, id)` |

### 2.4 Append-only enforcement

| Table | Privileges (itsm_app) | Trigger | Migration |
|-------|----------------------|---------|-----------|
| `source_events` | SELECT, INSERT | `trg_source_events_append_only` | 002 |
| `audit_events` | SELECT, INSERT | `trg_audit_events_append_only` | 006 |
| `erasure_tombstones` | SELECT, INSERT | `trg_erasure_tombstones_append_only` | 008 + 017 |
| `finding_transitions` | SELECT, INSERT | `trg_finding_transitions_append_only` | 015 |
| `investigation_requests` | SELECT, INSERT | `trg_investigation_requests_append_only` | 016 |
| `investigation_proposals` | SELECT, INSERT | `trg_investigation_proposals_append_only` | 016 |
| `review_decisions` | SELECT, INSERT | `trg_review_decisions_append_only` | 005 + 017 (H1) |

### 2.5 Runtime role (`itsm_app`)

- `NOSUPERUSER`, `NOBYPASSRLS`, `NOINHERIT` (in test context).
- Granted: SELECT, INSERT, UPDATE, DELETE on tenant-owned tables (except append-only: SELECT, INSERT only).
- `reviewer_authorizations`: SELECT only.
- `tenants`: SELECT, INSERT (no UPDATE/DELETE/TRUNCATE).
- `schema_migrations`: no privileges.
- Default privileges for future tables: SELECT, INSERT, UPDATE, DELETE (TRUNCATE/REFERENCES/TRIGGER revoked).

### 2.6 RLS policy pattern

```sql
CREATE POLICY tenant_isolation ON <table>
  USING (tenant_id = NULLIF(current_setting('itsm.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('itsm.tenant_id', true), '')::uuid);
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <table> FORCE ROW LEVEL SECURITY;
```

### 2.7 Known integrity gaps (H3)

- `evidence_references.access_fact_id` → `access_facts(id)` without tenant binding.
- `evidence_references.source_event_id` → no FK to `source_events`.
- `finding_transitions.finding_id` → `findings(id)` (not composite tenant-bound in migration 015; composite FK added in 007 for some tables).

These are documented gaps to be addressed in H3.<|end|><|start|>write to=assistant<|channel|>analysis <|constrain|>xml<|message|><rfl:parameter name="path">
/home/aparna/Desktop/itsm/docs/specs/RUNTIME_AND_CONFIGURATION_V1.md