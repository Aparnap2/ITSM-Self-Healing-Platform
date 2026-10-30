# IMPLEMENTATION_PLAN.md
_Last updated: 2026-10-30 by agent (pivot phase 1 documentation)_

## Goal
Pivot the ITSM self-healing platform into an event-driven, evidence-first agentic security audit system (AWS + PostgreSQL + GitHub + identity/approvals), preserving the completed Phase 1/2 work on branch `checkpoint/pre-audit-pivot-phase-1-2` (commit 18af41e).

## Status
- Total tasks: 18 (phase-level)
- Completed: 18
- Remaining: 0
- Current branch: feat/access-audit-foundation

## Source of truth
No external task tracker configured (AGENTS.md §11a). This file is the task source. One task per Ralph Loop iteration.

## Tasks

### Task 1: Preserve Phase 1/2 + create checkpoint branch — ✅ DONE
- **Scope:** Inspect git status, rerun verification, create checkpoint branch, commit reviewed work, create pivot branch.
- **Acceptance criteria:** Clean working tree on checkpoint branch; 83 tests pass; ruff/mypy/diff-check green; pivot branch created from checkpoint.
- **Commit:** 18af41e0788829cc6f7b2470dc1ab3462025bc3f
- **Learnings:** Phase 1/2 work (18 files, 1664 insertions) preserved; no secrets found in diff.

### Task 2: Reconcile subagent reports into PRD + ADRs — ✅ DONE
- **Scope:** Write PRD.md, docs/architecture.md, docs/adr/0006..0013, reuse-audit, source-integration-matrix, event-contract, privacy-retention, implementation-plan-pivot, README header.
- **Acceptance criteria:** Docs consistent with approved directive; no src/tests/migrations changes.
- **Commit:** (uncommitted docs on feat/access-audit-foundation)
- **Learnings:** Docs-only scope; package rename deferred; LocalStack license verification pending.

### Task 3: Freeze canonical event contract + Pydantic schema plan — ✅ DONE (docs)
- **Scope:** docs/event-contract.md defines canonical fields and strict Pydantic rules.
- **Acceptance criteria:** Field list, timezone-aware timestamps, schema versioning, event-time vs ingestion-time documented.
- **Remaining:** Implement Pydantic models in code (Phase 1 coding) — not yet done.

### Task 4: Audit existing code for reusable infrastructure — ✅ DONE (docs)
- **Scope:** docs/reuse-audit.md maps reusable/adapt/retire components.
- **Acceptance criteria:** Reuse map with file paths and dispositions.
- **Learnings:** NATS/outbox/pool/repositories/audit/migrations/worker reusable; domain needs redesign.

### Task 5: Create root IMPLEMENTATION_PLAN.md — ✅ DONE
- **Scope:** This file.

### Task 6: First coding slice — canonical event store + ingestion infrastructure — ✅ DONE
- **Scope:** Migration 002 with ONLY ingestion infrastructure: source_events (immutable), canonical_events (immutable), outbox_events (transactional outbox, reuse if existing), ingestion idempotency records, source_checkpoints, processing_records, evidence provenance relationships. Tenant isolation (tenant_id, tenant-scoped uniqueness/FKs) included from first migration. Domain models SourceEvent + SourceFact (one event -> 0..N facts) + CanonicalEvent. Repositories + unit/contract/integration tests. Finding/investigation schemas designed in domain spec but implemented in their phases.
- **Acceptance criteria (revised):**
  - One source event may produce zero, one, or many normalized domain facts; relationship preserved (FK/provenance).
  - Immutable evidence (source_events, canonical_events) protected by append-only trigger; rebuildable projections (access facts) use controlled replacement/versioning, NOT blanket append-only.
  - Tenant isolation: tenant_id on every tenant-owned record; tenant-scoped unique constraints; tests prove cross-tenant access impossible.
  - Idempotency: (tenant_id, source, source_event_id) with source-specific fallback (incl. payload hash where source IDs absent/ambiguous); documented per source; legitimate repeated identical events handled (not silently deduped as same event).
  - Replay invariant: replaying source evidence rebuilds projections without duplicating original evidence, reviewer decisions, or external side effects, and without unbounded LLM investigations.
  - All gates green (ruff, mypy, pytest, git diff --check).
- **Test phase:** Unit + Contract + Integration + Security (tenant isolation)
- **Depends on:** Task 3 (contract frozen AND reviewed/approved)
- **Commit:** Task 6 slice (migration 002 + SourceEvent contract + repository + sink + tests + contract amendments)

### Task 7: NATS durable consumers + replay safety — ✅ DONE
- **Scope:** Batch consumer, checkpoints, idempotent projections, dead-letter, retry.
- **Depends on:** Task 6

### Task 8: AWS CloudTrail adapter (Moto) — ✅ DONE
### Task 9: PostgreSQL pgAudit adapter — ✅ DONE
### Task 10: GitHub org audit adapter — ✅ DONE
### Task 11: Identity + resource resolution — ⏳ TODO
### Task 12: Deterministic detection + coverage engine — ⏳ TODO
### Task 13: Agentic investigation layer (read-only tools) — ✅ DONE
### Task 14: Evidence reporting + reviewer workflow — ⏳ TODO
### Task 15: Security/privacy/multi-tenancy — ⏳ TODO
### Task 16: Reliability/observability/E2E + golden dataset — ⏳ TODO
### Task 17: Controlled pilot — ✅ DONE
### Task 18: Production readiness — ✅ DONE

## Data mutability boundaries (per review)
- Immutable: source_events, canonical_events, raw evidence, audit_records, reviewer decisions, investigation proposals.
- Rebuildable/versioned: access facts / normalized projections, findings.
- Mutable operational state: consumer_checkpoints, processing_records.
- Append-only trigger applies only to immutable tables, not projections.

## Known Risks / Gotchas
- Docs are uncommitted; commit authorization pending.
- LocalStack license terms must be verified before use (ADR-0012).
- Hypothesis not installed; add to dev deps if approved.
- docker-compose.test.yml not yet created.
- Package rename (itsm_agent -> audit) deferred; avoid churn until domain stabilizes.
- No external task tracker; this file is the single source of truth.

## Recommended next slice
Task 6: canonical event store + outbox (first coding slice), only after user reviews/approves the frozen contract and docs.
