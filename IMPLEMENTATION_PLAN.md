# IMPLEMENTATION_PLAN.md
_Last updated: 2026-11-01 by agent (durable pipeline, findings/reviewer HTTP surface, Task 11/12/14 slices recorded; Task CI-0 accepted on green CI run 41271007745)_

## Goal
Pivot the ITSM self-healing platform into an event-driven, evidence-first agentic security audit system (AWS + PostgreSQL + GitHub + identity/approvals), preserving the completed Phase 1/2 work on branch `checkpoint/pre-audit-pivot-phase-1-2` (commit 18af41e).

## Status
- Total tasks: 19 (pivot Tasks 1-18 + release-qualification Task CI-0)
- Completed: 10 (Tasks 1-5, 7, 8, 9, 10, 13 — implemented and tested in-repo, evidence cited below)
- Newly completed: durable audit pipeline slice (Phase 7) — outbox → NATS JetStream → durable detection consumer → PostgreSQL findings + `processing_records`; commits 0a80cb2, f7bff8a, 00d11a9, 98e83ef (see Task 7 integration closure below).
- 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending): 8 (Tasks 6, 11, 12, 14, 15, 16, 17, 18)
- Remaining: 0 (no unimplemented pivot tasks)
- In progress: 0 (Task 14 HTTP reviewer surface committed in ca9ce88/babcbc0; full local suite 193 passed under ITSM_TEST_STRICT=1)
- Task CI-0: ✅ ACCEPTED — CI run 41271007745 is fully green on commit 98e83ef; the branch/PR remains draft and unmerged.
- Current branch: feat/access-audit-foundation

Status semantics: ✅ DONE means the slice is implemented and its named source
and test files exist in-repo. It does not assert an independently verified CI
run; exact passed/failed/skipped counts and independent acceptance evidence are
the Task CI-0 gate. The system is not production ready.

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
- **Commit:** 71091a1 (PRD.md, docs/architecture.md, ADR 0006-0013, docs/reuse-audit.md, docs/implementation-plan-pivot.md, README header). docs/event-contract.md, docs/privacy-retention.md, docs/source-integration-matrix.md were committed with slice 03554f6.
- **Learnings:** Docs-only scope; package rename deferred; LocalStack license verification pending.

### Task 3: Freeze canonical event contract + Pydantic schema plan — ✅ DONE (docs)
- **Scope:** docs/event-contract.md defines canonical fields and strict Pydantic rules.
- **Acceptance criteria:** Field list, timezone-aware timestamps, schema versioning, event-time vs ingestion-time documented.
- **Remaining:** none of the original blocker — Pydantic models are implemented in `src/itsm_agent/domain/events.py` (`SourceEvent`, `canonical_schema_version` mandatory; Task 6, 03554f6) and `migrations/002_source_events.sql` carries both `source_schema_version` and `canonical_schema_version` columns.

### Task 4: Audit existing code for reusable infrastructure — ✅ DONE (docs)
- **Scope:** docs/reuse-audit.md maps reusable/adapt/retire components.
- **Acceptance criteria:** Reuse map with file paths and dispositions.
- **Learnings:** NATS/outbox/pool/repositories/audit/migrations/worker reusable; domain needs redesign.
- **Commit:** 71091a1 (docs/reuse-audit.md).

### Task 5: Create root IMPLEMENTATION_PLAN.md — ✅ DONE
- **Scope:** This file.

### Task 6: First coding slice — canonical event store + ingestion infrastructure — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
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
- **Commit:** 03554f6 — `migrations/002_source_events.sql` (annotated Task 6; `source_events` with append-only trigger, `source_checkpoints`), `src/itsm_agent/domain/events.py` (`SourceEvent`), `src/itsm_agent/adapters/persistence/repositories.py`, `src/itsm_agent/adapters/persistence/ingestion_sink.py`, `tests/integration/test_source_event_ingestion.py`.
- **Verified deviations from the scope text above:** no `canonical_events` table exists anywhere in migrations/ (the canonical representation lives in `source_events` columns: `payload_hash`, `correlation_metadata`, evidence reference); no `SourceFact`/`CanonicalEvent` domain models exist in `src/` (the normalized-fact projection is `access_facts` per `migrations/004_detection.sql`, Task 12); no `processing_records` table (checkpoint state lives in `source_checkpoints`). The `outbox` table reuses `migrations/001_initial_schema.sql`. These deviations are recorded, not silently absorbed — release acceptance reviews them.

### Task 7: NATS durable consumers + replay safety — ✅ DONE
- **Scope:** Batch consumer, checkpoints, idempotent projections, dead-letter, retry.
- **Depends on:** Task 6
- **Commit:** a290432 — `src/itsm_agent/application/replay.py`, `src/itsm_agent/ports/repositories.py` (checkpoint/repository additions), `src/itsm_agent/adapters/persistence/repositories.py`, `tests/integration/test_nats_replay.py`, `docs/nats-stream-config.md`. Consumer and redelivery behavior is additionally covered by `tests/integration/test_nats_consumer.py` and `tests/integration/test_consumer_redelivery.py` (worker/consumer infrastructure predates the pivot; this slice adds the replay safety path).
- **Task 7 integration closure (durable audit pipeline, Phase 7):**
  - `tests/integration/test_audit_pipeline_durable.py` (00d11a9) exercises outbox → NATS JetStream → durable detection consumer → PostgreSQL `findings` + `processing_records`: redelivery after a crash between commit and ack yields no duplicate findings (`processing_records` status `COMPLETED` short-circuits), a full NATS round trip persists a `PRIVILEGE_ESCALATION` finding with exactly one `COMPLETED` processing record, an event that was never ingested raises with no processing record written (the consumer path dead-letters it), a tenant-mismatched event is rejected, and two tenants sharing an identical source event id stay isolated (two processing records, findings per tenant).
  - `tests/integration/test_audit_pipeline.py` (f7bff8a) covers real PostgreSQL source-event ingestion → detection plus cross-tenant isolation.
  - `migrations/006_audit_processing.sql` (0a80cb2) adds `processing_records` (unique on `(tenant_id, source, event_id, processing_version)`; statuses `PROCESSING`/`COMPLETED`/`FAILED`) and realigns the `findings.severity` CHECK to `P1`–`P4`.
  - `98e83ef` exports the new repositories and truncates `processing_records` in the integration test fixture.

### Task 8: AWS CloudTrail adapter (Moto) — ✅ DONE
- **Commit:** e689430 — `src/itsm_agent/collectors/aws/cloudtrail.py`, `src/itsm_agent/ports/collectors.py`, `tests/contract/test_cloudtrail_moto.py` (Moto contract), `tests/unit/test_cloudtrail_normalization.py`, `docs/cloudtrail-coverage.md`.

### Task 9: PostgreSQL pgAudit adapter — ✅ DONE
- **Commit:** 13ee521 — `src/itsm_agent/collectors/postgresql/pgaudit.py`, `tests/unit/test_pgaudit_normalization.py`, `docs/pgaudit-coverage.md`.

### Task 10: GitHub org audit adapter — ✅ DONE
- **Commit:** c915aae — `src/itsm_agent/collectors/github/audit_log.py`, `tests/contract/test_github_respx.py`, `tests/unit/test_github_normalization.py`, `docs/github-coverage.md`.

### Task 11: Identity + resource resolution — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** 55b30a2 — `migrations/003_identity_mappings.sql` (annotated "(Task 11)"), `src/itsm_agent/domain/identity_resolution.py`, `src/itsm_agent/domain/models.py` (identity projection additions), `src/itsm_agent/adapters/persistence/repositories.py`, `tests/unit/test_identity_resolution.py` (resolved/unresolved/ambiguous/time-validity/cross-tenant cases).
- **Commit:** bc795bc — identity resolution extension in `src/itsm_agent/domain/identity_resolution.py`: `resolve_cross_source` (multiple sources must agree on one internal id; disagreement is AMBIGUOUS; partial resolution still resolves), `resolve_assumed_role` (prefer the base identity behind an STS role session, fall back to the role), `resolve_resource_alias` (canonical resource id; unknown ids pass through, `None` stays `None` — no invented identity). `tests/unit/test_identity_resolution.py` now covers 14 cases, including cross-source agreement/disagreement/partial and alias passthrough.
- **Verification gap:** the mapping-repository ingest path has no integration test in-repo; acceptance criteria are not independently verified.

### Task 12: Deterministic detection + coverage engine — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** 80f08e3 (base) + Task 12.8 approval-evidence detection in ee55c3a — `src/itsm_agent/domain/models.py` (`ApprovalEvidence`), `src/itsm_agent/detection/engine.py` (`detect_approval_violation` + aliases, extended `run_detection`), `tests/unit/test_approval_detection.py` (16 cases: valid/missing/expired/revoked/denied/mismatch/coverage-gap/unknown-identity/cross-tenant/timezone/dict-input/source_coverage/aliases).
- **Approval-evidence outcome semantics (ee55c3a):** absence of approval evidence is not automatically a violation. `detect_approval_violation` emits `MISSING_APPROVAL` with outcome `SUSPICIOUS` (P2, risk 60) when a privileged action has no approval at all in a fully covered source with a known identity; `VIOLATION` is reserved for negative evidence — denied/rejected, revoked, expired, or dimension-mismatched approvals. Incomplete coverage yields `COVERAGE_GAP` (P3); an unresolved identity yields `INCONCLUSIVE` (P3).
- **Verification gap:** unit tests exist; the durable pipeline tests (f7bff8a, 00d11a9) exercise detection through the consumer, but approval-evidence detection has no dedicated integration coverage. Independent acceptance review pending (CI run 41271007745 green).

### Task 13: Agentic investigation layer (read-only tools) — ✅ DONE
- **Commit:** 26df864 — `src/itsm_agent/investigations/orchestrator.py`, `src/itsm_agent/domain/events.py` (`InvestigationRequest`/`InvestigationProposal`), `tests/unit/test_investigation.py` (proposal acceptance, invalid evidence reference, budget exhaustion, id-mismatch rejection).

### Task 14: Evidence reporting + reviewer workflow — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** 7fd9144 — `migrations/005_review_decisions.sql` (annotated "(Task 14)"), `src/itsm_agent/reporting/evidence_bundle.py`, `tests/unit/test_evidence_bundle.py`.
- **Commit:** 371dffb — `ReviewDecision` model (`src/itsm_agent/domain/models.py`), `PsycopgReviewDecisionRepository` in `src/itsm_agent/adapters/persistence/repositories.py` (insert-only `record`, tenant-scoped `list_for_finding`), exports in `adapters/persistence/__init__.py`, and `tests/integration/test_review_decisions.py` (3 tests: record + list, tenant isolation, append-only).
- **Commit:** ca9ce88 — reviewer HTTP surface `src/itsm_agent/api/routes/findings.py` (`GET /v1/findings`, `GET /v1/findings/{id}`, `POST`/`GET /v1/findings/{id}/decisions`; tenant required on every route; cross-tenant = 404), `create_app(findings_repo=..., review_decisions_repo=...)` wiring in `src/itsm_agent/api/app.py` (router mounted only when both repositories are supplied), and `PsycopgFindingRepository.get(tenant_id, finding_id)`. Dependencies are narrow protocols (`FindingsReader`, `DecisionsStore`) so the surface is testable offline.
- **Commit:** babcbc0 — `tests/unit/test_findings_api.py` (10 offline tests: tenant-scoped list, detail + decisions, cross-tenant 404 on read and POST with zero writes, 422 validation, 503 unconfigured, append-only, global-deps isolation) and `tests/integration/test_findings_api.py` (7 real-PostgreSQL tests: isolation, decision durability across an app rebuild, repository `get` scoping, append-only duplicates). Contract documented in `docs/findings-api.md`.
- **Verification gap:** reviewer workflow beyond the `review_decisions` table, bundle builder, repository, and HTTP surface is not independently acceptance-reviewed; authenticating the reviewer identity (approval binding, RBAC) is still missing. Independent acceptance review pending (CI run 41271007745 green; HTTP surface committed in ca9ce88 with 17 new tests in babcbc0).

### Task 15: Security/privacy/multi-tenancy — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** 994818e — `src/itsm_agent/privacy/redaction.py`, `tests/unit/test_redaction.py`, `tests/integration/test_tenant_isolation.py` (additions), `docs/security-boundaries.md`.
- **Verification gap:** redaction and tenant isolation have tests in-repo, but retention and the full multi-tenancy scope are not independently verified.

### Task 16: Reliability/observability/E2E + golden dataset — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** 89aac14 — `docs/observability.md`, `tests/e2e/test_multi_source_audit.py`.
- **Verification gap:** no golden dataset is committed and the slice added no new observability code (`src/itsm_agent/observability/` predates the pivot); independent acceptance review pending (CI run 41271007745 green).

### Task 17: Controlled pilot — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** fb6b344 — `docs/pilot.md`, `tests/e2e/test_pilot_scenario.py` (`test_pilot_scenario_end_to_end`).
- **Verification gap:** the pilot's measurement results (precision, false-positive rate, coverage — per docs/pilot.md) are not recorded in-repo; the scenario is implemented, not executed-with-evidence.

### Task 18: Production readiness — 🟡 IMPLEMENTED (slice committed; independent acceptance verification pending)
- **Commit:** 7b08f21 — `docs/production-readiness.md` (docs-only slice).
- **Verification gap:** the doc itself lists unwired gates ("Run pip-audit / safety in CI (to be wired)") and unverified license terms (LocalStack, ADR-0012). The system is not production ready and must not be claimed as such.

### Task CI-0: Release Qualification Repair — ✅ ACCEPTED (CI run 41271007745 green; PR draft, unmerged)
- **Scope:**
  - Fix the mypy strict failure on the action proposal adapter (done in commit 9e605b9).
  - Repair pytest collection so every test selector collects non-zero tests (no zero-collected suites).
  - Repair integration CI service wiring via `ITSM_TEST_PG_DSN` / `ITSM_TEST_NATS_URL` (currently absent from `.github/workflows/ci.yml`).
  - Fail CI when required services are unavailable instead of allowing silent skips.
  - Add contract, e2e, and fault-injection CI jobs.
  - Reconcile release documentation with repository reality (this change: `IMPLEMENTATION_PLAN.md`, `PRD.md`, `docs/event-contract.md`).
  - Add dependency-vulnerability, SAST, container-scan, and SBOM gates.
- **Acceptance gate:** all CI jobs green with exact passed/failed/skipped counts reported; no zero-collected suites. **Accepted:** CI run 41271007745 on commit 98e83ef is fully green. The branch/PR remains draft and unmerged, so merge is still outstanding. Tasks marked 🟡 above remain "implemented; independent acceptance review pending" until the PR is reviewed and merged.
- **Test phase:** Integration + CI gates (no new features; qualification only)

## Data mutability boundaries (per review)
- Immutable: source_events, canonical_events, raw evidence, audit_records, reviewer decisions, investigation proposals.
- Rebuildable/versioned: access facts / normalized projections, findings.
- Mutable operational state: consumer_checkpoints, processing_records.
- Append-only trigger applies only to immutable tables, not projections.

## Known Risks / Gotchas
- Pivot work plus the durable audit pipeline slice (Tasks 6-18, docs) is committed through babcbc0 on `feat/access-audit-foundation`; CI run 41271007745 is fully green on 98e83ef and the reviewer HTTP surface has since landed (ca9ce88 + tests babcbc0). The remaining release step is PR review and squash-merge; the branch/PR is still draft and unmerged.
- LocalStack license terms must be verified before use (ADR-0012).
- Hypothesis not installed; add to dev deps if approved.
- docker-compose.test.yml not yet created.
- Package rename (itsm_agent -> audit) deferred; avoid churn until domain stabilizes.
- No external task tracker; this file is the single source of truth.

## Recommended next slice
Priority 3 from the reviewer's ordering: **security boundaries for the reviewer surface** — authenticated reviewer identity (so `reviewer_id` is derived from a verified principal, not client input), RBAC for who may confirm/false-positive findings, PostgreSQL row-level security (or a session-bound tenant) so tenant scoping is enforced below the query layer, and retention/erasure enforcement for findings, evidence references and decisions. Until that lands, the findings API is deliberately unauthenticated and must stay bound to a trusted network. Merge remains the outstanding release step (PR #9 draft, unmerged). Contract for the current surface: `docs/findings-api.md`.
