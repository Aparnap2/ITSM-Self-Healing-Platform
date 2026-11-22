# Documentation Register v1.0

**Status:** H0 inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`

---

## 1. Status definitions

| Status | Meaning |
|--------|---------|
| `CURRENT` | Validated against current implementation |
| `OUTDATED` | Historically valid but no longer matches implementation |
| `CONTRADICTORY` | Conflicts with authoritative code or evidence |
| `UNVERIFIED` | Not yet demonstrated |
| `SUPERSEDED` | Replaced by an identified newer document or decision |

## 2. Document register

| Document | Path | Status | Notes |
|----------|------|--------|-------|
| README.md | `README.md` | CONTRADICTORY | Migration count (says 001–006, actual 017); finding transitions (says none, exist); audit consumer entrypoint (says none, exists) |
| PRD.md | `PRD.md` | OUTDATED | Says qualification in progress; STAGING_READY + DEMO_QUALIFIED passed |
| Architecture | `docs/architecture.md` | OUTDATED | Describes pivot as in progress; pivot complete |
| Security boundaries | `docs/security-boundaries.md` | OUTDATED | Refers to old feature branch |
| Implementation plan | `IMPLEMENTATION_PLAN.md` | OUTDATED | November 17 baseline, outdated qualification numbers |
| Staging qualification | `docs/staging-demo-qualification.md` | CONTRADICTORY | Links CI run 44464855386 to a6e76a0 (run was on b9644e4); 856 vs 876 executions |
| Event contract | `docs/event-contract.md` | UNVERIFIED | Needs reconciliation with actual models |
| Findings API | `docs/findings-api.md` | CURRENT | Matches implementation |
| Security CI | `docs/security-ci.md` | CURRENT | Matches CI configuration |
| Observability | `docs/observability.md` | UNVERIFIED | Needs reconciliation with actual metrics |
| Production readiness | `docs/production-readiness.md` | OUTDATED | Needs update for new invariants |
| Migration safety | `docs/migration-safety.md` | CURRENT | Matches migration system |
| NATS stream config | `docs/nats-stream-config.md` | CURRENT | Matches nats_bus.py |
| Pilot | `docs/pilot.md` | UNVERIFIED | Needs reconciliation |
| Privacy/retention | `docs/privacy-retention.md` | CURRENT | Matches implementation |
| Reuse audit | `docs/reuse-audit.md` | UNVERIFIED | Needs reconciliation |
| Source integration matrix | `docs/source-integration-matrix.md` | UNVERIFIED | Needs reconciliation |
| CloudTrail coverage | `docs/cloudtrail-coverage.md` | UNVERIFIED | Needs reconciliation |
| GitHub coverage | `docs/github-coverage.md` | UNVERIFIED | Needs reconciliation |
| PgAudit coverage | `docs/pgaudit-coverage.md` | UNVERIFIED | Needs reconciliation |
| Demo storyboard | `docs/demo-storyboard.md` | CURRENT | Matches demo flow |
| Release qualification | `docs/release-qualification.md` | OUTDATED | References old commits |
| Staging E2E plan | `docs/staging-e2e-qualification-plan.md` | OUTDATED | Needs update |
| CI docs | `docs/ci/README.md`, `docs/ci/act-local-ci.md`, `docs/ci/release-path.md` | CURRENT | Matches CI |
| Production-parity spec | `docs/specs/PRODUCTION_PARITY_V1.md` | CURRENT | New (this milestone) |

## 3. ADR register

| ADR | Title | Status |
|-----|-------|--------|
| 0001 | Hexagonal ports/adapters | CURRENT |
| 0002 | Inbox/outbox durable publishing | CURRENT |
| 0003 | Moto vs LocalStack licensing | CURRENT |
| 0004 | LangGraph checkpointing | CURRENT |
| 0005 | Deny-by-default policy | CURRENT |
| 0006 | Python-first implementation | CURRENT |
| 0007 | PostgreSQL canonical event store | CURRENT |
| 0008 | Event-driven architecture | CURRENT |
| 0009 | Event sourcing/evidence preservation | CURRENT |
| 0010 | Selective agentic reasoning | CURRENT |
| 0011 | Pydantic at boundaries | CURRENT |
| 0012 | LocalStack testing | CURRENT |
| 0013 | Compliance not certification | CURRENT |
| 0014 | Explicit CI gates and release path | CURRENT |
| 0015 | LocalStack Explainable IAM | CURRENT |

## 4. SOP register

| SOP | Title | Status | Notes |
|-----|-------|--------|-------|
| SOP-01 | Start environment | OUTDATED | Worker description outdated (fixed in docs commit, but needs re-verification) |
| SOP-02 | Ingestion failure | UNVERIFIED | Not exercised in staging |
| SOP-03 | DLQ replay | UNVERIFIED | Not exercised in staging |
| SOP-04 | Checkpoint recovery | UNVERIFIED | Not exercised in staging |
| SOP-05 | Tenant provisioning | UNVERIFIED | Not exercised in staging |
| SOP-06 | Staging E2E run | CONTRADICTORY | Reviewer token references outdated |

## 5. SOP reconciliation requirements

For every SOP, record:
- SOP ID and current revision
- Exact commands and referenced services
- Whether commands and environment variables exist
- Comparison with current implementation
- Stale authentication, reviewer, migration and staging instructions
- Preconditions, expected outcomes, failure handling, retained evidence
- Status: CURRENT, OUTDATED, CONTRADICTORY, or UNVERIFIED

An SOP that has never been tested is UNVERIFIED, not VALIDATED.

## 6. Contradiction register (preliminary, full detail in REPOSITORY_BASELINE_V1.md §12)

| # | Location | Claim | Reality | Severity | Disposition |
|---|----------|-------|---------|----------|-------------|
| C1 | README.md:112 | No finding status transitions | Finding lifecycle exists (migration 015) | High | DOCUMENTATION_DEFECT |
| C2 | README.md:159 | Migrations 001–006 | 16 migrations (001–016) | High | DOCUMENTATION_DEFECT |
| C3 | README.md:290–291 | No packaged audit consumer entrypoint | `python -m itsm_agent.workers.audit_consumer` exists | Medium | DOCUMENTATION_DEFECT |
| C4 | PRD.md:5,12 | Qualification in progress | STAGING_READY + DEMO_QUALIFIED passed | Medium | DOCUMENTATION_DEFECT |
| C5 | docs/architecture.md:76 | Pivot in progress | Pivot complete | Medium | DOCUMENTATION_DEFECT |
| C6 | docs/security-boundaries.md:3 | Refers to old feature branch | Should reference main | Low | DOCUMENTATION_DEFECT |
| C7 | IMPLEMENTATION_PLAN.md | November 17 baseline | Outdated | Medium | DOCUMENTATION_DEFECT |
| C8 | docs/staging-demo-qualification.md | Links CI run 44464855386 to a6e76a0 | Run was on b9644e4 | High | DOCUMENTATION_DEFECT |
| C9 | docs/staging-demo-qualification.md | 856 executions | Final verification says 876 | Medium | DOCUMENTATION_DEFECT |
| C10 | docs/staging-demo-qualification.md | References November 19 artifacts | Newer November 21 artifacts present | Low | DOCUMENTATION_DEFECT |

## 7. Historical evidence preservation rule

Historical qualification artifacts remain immutable. New reports reference their exact SHA and supersede earlier qualification where appropriate. Never rewrite historical evidence to make current qualification look better.