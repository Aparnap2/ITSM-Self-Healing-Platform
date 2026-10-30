# Implementation Plan — Pivot to Security Audit System

This is the pivot plan (docs-first). Root `IMPLEMENTATION_PLAN.md` will be
created separately when execution begins.

## Goal

Pivot the platform from ITSM self-healing to an event-driven, evidence-first
agentic security audit system, reusing durable infrastructure.

## Phases

### Phase 1 — Audit & pivot docs (this)
- Deliver: PRD, architecture, ADRs, reuse audit, source matrix, event contract,
  privacy/retention, this plan.
- Exit gate: docs coherent and reviewed.

### Phase 2 — Canonical event contract & domain models
- Implement canonical event Pydantic models and enums.
- Exit gate: unit tests for validation and versioning pass.

### Phase 3 — Source adapters
- Implement CloudTrail, pgAudit, GitHub, identity/approval adapters (simulated).
- Exit gate: contract tests for auth/pagination/checkpoints pass.

### Phase 4 — Ingestion & normalization pipeline
- Ingest, validate, normalize, append canonical events, outbox.
- Exit gate: duplicate delivery and outage tests pass.

### Phase 5 — Deterministic detection rules
- Implement rule engine with reason codes.
- Exit gate: all allow/deny branches tested.

### Phase 6 — Evidence preservation & redaction
- Raw evidence references, hashing, redaction.
- Exit gate: redaction tests pass; no secrets in payloads.

### Phase 7 — Outbox/NATS/batch consumer
- Batch consumption and deterministic analysis trigger.
- Exit gate: integration tests pass.

### Phase 8 — Deterministic analysis engine
- Correlation, aggregation, finding generation.
- Exit gate: findings reproducible on seeded data.

### Phase 9 — Selective agentic investigation
- Bounded LLM triage/summary for flagged cases.
- Exit gate: core tests pass without LLM.

### Phase 10 — Policy & approvals (reuse)
- Reuse deny-by-default policy; adapt to audit actions.
- Exit gate: policy invariants pass.

### Phase 11 — Verification & audit
- Independent verification and append-only audit.
- Exit gate: audit completeness tests pass.

### Phase 12 — Compliance reporting
- Evidence reports with limitations; no certification claims.
- Exit gate: report generated from real test run.

### Phase 13 — Evaluation & CI
- Scenario harness, security gates, CI.
- Exit gate: deterministic suite passes offline.

## Known limitations

- Plan is documentation; execution not started.
- Phase durations not estimated.
