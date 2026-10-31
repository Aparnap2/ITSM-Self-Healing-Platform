# Architecture — Event-Driven, Evidence-First Agentic Security Audit System

Status: pivot baseline. Source of truth: `PRD.md`.

## 1. Architecture decisions (ADR-001..008)

| ADR | Decision |
|---|---|
| ADR-001 | Hexagonal ports/adapters (domain has no vendor SDKs) |
| ADR-002 | Inbox/outbox durable publishing over NATS JetStream |
| ADR-003 | Moto default AWS simulator; LocalStack optional pending license |
| ADR-004 | LangGraph with durable PostgreSQL checkpointing |
| ADR-005 | Deny-by-default deterministic policy engine |
| ADR-006 | Python-first implementation |
| ADR-007 | PostgreSQL canonical event store |
| ADR-008 | Event-driven architecture |
| ADR-009 | Event sourcing and evidence preservation |
| ADR-010 | Selective agentic reasoning |
| ADR-011 | Pydantic at boundaries |
| ADR-012 | LocalStack testing (optional) |
| ADR-013 | Compliance is not certification |

See `docs/adr/`.

## 2. Pipeline diagram

```
Source (CloudTrail / pgAudit / GitHub / IdP)
  -> Source adapter (auth, pagination, checkpoint)
  -> Validate + normalize (strict Pydantic)
  -> Append canonical event (PostgreSQL, append-only)
  -> Outbox
  -> NATS JetStream
  -> Batch consumer
  -> Deterministic analysis (rules + policy)
  -> Investigation requested (selective, bounded LLM)
  -> Verification + audit + compliance report
```

## 3. Component responsibilities

| Component | Responsibility | Must NOT |
|---|---|---|
| Source adapters | Auth, pagination, checkpoint, fetch events | Mutate source state |
| Ingestion API | Authenticate, validate, dedup, durably accept | Run model calls synchronously |
| Canonical event store (PG) | Append-only events, evidence refs, audit | Be bypassed by adapters |
| Outbox publisher | Publish persisted events; mark after ack | Assume publish success |
| NATS consumer | Explicit acks, bounded redelivery, DLQ | Assume exactly-once |
| Batch consumer | Group events, run deterministic analysis | Invoke LLM per event |
| Deterministic analyzer | Rules + policy, reason codes | Call LLM or network |
| Investigation service | Bounded LLM triage/summary | Authorize or execute |
| Verifier | Independent postcondition read | Trust tool success |
| Audit repository | Append-only audit, redaction | Log secrets |
| Compliance reporter | Evidence reports with limitations | Claim certification |

## 4. Tenant isolation

- Every canonical event carries `tenant_id`.
- All queries and storage are tenant-scoped; cross-tenant access is denied by
  default.
- Adapters authenticate tenant context at ingestion; tenant is never taken from
  untrusted payload alone.

## 5. Privacy, redaction, retention

See `docs/privacy-retention.md`. Summary: redact secrets/PII at ingestion,
minimize LLM context, retain per policy, never log raw credentials.

## 6. Module import rules

Same as prior: `domain` pure; `ports` interfaces only; `application` depends on
ports; adapters implement ports; composition root wires.

## 7. Known limitations

- Pivot in progress; ITSM-centric code remains and requires redesign.
- Compliance output is evidence, not certification.
- LocalStack optional pending license verification.
