# Architecture — Headless ITSM Self-Healing Platform

Status: baseline (skeleton). Source of truth: `PRD.md` §2. This document
summarizes boundaries and adds the import rules downstream agents must
respect.

## 1. System boundary diagram

```text
                UNTRUSTED EXTERNAL WORLD
  ┌──────────────────────────────────────────────────────────┐
  │  ITSM / alert sources · webhook senders · ticket text    │
  │  log content · LLM output · approval submissions         │
  └───────────────┬──────────────────────────────────────────┘
                  │  (trust boundary 1: authenticate + validate)
                  ▼
        ┌─────────────────────┐
        │  API / Ingestion    │  authn, schema validation, size/rate
        │  (src/itsm_agent/   │  limits, correlation + idempotency keys
        │   api/)             │
        └─────────┬───────────┘
                  │  durable accept only after commit
                  ▼
        ┌─────────────────────┐
        │  PostgreSQL         │  inbox (dedup) + outbox + business state
        │  (adapters/         │  + approvals + action attempts + audit
        │   persistence/)     │
        └─────────┬───────────┘
                  │  (trust boundary 2: outbox → broker)
                  ▼
        ┌─────────────────────┐
        │  NATS JetStream     │  at-least-once delivery, durable
        │  (adapters/         │  consumers, bounded redelivery, DLQ
        │   messaging/)       │
        └─────────┬───────────┘
                  ▼
        ┌─────────────────────────────────────────────────┐
        │  Workflow Worker (LangGraph)                    │
        │  (application/)                                 │
        │  validate → normalize → triage → diagnostics →  │
        │  policy → approval gate → intent → execute →    │
        │  reconcile → verify → ITSM update → finalize    │
        └───┬──────────┬──────────┬───────────┬───────────┘
            │          │          │           │
            ▼          ▼          ▼           ▼
     ┌──────────┐ ┌─────────┐ ┌─────────┐ ┌──────────────┐
     │ Mockoon  │ │ Moto /  │ │ Ollama  │ │ OTel /       │
     │ ITSM +   │ │ infra   │ │ (local  │ │ Prometheus   │
     │ identity │ │ sim     │ │ LLM,    │ │ (observ-     │
     │ APIs     │ │         │ │ option- │ │ ability/)    │
     │          │ │         │ │ al)     │ │              │
     └──────────┘ └─────────┘ └─────────┘ └──────────────┘
       (trust boundary 3: every adapter response is untrusted
        data until validated; a success response is not proof)
```

Everything right of the API is simulated or local. No real production
mutations exist in the portfolio baseline (PRD §1.4, §8.1).

## 2. Component responsibilities (PRD §2.2, condensed)

| Component | Location | Responsibility | Must NOT |
|---|---|---|---|
| API/inbox | `api/` | Authenticate, validate, dedup, durably accept events; ack only after commit | Run model calls or remediation synchronously in the request |
| Outbox publisher | `application/` + `adapters/persistence/` | Publish persisted events to NATS; mark published only after broker ack | Assume publish succeeded without ack |
| NATS consumer | `adapters/messaging/` | Explicit acks, durable consumer, bounded redelivery, DLQ/escalation | Assume exactly-once delivery |
| Workflow worker | `application/` | Run the explicit LangGraph state machine; checkpoint to PostgreSQL; enforce budgets | Hold an open HTTP request for the workflow |
| Policy engine | `domain/policies.py` | Pure deterministic allow/deny/require-approval with reason codes | Call LLM, network, or read mutable global state |
| Tool registry | `application/` | Map known action type → typed adapter; reject unknown types/params | Execute model-generated code |
| Verifier | `application/` + `adapters/infrastructure/` | Read actual target state via a read-only path distinct from the action response | Treat a tool success message as evidence |
| Audit repository | `adapters/persistence/` | Append-only audit events, redaction, correlation linking | Log secrets or serialize arbitrary objects |
| Scenario runner | `tests/scenarios/`, `evals/` | Seed state/faults, run bounded, check invariants, emit JSON/JUnit | Use LLM prose as the expected result |

## 3. Event flow (PRD §7)

`IncidentCreated → DiagnosticsCollected → RemediationProposed →
PolicyEvaluated → ApprovalRequested → ApprovalDecided →
RemediationStarted → RemediationExecuted → RemediationVerified →
IncidentResolved | IncidentEscalated | OutboundUpdateFailed`

Events are immutable facts with schema versions. Unknown event types are
rejected or quarantined, never dynamically executed. Consumers
deduplicate on `(source_system, external_event_id)`.

## 4. Trust boundaries and validation points

1. **Ingestion boundary** — webhook/event payloads: authenticate the
   source, validate with strict Pydantic (`extra="forbid"`), apply size
   and rate limits, assign correlation + idempotency keys. Ticket text
   and log content are untrusted data, never instructions.
2. **LLM output boundary** — every model response is re-validated with
   Pydantic against a schema-constrained contract (`TriageResult`,
   action proposals). Confidence is an evaluation signal, never an
   authorization signal. Bounded retries on invalid output, then
   escalate.
3. **Approval boundary** — approver identity is authenticated
   independently; `approver_id` in a body is not proof. Approval binds
   to the exact proposal hash, expires, and is single-use (nonce).
4. **Adapter boundary** — all external/simulator responses are validated
   before entering domain logic. A `ToolResult.status == "SUCCEEDED"`
   never implies `VerificationResult.passed == True`.
5. **Execution boundary** — side effects occur only after (a) durable
   action intent + idempotency key, (b) a durable policy decision, and
   (c) a valid approval when required. Uncertain outcomes trigger
   reconciliation before any retry.

## 5. Module import rules (hexagonal boundary contract)

Downstream agents MUST respect these dependency directions:

```text
domain ──────────────► (stdlib + pydantic only)
ports  ──────────────► domain
application ─────────► domain, ports, observability (injected)
api ─────────────────► domain, application, config
adapters/* ──────────► ports, domain (types only), config
observability ───────► (stdlib + otel/prometheus SDKs only)
config ──────────────► (stdlib + pydantic only)
```

- `domain/` must not import `application`, `ports`, `adapters`, `api`,
  LangGraph, any vendor SDK, or any I/O library. It is pure and
  deterministic (PRD §12, ADR-0001).
- `ports/` contains abstract interfaces (typing Protocols / ABCs) only —
  no implementations, no vendor imports.
- `application/` depends only on `ports`; it never imports a concrete
  adapter. Wiring happens exclusively in the **composition root** (the
  API app factory and the worker entrypoint), which may import
  everything.
- `adapters/*` implement `ports` and may import vendor SDKs
  (httpx, nats-py, asyncpg/psycopg, boto3, langchain-ollama). Domain
  code must never import these.
- `tests/` may import anything; contract tests exercise adapters against
  simulators; unit tests exercise `domain` with zero I/O.

## 6. Failure domains (PRD §2.4, summary)

LLM unavailable → deterministic paths continue, model-dependent triage
escalates within limits. Invalid model output → bounded retry, then
escalate, no action. NATS unavailable → events stay durably in the
outbox. PostgreSQL unavailable → fail closed, no side effects without
durable state/audit capacity. Uncertain tool outcome → reconcile target
state before retry. Verification failure → never resolve; escalate.
Worker crash → resume from durable checkpoints; reconcile in-flight
actions. Expired approval → reject and escalate.
