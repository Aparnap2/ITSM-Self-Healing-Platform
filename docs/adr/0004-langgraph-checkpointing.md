# ADR-0004: LangGraph with durable PostgreSQL checkpointing

Status: Accepted
Date: 2026-10-28

## Context

The incident workflow is a long-running, stateful state machine
(PRD §3): validate → triage → diagnostics → policy → approval gate →
execute → reconcile → verify → ITSM update. It must survive worker
crashes (SOP-05), pause indefinitely at the approval gate without
holding a worker or DB transaction open (PRD §3.4), and resume from
durable state. LangGraph is the locked orchestration choice (PRD §0),
but its default in-memory checkpointer loses state on restart.

## Decision

- Use **LangGraph with a PostgreSQL-backed checkpointer** (e.g.
  `AsyncPostgresSaver` from `langgraph-checkpoint-postgres`) so every
  super-step's state is durably persisted.
- **Interrupt/resume semantics:** the `request_approval` node issues a
  graph interrupt; the workflow persists and the worker releases. An
  authenticated approval resumes the graph from the checkpoint. Approval
  wait time is excluded from the workflow wall-clock budget.
- **Canonical state is PostgreSQL business tables, not the checkpoint.**
  The checkpoint is an orchestration snapshot only (PRD §3.3): IDs,
  status/node, references, hashes, retry counters. Incidents, approvals,
  action attempts, and audit events live in normalized tables.
- **Bounded execution:** node budgets, tool-call caps, retry limits, and
  a wall-clock deadline are enforced in code around the graph, not
  delegated to the framework.
- Crash recovery at fault-injection points (before action, after action
  before result) reconciles in-flight actions against actual target
  state before continuing.

## Consequences

- Worker restarts resume exactly where they stopped; no accepted
  incident or pending approval is silently lost (NFR recoverability).
- Checkpoint blobs are opaque to business queries — anything that must
  be audited or deduplicated must also be written to a real table.
  This dual-write is deliberate and tested.
- Versioning: checkpoint format is tied to the graph shape; workflow
  version is recorded on `WorkflowRun` so old checkpoints are not
  resumed by incompatible graph versions.

## Alternatives considered

1. **In-memory checkpointer.** Rejected: loses state on restart;
   violates SOP-05 and the recoverability NFR.
2. **Temporal / durable-execution frameworks.** Rejected: PRD §1.4
   excludes Temporal without demonstrated need; LangGraph + Postgres
   covers the required interrupt/resume with far less operational
   weight.
3. **Custom state machine without LangGraph.** Rejected: LangGraph is a
   locked decision; a hand-rolled machine would re-implement
   interrupt/resume and lose the explicit-node auditability the PRD
   requires.
4. **Checkpoint as the only state store.** Rejected: PRD §5 explicitly
   forbids treating checkpoint state as the canonical business record.
