# ADR-0007: PostgreSQL as canonical event store

Status: Accepted
Date: 2026-10-30

## Context

Security audit requires an immutable, queryable record of canonical events,
evidence references, and audit decisions. PostgreSQL is already the durable
source of truth. Event sourcing demands append-only storage with strong
consistency and tenant isolation.

## Decision

- PostgreSQL stores canonical events append-only, with tenant_id on every row.
- Raw evidence is referenced (not inlined) via raw_evidence_reference.
- LangGraph checkpoints are orchestration snapshots only, not business state.
- Migrations are versioned and applied before runtime.

## Consequences

- Strong consistency and queryability for audit and compliance.
- Append-only discipline required; corrections are new events.
- Checkpoint blobs remain opaque to business queries.

## Alternatives considered

1. Event store database (EventStoreDB). Rejected: adds operational dependency
   without demonstrated need.
2. Object storage only. Rejected: lacks transactional consistency and querying.
