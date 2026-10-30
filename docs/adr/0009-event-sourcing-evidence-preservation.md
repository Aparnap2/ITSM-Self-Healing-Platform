# ADR-0009: Event sourcing and evidence preservation

Status: Accepted
Date: 2026-10-30

## Context

Audit findings must be reproducible and defensible. Events are immutable facts;
raw evidence must be preserved and referenced, not mutated. Corrections are
new events.

## Decision

- Canonical events are append-only and schema-versioned.
- Raw evidence is stored/referenced via raw_evidence_reference with payload_hash.
- Redaction occurs at ingestion; redacted payloads are what enters the store.
- Evidence references are immutable once written.

## Consequences

- Full audit trail and reproducibility.
- Storage grows with events; retention policy applies (see privacy-retention).
- Redaction is one-way; original secrets are never retained.

## Alternatives considered

1. Mutable event records. Rejected: breaks audit integrity.
2. Storing raw payloads unredacted. Rejected: violates privacy invariants.
