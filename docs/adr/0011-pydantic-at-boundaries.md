# ADR-0011: Pydantic at boundaries

Status: Accepted
Date: 2026-10-30

## Context

External events, LLM outputs, approvals, and tool inputs are untrusted. Typed
validation at trust boundaries prevents injection and malformed data from
reaching domain logic.

## Decision

- All boundary contracts use Pydantic v2 with extra="forbid".
- Timestamps normalized to timezone-aware UTC at the boundary.
- Unknown event types are rejected or quarantined, never executed.
- Validation failures fail closed.

## Consequences

- Strong input guarantees; clear error surfaces.
- Schema versioning required for evolution.
- Slight overhead at ingestion; acceptable.

## Alternatives considered

1. Loose dict validation. Rejected: allows injection and drift.
2. JSON Schema only. Rejected: less ergonomic and weaker typing in Python.
