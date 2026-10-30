# ADR-0006: Python-first implementation

Status: Accepted
Date: 2026-10-30

## Context

The platform is a portfolio-grade, headless system requiring typed contracts,
deterministic policy, and reproducible tests. Python with Pydantic v2 and
LangGraph is already the locked stack (PRD §0). A Python-first implementation
keeps domain logic pure, testable offline, and consistent with existing
adapters and migrations.

## Decision

- Implement all domain, application, and adapter code in Python 3.12.
- Use Pydantic v2 for all boundary contracts.
- Use LangGraph for workflow orchestration with PostgreSQL checkpointing.
- No second language or runtime in the baseline.

## Consequences

- Single toolchain; simpler CI and onboarding.
- Domain remains pure and offline-testable.
- Performance-critical paths rely on async I/O and batching, not a new runtime.

## Alternatives considered

1. Polyglot (Rust/Go for hot paths). Rejected: adds operational complexity
   without demonstrated need.
2. TypeScript-first. Rejected: conflicts with existing Python codebase and
   locked decisions.
