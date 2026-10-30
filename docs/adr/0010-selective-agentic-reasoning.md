# ADR-0010: Selective agentic reasoning

Status: Accepted
Date: 2026-10-30

## Context

LLMs are useful for ambiguous triage and investigation narratives but are
non-deterministic and must never authorize or execute. The 80/20 target keeps
the core deterministic.

## Decision

- Deterministic code performs ingestion, normalization, detection, policy,
  verification, and reporting.
- LLMs are invoked only for bounded investigation tasks (triage, summary,
  narrative) and only when deterministic rules flag a case.
- LLM output is validated with Pydantic and never treated as authorization.
- Model calls are optional; core tests run without them.

## Consequences

- Safety invariants hold regardless of model availability.
- Agentic value is additive, not load-bearing.
- Bounded retries and budgets enforced in code.

## Alternatives considered

1. LLM-driven detection. Rejected: non-deterministic, unauditable.
2. No LLM at all. Rejected: loses investigation assistance value.
