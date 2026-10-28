# ADR-0001: Hexagonal architecture — domain must not import vendor SDKs

Status: Accepted
Date: 2026-10-28

## Context

The platform integrates many external systems: Mockoon-simulated ITSM and
identity APIs, NATS JetStream, PostgreSQL, Moto/LocalStack (AWS), Ollama
(LLM), and later Jira Service Management and ServiceNow. The PRD (§1,
§12) requires that domain logic have no direct vendor SDK dependency and
that every integration sit behind an adapter/port. Without an enforced
boundary, SDK types and HTTP details leak into business rules, making
the policy engine untestable without network and the codebase hard to
swap between simulators and real SaaS.

## Decision

Adopt a ports-and-adapters (hexagonal) layout:

- `domain/` — pure, deterministic business logic (contracts, enums,
  canonical hashing, state transitions, policy matrix). Imports only the
  standard library and Pydantic v2. No I/O, no LLM, no network, no
  vendor imports.
- `ports/` — abstract interfaces (typing Protocols/ABCs) owned by the
  application, one per integration concern (itsm, identity,
  infrastructure, event_bus, repositories, model).
- `adapters/` — concrete implementations of ports; the only place vendor
  SDKs may be imported.
- Composition root (API app factory, worker entrypoint) is the only code
  that wires concrete adapters into the application.

## Consequences

- Policy and transition logic is unit-testable offline, satisfying the
  CI requirement that deterministic tests run without network or LLM.
- Swapping Mockoon for real Jira (Phase 6) touches only an adapter.
- Slight indirection cost: every integration needs a port + adapter pair
  even when only one implementation exists initially. Accepted — the
  boundary is the product requirement, not speculative abstraction.

## Alternatives considered

1. **Layered architecture (domain → services → infra imports allowed
   downward).** Rejected: nothing mechanically prevents vendor types
   from leaking into domain; the PRD explicitly forbids it.
2. **Direct SDK usage with integration tests only.** Rejected: tests
   would require network/simulators for every policy change, violating
   the determinism and 16 GB resource constraints.
3. **Plugin/dynamic adapter loading.** Rejected: dynamic loading
   conflicts with fail-closed safety (unknown code must not execute)
   and adds attack surface for no current need.
