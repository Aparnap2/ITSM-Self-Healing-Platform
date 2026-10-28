# ITSM Self-Healing Platform

A headless, event-driven IT operations agent: it consumes incident
events, gathers diagnostic evidence, proposes a bounded remediation,
passes it through deterministic deny-by-default policy enforcement,
executes only allowlisted tools, independently verifies the actual
resulting state, and records an auditable outcome — resolving an
incident only when verification passes.

**The point:** agentic reasoning inside deterministic operational
boundaries. The LLM proposes; policy code authorizes; adapters execute;
an independent verifier establishes success.

## Status

Skeleton phase — architecture and repository structure only. No business
logic is implemented yet. See `PRD.md` for the full specification and
`docs/architecture.md` for boundaries and import rules.

## Stack

Python 3.12 · Pydantic v2 · LangGraph (PostgreSQL checkpointing) ·
PostgreSQL (durable source of truth) · NATS JetStream (event backbone) ·
Mockoon (deterministic HTTP simulators) · Moto (AWS API simulator) ·
Ollama (optional local LLM) · OpenTelemetry / Prometheus.

Headless by design: no UI, no dashboard.

## Repository layout

```text
src/itsm_agent/     application code (api, domain, application, ports,
                    adapters, observability, config)
simulators/         Mockoon fixtures, infrastructure simulator, seeds
tests/              unit, contract, integration, security,
                    fault_injection, scenarios
evals/              evaluation datasets and generated reports
docs/               architecture, ADRs, runbooks
migrations/         PostgreSQL schema migrations
```

## Quickstart

> Placeholder — will be filled in as the stack comes online
> (compose up → migrations → seed fixtures → run scenarios).
> See `PRD.md` §4 (SOPs) for the target operating procedures.

## Documentation

- [`PRD.md`](PRD.md) — full specification, contracts, SOPs, test plan
- [`docs/architecture.md`](docs/architecture.md) — system boundaries,
  component responsibilities, trust boundaries, import rules
- [`docs/adr/`](docs/adr/) — architecture decision records:
  hexagonal ports/adapters, inbox/outbox durable publishing,
  Moto vs LocalStack licensing, LangGraph checkpointing,
  deny-by-default policy
