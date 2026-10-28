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

Implementation in progress: ingestion, durable inbox/outbox, NATS
JetStream consumer, LangGraph remediation workflow, deterministic policy,
independent verification, and audit persistence are implemented and
tested (61 tests). See `PRD.md` for the full specification.

## Stack

Python 3.12 · Pydantic v2 · LangGraph (PostgreSQL checkpointing) ·
PostgreSQL (durable source of truth) · NATS JetStream (event backbone) ·
Mockoon (deterministic HTTP simulators) · Moto (AWS API simulator) ·
Ollama (optional local LLM) · OpenTelemetry / Prometheus.

Headless by design: no UI, no dashboard.

## Running the worker

Set ITSM_POSTGRES_DSN and ITSM_NATS_URL, then run:

    python -m itsm_agent.workers.consumer

Environment: ITSM_POSTGRES_DSN/DATABASE_URL, ITSM_NATS_URL/NATS_URL,
ITSM_WORKER_CONCURRENCY (default 4), ITSM_WORKER_SHUTDOWN_TIMEOUT (default 30),
ITSM_SIMULATOR_SEED (default 42). The worker subscribes to itsm.events.> on the
ITSM_EVENTS stream (durable consumer itsm-workflow), ACKs only after durable
processing, NAKs transient failures, dead-letters poison messages.

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
