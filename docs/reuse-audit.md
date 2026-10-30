# Reuse Audit — Pivot to Security Audit System

## Reusable infrastructure

- NATS adapter (`adapters/messaging/nats_bus.py`, `outbox_relay.py`)
- Connection pool (`adapters/persistence/pool.py`)
- Repositories (`adapters/persistence/repositories.py`)
- Audit port (`adapters/persistence/audit_port.py`)
- Ingestion sink (`adapters/persistence/ingestion_sink.py`)
- Migrations (`adapters/persistence/migrations.py`)
- Workflow worker (`application/worker.py`)
- NATS consumer (`workers/consumer.py`)
- Inbox/outbox tables and dedup logic
- Observability (`observability/`)
- Test harness structure (`tests/`)

## Components needing redesign

- Domain models/events/policies (ITSM incident -> security audit event)
- LangGraph nodes and services (triage/diagnostics -> detection/investigation)
- API routes (ingestion -> security event ingestion)
- Canonical event contract (new fields)
- Scenario harness (ITSM scenarios -> security audit scenarios)

## Components to retire

- ITSM adapters (`adapters/itsm/`)
- Identity adapters for ITSM (repurpose for security identity)
- Infrastructure simulators for service health/restart
- Mockoon fixtures for ITSM/incident flows (replace with source simulators)

## Known debt

- ITSM-centric naming throughout codebase.
- Policy matrix tuned to remediation actions, not audit findings.
- Scenario inventory (24 ITSM scenarios) needs replacement.
- Documentation references ITSM product; being pivoted.

## Known limitations

- Reuse assessment is static; runtime verification not performed.
- Some components may be partially reusable after refactor.
