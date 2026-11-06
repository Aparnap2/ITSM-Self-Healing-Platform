# Event-Driven, Evidence-First Agentic Security Audit System

A headless security audit platform: it ingests security events from AWS
CloudTrail, pgAudit, GitHub, and identity/approval sources, preserves
immutable evidence, runs deterministic detection and policy evaluation,
selectively invokes bounded agentic investigation, and produces an
auditable evidence bundle for a human reviewer — without claiming
certification.

**The point:** agentic reasoning inside deterministic audit boundaries. The
LLM proposes and explains; policy code authorizes; allowlisted adapters
execute; an independent verifier establishes success. A model proposal is
never authorization.

## Status

**Working vertical slice, not production ready.** One canonical event can
now travel the whole durable path:

```
source event ──► PostgreSQL (inbox + source_events + outbox, one transaction)
             ──► outbox relay ──► NATS JetStream
             ──► durable detection consumer (tenant re-validated against PG)
             ──► identity/resource resolution ──► deterministic detection
             ──► findings + processing_records (same transaction) ──► ACK
             ──► reviewer HTTP API ──► append-only review decisions
```

Proven by tests running against real PostgreSQL and NATS JetStream (not mocks):

- **Atomic acceptance** — inbox receipt, canonical source event, and outbox
  record commit in one transaction; duplicates return `DUPLICATE` and are
  not re-published.
- **At-least-once processing** — the consumer is idempotent on
  `(tenant_id, source, event_id, processing_version)`. Redelivery after a
  crash between commit and ACK creates **no duplicate findings**; the
  completed record short-circuits and the message is ACKed.
- **Canonical-state trust** — the consumer re-reads the event from
  PostgreSQL and rejects a message whose tenant does not match the stored
  tenant. Unknown events are rejected (dead-lettered) and leave no
  processing record.
- **Tenant isolation** — two tenants with identical external event ids
  produce isolated findings and processing records; cross-tenant reads
  return 404.
- **Deterministic detection** — privilege escalation, failed-access
  patterns, and approval-evidence checks (`MISSING_APPROVAL`,
  `DENIED_APPROVAL`, `EXPIRED_APPROVAL`, `REVOKED_APPROVAL`,
  `MISMATCHED_APPROVAL`, coverage gaps, inconclusive). No LLM is called on
  this path.
- **Append-only review** — reviewer decisions are insert-only and
  tenant-scoped, and survive an API process restart.
- **Authenticated reviewer boundary** — bearer-token verification, RBAC
  (`auditor` / `analyst` / `reviewer` / `admin`), tenant-membership checks, and
  actor provenance taken from the credential (never the request body). Tested
  offline and against real PostgreSQL.
- **Database-enforced tenant isolation** — PostgreSQL row-level security
  (enabled *and* forced) on every tenant-owned table, keyed on a
  transaction-local context. Missing context sees zero rows; pooled
  connections cannot leak a tenant across transactions.
- **Retention and erasure semantics** — append-only evidence is never
  rewritten: expiry records a tombstone that preserves the integrity hash,
  while only rebuildable derived projections are deleted. Legal holds block
  execution.

At-least-once delivery only. There is no exactly-once claim anywhere in this
repository: PostgreSQL is canonical, NATS is transport, and consumers must
be idempotent.

### Explicitly not done yet

- The HMAC bearer is a minimal replaceable point, not an IdP: no key
  rotation, revocation, or server-side role freshness. An OIDC relying party
  is implemented (`src/itsm_agent/api/oidc.py`) with offline security tests,
  but it is not wired into a deployed entrypoint. mTLS is still absent.
- Retention has no always-on scheduler worker in this baseline: the
  scheduler is implemented and lifecycle-tested
  (`src/itsm_agent/privacy/scheduler.py`,
  `tests/integration/test_retention_scheduler_lifecycle.py`), but it is not
  wired to a deployed entrypoint, so erasure is invoked programmatically.
- No pagination, no finding status transitions (decisions are append-only
  annotations), and no management API for principals, roles, or tenants.
- Forced RLS covers the audit domain plus the incident/workflow/action/
  approval/audit tables added by `migrations/011_tenant_owned_workflow.sql`;
  it does not cover tables outside that set.
- The worker has a packaged entrypoint (`Dockerfile` CMD is
  `python -m itsm_agent.workers.consumer`); there is no packaged console
  entrypoint for the API server, which is composed programmatically.
- The Jira Service Management adapter is not implemented; Mockoon remains
  the audited acceptance connector for ITSM.
- No production deployment has been validated. Nothing here is "production
  ready"; see `IMPLEMENTATION_PLAN.md` for the acceptance gate history.

## Stack

Python 3.12 · Pydantic v2 · LangGraph (PostgreSQL checkpointing) ·
PostgreSQL (durable source of truth) · NATS JetStream (event backbone) ·
Mockoon (deterministic HTTP simulators) · Moto (AWS API simulator) ·
Ollama / Groq-compatible endpoint (optional LLM) · OpenTelemetry /
Prometheus.

Headless by design: no UI, no dashboard.

## Repository layout

```text
src/itsm_agent/
  domain/            canonical event contract, models, identity resolution
  detection/         deterministic detection rules (no LLM, no I/O)
  investigations/    bounded LLM-assisted investigation (proposes only)
  reporting/         evidence bundle assembly
  application/       use cases: replay, ITSM worker, audit consumer
  ports/             protocols (repositories, adapters, LLM)
  adapters/          psycopg repositories, NATS bus, sources, simulators
  api/               FastAPI ingestion webhook + findings/reviewer surface
  workers/           long-running consumer entrypoints
simulators/          Mockoon fixtures, infrastructure simulator, seeds
tests/               unit, contract, integration, security,
                     fault_injection, scenarios, e2e
evals/               evaluation datasets and generated reports
docs/                architecture, ADRs, runbooks, API contracts
migrations/          forward-only PostgreSQL migrations (001-006)
ci/                  NATS server config used by CI and local integration runs
```

## The durable pipeline in code

| Stage | Entry point |
| --- | --- |
| Canonical event + atomic accept | `adapters/persistence/ingestion_sink.py` (`PsycopgSourceEventSink.accept_source_event`) |
| Outbox → JetStream | `adapters/messaging/outbox_relay.py` (`OutboxRelay.relay_once`) |
| JetStream publish/consume, DLQ | `adapters/messaging/nats_bus.py` |
| Durable detection consumer | `application/audit_consumer.py` (`consume_source_event`) |
| Idempotency ledger | `migrations/006_audit_processing.sql` (`processing_records`) |
| Deterministic rules | `detection/engine.py` (`run_detection`) |
| Findings + decisions persistence | `adapters/persistence/repositories.py` |
| Reviewer API | `api/routes/findings.py` |

`consume_source_event` performs: envelope validation → poison-message
dead-lettering → canonical tenant re-read → processing claim → detection →
findings upsert + `COMPLETED` record in one transaction → ACK. Retries are
bounded; exhausted messages are dead-lettered rather than silently resolved.

## HTTP surface

### Ingestion (existing, signed)

`POST /v1/incidents/webhook` — HMAC-signed, replay-protected, rate-limited,
strict schema. ACKs only after durable commit.

### Findings queue and reviewer decisions

Tenant scoping is a required query parameter on every call. A finding that
belongs to another tenant is reported as `404`, exactly like a missing one.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/findings?tenant_id=…` | List findings for a tenant |
| `GET` | `/v1/findings/{id}?tenant_id=…` | Finding detail + its decisions |
| `POST` | `/v1/findings/{id}/decisions?tenant_id=…` | Append a reviewer decision (`201`) |
| `GET` | `/v1/findings/{id}/decisions?tenant_id=…` | List decisions for a finding |

```bash
curl -s -H "Authorization: Bearer $REVIEWER_TOKEN" \
  "http://localhost:8000/v1/findings?tenant_id=$TENANT_ID"

curl -s -X POST \
  -H "Authorization: Bearer $REVIEWER_TOKEN" \
  "http://localhost:8000/v1/findings/$FINDING_ID/decisions?tenant_id=$TENANT_ID" \
  -H 'content-type: application/json' \
  -d '{
        "decision": "CONFIRMED",
        "rationale": "AssumeRole to Admin by an unapproved principal.",
        "evidence_pack_ref": "bundle-2026-11-01-001"
      }'
```

Decision body: `decision` in
`CONFIRMED | FALSE_POSITIVE | ACCEPTED_RISK | NEEDS_MORE_EVIDENCE`,
`rationale` (1–2000 chars), optional `evidence_pack_ref`. `reviewer_id` is
derived from the credential and rejected in the body. Status codes:
`200` read, `201` appended, `401` missing/invalid credential, `403`
cross-tenant or missing permission, `404` unknown/cross-tenant, `422` invalid
body,
`503` store not configured. Full contract and known gaps:
[`docs/findings-api.md`](docs/findings-api.md). Tokens are minted out of band
with `itsm_agent.api.auth.mint_token`; there is no token endpoint yet.

## Local development

Integration tests expect PostgreSQL and NATS JetStream. CI uses these
exact shapes; locally they are published on **5544** and **4224** to avoid
clashing with other projects.

```bash
# PostgreSQL 16
docker run -d --name itsm-test-pg \
  -e POSTGRES_USER=itsm -e POSTGRES_PASSWORD=itsm -e POSTGRES_DB=itsm_test \
  -p 5544:5432 postgres:16

# NATS with JetStream
docker run -d --name itsm-test-nats -p 4224:4222 -p 8224:8222 \
  -v "$PWD/ci/nats.conf:/etc/nats/nats-server.conf:ro" nats:2

# Apply migrations (forward-only, idempotent, tracked in schema_migrations)
uv run python -m migrations.apply \
  --dsn "postgresql://itsm:itsm@localhost:5544/itsm_test"

# Run everything under strict mode (unreachable services fail, never skip)
ITSM_TEST_STRICT=1 \
ITSM_TEST_PG_DSN="postgresql://itsm:itsm@localhost:5544/itsm_test" \
ITSM_TEST_NATS_URL="nats://localhost:4224" \
uv run pytest -q
```

Targeted suites:

```bash
uv run pytest -m unit -q                 # no network, no containers
uv run pytest -m contract -q             # Mockoon/Moto/respx, offline
uv run pytest -m security -q             # fail-closed invariants
uv run pytest -m integration -q          # real PostgreSQL + NATS
uv run pytest -m fault_injection -q      # deterministic failure modes
uv run pytest -m scenarios -q            # scenario harness
uv run pytest -m e2e -q                  # end-to-end acceptance
```

Quality gates (all must be green before a push):

```bash
uv run ruff format --check . && uv run ruff check . && uv run mypy src tests
```

### Running the worker

Set `ITSM_POSTGRES_DSN` and `ITSM_NATS_URL`, then:

```bash
python -m itsm_agent.workers.consumer
```

Environment: `ITSM_POSTGRES_DSN`/`DATABASE_URL`,
`ITSM_NATS_URL`/`NATS_URL`, `ITSM_WORKER_CONCURRENCY` (default 4),
`ITSM_WORKER_SHUTDOWN_TIMEOUT` (default 30), `ITSM_SIMULATOR_SEED`
(default 42). The worker subscribes to `itsm.events.>` on the `ITSM_EVENTS`
stream (durable consumer `itsm-workflow`), ACKs only after durable
processing, NAKs transient failures, and dead-letters poison messages.
The security-audit consumer is composed the same way but has no packaged
entrypoint yet (see limitations).

## Safety invariants

These are enforced in code and covered by tests; they are the reason the
LLM cannot talk its way into an action.

1. Unknown action, target, or principal → deny (fail closed).
2. A model proposal is not authorization; deterministic policy decides.
3. Approval is exact-action-bound, unexpired, single-use, and revalidated.
4. No side effect before durable action intent and policy decision.
5. Uncertain outcome → reconcile target state before any retry.
6. A tool success response is not proof of recovery; an independent
   verifier establishes success.
7. No resolution without independent postcondition verification.
8. Terminal outcomes carry required audit records; retry exhaustion
   escalates, never silently resolves.
9. Tenant ownership is re-read from PostgreSQL before processing; message
   metadata is not trusted.
10. No secrets in Git, logs, traces, test output, or audit payloads.
    Deterministic tests never require a remote LLM, SaaS, or internet.
11. Reviewer identity and tenant scope come from a verified credential, never
    from the request body; RBAC is deny-by-default.
12. Tenant isolation is enforced by PostgreSQL RLS *and* by query predicates;
    missing tenant context sees zero rows (fail closed).
13. Append-only evidence is never rewritten by retention; erasure preserves
    an integrity tombstone and deletes only rebuildable projections.

## Documentation

- [`PRD.md`](PRD.md) — full specification, contracts, SOPs, test plan
- [`docs/architecture.md`](docs/architecture.md) — system boundaries,
  component responsibilities, trust boundaries, import rules
- [`docs/adr/`](docs/adr/) — architecture decision records: hexagonal
  ports/adapters, inbox/outbox durable publishing, Moto vs LocalStack
  licensing, LangGraph checkpointing, deny-by-default policy
- [`docs/event-contract.md`](docs/event-contract.md) — canonical event
  fields, timestamp and schema-versioning rules
- [`docs/source-integration-matrix.md`](docs/source-integration-matrix.md) —
  source coverage and trust levels
- [`docs/security-boundaries.md`](docs/security-boundaries.md) —
  authentication, RBAC, row-level security, and the honest gaps
- [`docs/privacy-retention.md`](docs/privacy-retention.md) — retention,
  legal hold, erasure tombstones, and redaction
- [`docs/findings-api.md`](docs/findings-api.md) — findings queue and
  reviewer-decision HTTP contract (tenant scoping, status codes,
  evidence-first invariants, known gaps)
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — task status, commit
  evidence, and the CI acceptance gate

## License

Proprietary. See `pyproject.toml`.
