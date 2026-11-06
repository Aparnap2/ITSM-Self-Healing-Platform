# SOP-02 — Triage and recover an ingestion failure

Scope: the durable ingestion path from a signed webhook or collector to
PostgreSQL and NATS JetStream.
Audience: on-call operator with read access to PostgreSQL and NATS; writes
require the administration connection.

## Purpose

Restore event acceptance without losing or duplicating evidence, and show
exactly where the event stopped. The pipeline is at-least-once end to end
(`docs/nats-stream-config.md`); recovery means making durable state visible
again, not forcing an event through.

## Scope

In scope:

- `POST /v1/incidents/webhook` (`src/itsm_agent/api/routes/ingestion.py`).
- `PsycopgIngestionSink` / `PsycopgSourceEventSink`
  (`src/itsm_agent/adapters/persistence/ingestion_sink.py`).
- `event_inbox`, `source_events`, `outbox`, `source_checkpoints`
  (`migrations/001_initial_schema.sql`, `migrations/002_source_events.sql`).
- `OutboxRelay` (`src/itsm_agent/adapters/messaging/outbox_relay.py`).

Out of scope: dead-letter replay (SOP-03), consumer/checkpoint recovery
(SOP-04), tenant provisioning (SOP-05).

## Preconditions

- Repository root, with the local stack from SOP-01 running:
  `docker compose ps` shows `postgres`, `nats`, and the application healthy.
- `POSTGRES_USER`, `POSTGRES_DB`, and `NATS_MONITOR_HOST_PORT` are available
  in the shell (same values as `.env`).
- A read-only database connection. All repairs below need the
  administration/owner connection; the runtime role `itsm_app` is
  `NOBYPASSRLS` and cannot manage tenancy (`migrations/010_runtime_role.sql`,
  `migrations/014_least_privilege_tenant_registry.sql`).
- The tenant UUID, source name (`cloudtrail`, `pgaudit`, `github`, `identity`),
  and approximate event time are known.

## Symptoms and triggers

| Symptom | Likely layer | First check |
| --- | --- | --- |
| Webhook returns `503 {"status":"unavailable"}` | sink commit failed | `outbox`/`event_inbox` counts; database health |
| Webhook returns `202` but the consumer never sees the event | outbox relay or broker | `outbox.status = 'pending'`; NATS stream depth |
| Webhook returns `200 {"status":"duplicate"}` unexpectedly | inbox dedup | `event_inbox` unique key |
| `outbox` rows accumulate with `status = 'pending'` | relay cannot publish | relay logs; NATS reachability |
| `outbox` rows with `status = 'failed'` | retry budget exhausted | `last_error`, `attempts` |
| `source_events` row exists but no finding appears | downstream consumer | SOP-04 |
| Collector cursor moved but no event was stored | collector/replay boundary | `source_checkpoints` vs `source_events` |

The webhook returns only `202` after a durable commit, `200` for a duplicate,
`422` for an invalid payload, `503` when durable acceptance failed, and
`401`/`413`/`429` for security rejections
(`src/itsm_agent/api/routes/ingestion.py:15-16`).

## Procedure

Work through the steps in order. Do not skip to replay: replaying an event
that is still queued is the most common way to create a duplicate storm.

### 1. Confirm the stack and capture a baseline

```sh
docker compose ps
docker compose logs --tail 100 api
docker compose logs --tail 100 worker
```

Capture the current counts before changing anything.

```sh
docker compose exec postgres psql \
  -U "${POSTGRES_USER:-itsm}" -d "${POSTGRES_DB:-itsm}" -v ON_ERROR_STOP=1
```

```sql
-- Replace <tenant-uuid>. Always filter explicitly: an administration
-- connection can bypass RLS, so a missing WHERE clause is a real risk.
SELECT 'event_inbox' AS table_name, status, count(*)
FROM event_inbox
WHERE tenant_id = '<tenant-uuid>'::uuid
GROUP BY status
UNION ALL
SELECT 'outbox', status, count(*)
FROM outbox
WHERE tenant_id = '<tenant-uuid>'::uuid
GROUP BY status
ORDER BY table_name, status;
```

### 2. Inspect the inbox for the affected event

```sql
SELECT id, source_system, external_event_id, status, attempt_count,
       received_at, last_error
FROM event_inbox
WHERE tenant_id = '<tenant-uuid>'::uuid
ORDER BY received_at DESC
LIMIT 20;
```

The dedup key is `(tenant_id, source_system, external_event_id)`
(`migrations/009_tenant_scoped_inbox.sql`). A second delivery of the same
key is `DUPLICATE` and must not be re-enqueued.

### 3. Inspect `source_events`

```sql
SELECT id, source, source_event_id, idempotency_key, event_time,
       ingested_at, payload_hash
FROM source_events
WHERE tenant_id = '<tenant-uuid>'::uuid
  AND source = '<source>'
ORDER BY ingested_at DESC
LIMIT 20;
```

`source_events` is append-only: `UPDATE` and `DELETE` raise
(`migrations/002_source_events.sql:46-58`). Never attempt to edit it to
"repair" an event.

### 4. Inspect the outbox and decide the failure class

```sql
SELECT status, count(*), min(created_at) AS oldest, max(created_at) AS newest
FROM outbox
WHERE tenant_id = '<tenant-uuid>'::uuid
GROUP BY status;
```

```sql
SELECT id, event_type, aggregate_id, attempts, last_error, next_attempt_at
FROM outbox
WHERE tenant_id = '<tenant-uuid>'::uuid
  AND status IN ('pending', 'failed')
ORDER BY created_at
LIMIT 20;
```

- `pending` with a future `next_attempt_at` is a normal retry lease
  (`claim_pending`, `src/itsm_agent/adapters/persistence/repositories.py:324-361`).
- `pending` with an old `next_attempt_at` means the relay is not running or
  cannot reach NATS.
- `failed` is terminal after `max_attempts` (default 10,
  `src/itsm_agent/adapters/messaging/outbox_relay.py:44-57`,
  `src/itsm_agent/adapters/persistence/repositories.py:381-401`).

### 5. Check the broker and stream depth

```sh
curl -s "http://127.0.0.1:${NATS_MONITOR_HOST_PORT:-8222}/jsz?streams=true&consumers=true" \
  | python3 -m json.tool | head -80
```

Read `streams[].state.messages` for `ITSM_EVENTS` and `ITSM_DLQ`, and the
consumer entry for `itsm-workflow` (`docs/nats-stream-config.md`). If the
monitor port does not answer, stop here: broker recovery is a prerequisite,
not an ingestion fix.

### 6. Repair the correct layer

| Finding | Action |
| --- | --- |
| Relay not running | start the deployment's `OutboxRelay.run()` process (none is wired in `compose.yaml`; see Known limitations) |
| NATS unreachable | restore NATS, then let `pending` rows drain |
| `failed` rows, broker now healthy | reconcile first, then reset to `pending` (step 7) |
| Event absent from `outbox` and `source_events` | the request never committed; the sender must retry |
| Event present, consumer lagging | SOP-04 |
| Event dead-lettered | SOP-03 |

Restart the affected process after a configuration fix. `worker` is the
consumer; a relay process supplied by the deployment must be restarted by its
own supervisor (there is no relay service in `compose.yaml`).

```sh
docker compose restart worker
```

Do not restart PostgreSQL or delete volumes to clear a backlog. The local
`make compose-reset` deletes data and is not a recovery step.

### 7. Reset terminal outbox rows only after reconciliation

Before resetting a `failed` row, confirm the message is not already in
JetStream under the same aggregate id. Check the stream state from step 5 or
look for a consumer record. If the publish may have succeeded, a reset can
produce a duplicate; consumers deduplicate, but the duplicate is still noise
and must be recorded.

```sql
-- One row at a time. Replace <outbox-id>.
UPDATE outbox
SET status = 'pending', attempts = 0, next_attempt_at = now(), last_error = NULL
WHERE id = '<outbox-id>'::uuid
  AND status = 'failed';
```

Use the administration connection. Re-run the step 4 query afterwards.

### 8. Replay an event that was durably accepted but never processed

Only when the `source_events` row exists, the tenant matches, and there is no
live outbox row for it. The bounded helper is
`src/itsm_agent/application/replay.py`:

```sh
# Replace the tenant, source, and window. limit is 1..1000 by contract.
# Use the administration DSN: the runtime role's RLS context is unset here.
uv run python - <<'PY'
import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.application.replay import replay_source_events


async def main() -> None:
    pool = create_pool(
        PersistenceConfig(dsn=os.environ["ADMIN_DATABASE_URL"], max_size=2)
    )
    await pool.open()
    try:
        ids = await replay_source_events(
            pool,
            tenant_id=UUID("<tenant-uuid>"),
            source="<source>",
            start=datetime.now(UTC) - timedelta(hours=1),
            end=datetime.now(UTC),
            limit=100,
        )
        print(f"requeued={len(ids)} first={ids[:5]}")
    finally:
        await pool.close()


asyncio.run(main())
PY
```

The helper inserts one `SourceEventReplayed` outbox row per source event and
skips an event that already has one
(`src/itsm_agent/application/replay.py:41-63`). It never rewrites
`source_events`.

## Deduplication and idempotency

| Boundary | Key | Behaviour |
| --- | --- | --- |
| Webhook inbox | `(tenant_id, source_system, external_event_id)` | second insert is `DUPLICATE`, returns `200` (`migrations/009_tenant_scoped_inbox.sql`, `src/itsm_agent/adapters/persistence/repositories.py:224-253`) |
| Canonical store | `(tenant_id, idempotency_key)` | unique constraint (`migrations/002_source_events.sql:37-39`) |
| Outbox replay | `(aggregate_id, event_type = 'SourceEventReplayed')` | checked before insert (`src/itsm_agent/application/replay.py:44-50`) |
| Consumer | `(tenant_id, source, event_id, processing_version)` | `COMPLETED` short-circuits (`migrations/006_audit_processing.sql:28`) |
| Transport | NATS at-least-once | redelivery is expected; ack after the durable commit (`docs/nats-stream-config.md`) |

Resubmitting the original webhook is not a replay mechanism; the inbox
returns `DUPLICATE` and no outbox row is created.

## Verification

- `outbox` has no `pending` rows older than the relay poll interval and no
  unexplained `failed` rows for the tenant.
- A new signed event for the tenant returns `202`, appears once in
  `source_events`, appears once in `outbox` with `published`, and produces a
  finding or a processing record (whichever your source path owns).
- Re-sending the same event returns `200 duplicate` and does not add a row.
- Two consecutive counts of `source_events` for the event id are identical
  (no evidence rewrite).

## Rollback and recovery

- There is no down-migration path; migrations are forward-only
  (`docs/migration-safety.md`, `docs/production-readiness.md`).
- An incorrect repair is undone from a database backup, not by editing
  evidence. `source_events` and `audit_events` reject `UPDATE`/`DELETE`
  (`migrations/001_initial_schema.sql:171-182`).
- Stopping ingestion is safe: the API returns `503` rather than accepting
  without a durable commit. Stop the relay/worker with
  `docker compose stop worker`; resume with `docker compose start worker`.

## Escalation

| Condition | Escalate to | Timing |
| --- | --- | --- |
| Data loss suspected (`source_events` missing after a `202`) | `<platform-owner>` + `<security-lead>` | immediate |
| `failed` outbox rows span tenants | `<platform-owner>` | within 1 hour |
| Broker unavailable or stream lost | `<platform-owner>` | immediate |
| Suspected credential or signature bypass | `<security-lead>` | immediate; preserve logs |
| Repair would touch evidence or tenancy | `<data-owner>` | before executing |

No real names, pager numbers, or credentials belong in this document or in
the incident ticket.

## Evidence to capture

- Ticket id, operator, start/end timestamps in UTC.
- Output of the step 1 and step 4 queries before and after the repair.
- Affected `event_inbox.id`, `source_events.id`, `outbox.id` values.
- Exact `last_error` strings (truncated to 2000 characters by the code) with
  secrets removed.
- NATS monitoring JSON excerpt showing stream depth and consumer state.
- The replay command used, its `requeued` count, and the resulting outbox ids.
- Confirmation that no secret, token, or raw credential appears in the
  captured output.

## Known limitations

- No service in `compose.yaml` runs `OutboxRelay.run()`, and
  `src/itsm_agent/workers/consumer.py` does not start one. In the local stack
  a webhook can commit `event_inbox` + `outbox` and the outbox row will stay
  `pending` until a relay process is run. The integration tests instantiate
  `OutboxRelay` directly (`tests/integration/test_outbox_relay.py`); a
  deployment must supply its own relay entrypoint.
- `event_inbox` status is not advanced on the source-event path:
  `PsycopgSourceEventSink` inserts `RECEIVED` and the consumer records
  progress in `processing_records`, not in the inbox
  (`src/itsm_agent/adapters/persistence/ingestion_sink.py:80-105`,
  `src/itsm_agent/adapters/persistence/repositories.py:224-285`). Do not read inbox
  status as a delivery-progress indicator.
- `replay_source_events` filters by `tenant_id` but does not set the RLS
  context; on a `NOBYPASSRLS` runtime role it sees zero rows
  (`src/itsm_agent/application/replay.py:26-39`). Run it on the administration connection, or extend it
  to use `tenant_transaction` before relying on it in a constrained
  deployment.
- There is no automated reconciliation job that compares `outbox`,
  `source_events`, and `processing_records`.
- The outbox replay check is read-then-insert, not a unique constraint; two
  concurrent operators can both enqueue the same event. Run replays one at a
  time.
- NATS is single-node in this repository; replication and stream limits are
  not validated (`docs/nats-stream-config.md`).
- The local `itsm` role is a superuser, so RLS does not constrain local
  console queries. Every query in this runbook therefore filters `tenant_id`
  explicitly.
