# SOP-04 — Recover a consumer checkpoint or stalled consumer

Scope: the durable NATS consumer, the PostgreSQL idempotency ledger, and the
collector cursor table.
Audience: on-call operator with NATS monitoring and PostgreSQL read access.

## Purpose

Restore forward progress when the detection consumer stops advancing, and
distinguish three different things this repository calls a "checkpoint":

1. the JetStream durable consumer's delivery state (`itsm-workflow`);
2. the `processing_records` idempotency ledger;
3. the `source_checkpoints` collector cursor.

They fail differently. Treating one as another is how duplicate work or
false "recovery" happens.

## Scope

In scope:

- `JetStreamConsumer` / `ensure_consumer`
  (`src/itsm_agent/adapters/messaging/nats_bus.py:118-209`).
- `consume_source_event` (`src/itsm_agent/application/audit_consumer.py`).
- `processing_records` (`migrations/006_audit_processing.sql`).
- `source_checkpoints` (`migrations/002_source_events.sql:60-70`) and the
  collectors that write it
  (`src/itsm_agent/collectors/aws/cloudtrail.py:146-178`,
  `src/itsm_agent/collectors/postgresql/pgaudit.py`,
  `src/itsm_agent/collectors/github/audit_log.py`).
- The worker process (`src/itsm_agent/workers/consumer.py`).

Out of scope: ingestion failures (SOP-02) and dead-letter replay (SOP-03).

## Preconditions

- Stack running (`docker compose ps`), with `nats` monitor port reachable.
- `NATS_URL`, `NATS_MONITOR_HOST_PORT`, and the database connection values
  are available.
- Administration database access for any write. Reads should include an
  explicit `tenant_id` filter even on a superuser connection.
- The tenant and source are known.

## Symptoms and triggers

| Symptom | Likely cause | First check |
| --- | --- | --- |
| `ITSM_EVENTS` message count not decreasing | consumer stopped or failing | worker logs; consumer state |
| Worker logs repeat `message outcome=retry` | handler exception below `max_deliver` | `processing_records.last_error` |
| Worker logs repeat `message outcome=duplicate` | redelivery after a lost ACK | expected; check for progress, not zero duplicates |
| `num_ack_pending` grows | consumer fetched but never ACKed | worker crash or blocked DB transaction |
| `processing_records` has `FAILED` rows | detection raised | `last_error` |
| `processing_records` has `PROCESSING` rows older than the run | committed by a non-standard writer | see step 6 |
| `source_checkpoints.updated_at` is old | collector not running | no collector is scheduled in `compose.yaml`; this is expected |
| Events accepted but no findings | detection produced zero findings, or event not processed | compare ledger and findings |

## Procedure

### 1. Confirm the worker process

```sh
docker compose ps
docker compose logs --tail 200 worker
```

Look for the startup line `worker started: concurrency=...`
(`src/itsm_agent/workers/consumer.py:235`). If the process is restarting,
fix the startup error first. `verify_runtime_database` aborts startup when
the database role is unsafe
(`src/itsm_agent/adapters/persistence/privileges.py`, called from
`consumer.py:82-84`).

### 2. Snapshot broker state

```sh
curl -s "http://127.0.0.1:${NATS_MONITOR_HOST_PORT:-8222}/jsz?streams=true&consumers=true" \
  | python3 -m json.tool | head -120
```

Record for `ITSM_EVENTS`:

- `state.messages` (messages retained; WorkQueue removes them on ack)
- `state.first_seq` / `state.last_seq`

Record for the `itsm-workflow` consumer:

- `num_pending`, `num_ack_pending`, `num_redelivered`

`ITSM_EVENTS` uses WorkQueue retention, so a message that was acked is gone;
an unacked message is still the only broker copy
(`docs/nats-stream-config.md:5-6,24-28`).

### 3. Identify one affected event

Use a bounded window and a tenant filter:

```sql
-- Replace <tenant-uuid>, <source>, and the window.
SELECT id, event_id, processing_version, status, started_at, completed_at,
       finding_ids, last_error
FROM processing_records
WHERE tenant_id = '<tenant-uuid>'::uuid
  AND source = '<source>'
  AND started_at >= now() - interval '2 hours'
ORDER BY started_at DESC
LIMIT 50;
```

Then confirm the canonical row exists and belongs to the same tenant:

```sql
SELECT id, tenant_id, source, event_time, ingested_at
FROM source_events
WHERE tenant_id = '<tenant-uuid>'::uuid
  AND id = '<event-id>'::uuid;
```

A missing canonical row is not a checkpoint problem. It is an ingestion or
replay problem (SOP-02), or a tenant mismatch that must be escalated.

### 4. Confirm what "done" means for that event

`processing_records` is the idempotency ledger. Its unique key is
`(tenant_id, source, event_id, processing_version)`
(`migrations/006_audit_processing.sql:26-29`). Status meanings:

- `COMPLETED` — detection ran; `finding_ids` may be empty because the rules
  produced no finding. This is not a lost event.
- `FAILED` — detection raised; the next delivery resets it to `PROCESSING`
  and retries
  (`src/itsm_agent/adapters/persistence/repositories.py:1119-1128`).
- `PROCESSING` — a claim exists. This path claims and completes inside one
  transaction (`src/itsm_agent/application/audit_consumer.py:57-120`), so a
  crash rolls the claim back. A committed `PROCESSING` row is therefore
  suspicious.

Verify the findings named by a completed record:

```sql
SELECT id, tenant_id, finding_type, severity, status, detected_at
FROM findings
WHERE tenant_id = '<tenant-uuid>'::uuid
  AND id = ANY ('{<finding-id>,<finding-id>}'::uuid[]);
```

### 5. Recover by restart (the normal path)

Restarting the worker re-creates the durable consumer
(`src/itsm_agent/workers/consumer.py:233-234` calls `ensure_consumer`).
`ensure_consumer` deletes the existing consumer and creates it again with
`DeliverPolicy.ALL`
(`src/itsm_agent/adapters/messaging/nats_bus.py:148-166`). Consequences:

- Every unacked message in `ITSM_EVENTS` is redelivered.
- A message whose durable commit succeeded but whose ACK was lost is
  reprocessed; `processing_records` short-circuits it as `COMPLETED`, so no
  duplicate finding is produced.
- The previous consumer cursor is **not** resumed. This is deliberate in the
  current code (the comment says it starts runs from a clean delivery state)
  but it means "checkpoint recovery" here is replay plus idempotency, not
  offset restore.

```sh
docker compose restart worker
docker compose logs --tail 200 worker
```

The worker is bounded: `max_deliver=3` and a 1-2 second fetch timeout
(`consumer.py:251-252,295-296`). A message that fails three times is
dead-lettered (SOP-03), not retried forever.

### 6. Handle a committed `PROCESSING` row

Only after confirming no worker is actively processing the event (check the
worker logs and current connections), mark the stale row `FAILED` so the next
delivery reclaims it:

```sql
-- Replace <record-id> and the timestamp. Record the reason.
UPDATE processing_records
SET status = 'FAILED',
    last_error = 'operator reset: stale PROCESSING at <utc-timestamp>'
WHERE id = '<record-id>'::uuid
  AND status = 'PROCESSING';
```

Do not set a record to `COMPLETED` by hand. That would suppress detection
without evidence. If the record is already `COMPLETED` and you believe
detection is wrong, the supported mechanism is a new `processing_version`
(the unique key includes it), which is a code change, not an operator edit.

### 7. Requeue an event that is in no queue and has no ledger row

If `source_events` has the row, no `processing_records` row exists, and no
NATS message remains, the event fell between publish and processing. Use the
bounded replay helper from SOP-02 (step 8). It creates a
`SourceEventReplayed` outbox row; it does not rewrite evidence. This assumes
the `relay` service (or `python -m itsm_agent.workers.relay`) is running; if
it is not, the new row will also stay `pending` (SOP-02, Known limitations).

Before replaying, reconcile:

```sql
SELECT
  (SELECT count(*) FROM source_events
    WHERE tenant_id = '<tenant-uuid>'::uuid AND source = '<source>') AS canonical,
  (SELECT count(*) FROM processing_records
    WHERE tenant_id = '<tenant-uuid>'::uuid AND source = '<source>') AS ledger,
  (SELECT count(*) FROM processing_records
    WHERE tenant_id = '<tenant-uuid>'::uuid AND source = '<source>'
      AND status = 'COMPLETED') AS completed;
```

Large gaps are an incident, not a routine replay. Do not bulk-replay a
window larger than the helper's `limit` (1-1000) without a written plan.

## Verification

- `ITSM_EVENTS.state.messages` is 0 or decreasing, and the consumer's
  `num_ack_pending` returns to 0.
- New events produce `processing_records` rows with `COMPLETED` and, when
  the rules fire, findings.
- No new DLQ entries appear (SOP-03).
- `source_checkpoints.updated_at` advances only if a collector is actually
  running; absence is not evidence of a consumer fault.

## At-least-once semantics

The repository never claims exactly-once (`README.md`;
`docs/nats-stream-config.md`).

- The outbox relay marks a row published only after broker acknowledgement
  (`src/itsm_agent/adapters/messaging/outbox_relay.py:81-94`).
- The consumer ACKs only after the detection transaction commits
  (`src/itsm_agent/application/audit_consumer.py:186`).
- A crash between commit and ACK causes redelivery; the ledger suppresses
  duplicate findings.
- A crash before commit causes redelivery with no committed state.
- A message that exhausts retries is dead-lettered, not silently resolved.

## Reconciliation before replay

Do these checks in order; stop at the first mismatch:

1. `source_events` row exists and its tenant equals the message tenant
   (`src/itsm_agent/application/audit_consumer.py:57-71`).
2. `processing_records` has at most one row for
   `(tenant, source, event_id, processing_version)` (enforced by the unique
   constraint).
3. If `COMPLETED`, the `finding_ids` either resolve to findings or are
   legitimately empty.
4. If `FAILED`, the error is understood and the cause is fixed.
5. No live NATS message exists for the event before creating a replay row.

## Rollback and recovery

- There is no checkpoint file to restore. The broker holds unacked messages;
  PostgreSQL holds the ledger and evidence.
- Do not delete `ITSM_EVENTS` or its stream to "reset" the consumer. That
  removes the only copy of unacked events.
- Do not truncate `processing_records` to force reprocessing. It is the
  audit trail of what detection did.
- If the database is restored from backup, events acked after the backup are
  lost from the ledger; replay the source window only after reconciling
  against `source_events`.
- Migrations are forward-only; there is no schema rollback
  (`docs/production-readiness.md:10-11`).

## Escalation

| Condition | Escalate to | Timing |
| --- | --- | --- |
| Ledger and canonical store disagree for more than one tenant | `<platform-owner>` + `<data-owner>` | immediate |
| Tenant mismatch between message and canonical row | `<security-lead>` | immediate |
| Repeated consumer crash after restart | `<platform-owner>` | within 1 hour |
| Replay required for a window larger than 1000 events | `<platform-owner>` | before executing |
| Suspected loss of acked events | `<data-owner>` | immediate |

## Evidence to capture

- Worker log excerpt showing startup and the last 50 outcome lines.
- NATS monitoring JSON for `ITSM_EVENTS` and `itsm-workflow` before/after.
- `processing_records` rows for the affected event(s), including status,
  `processing_version`, `last_error`, and `finding_ids`.
- `source_events` row id and tenant id.
- Restart timestamps and the resulting redelivery counts.
- Any replay command and its bound.
- Do not capture payloads, tokens, or database passwords.

## Known limitations

- `ensure_consumer` deletes and recreates the durable consumer on every
  worker start (`src/itsm_agent/adapters/messaging/nats_bus.py:151-165`).
  There is no offset-resume path, and every restart redelivers all unacked
  messages. Idempotency is the correctness mechanism; expect duplicate log
  lines.
- There is no lease or reaper for `processing_records`. A `PROCESSING` row
  committed by an out-of-band writer blocks that event until an operator
  intervenes.
- `source_checkpoints` is a collector cursor, not a consumer checkpoint. It
  is written when `checkpoint_repo` is supplied
  (`src/itsm_agent/collectors/aws/cloudtrail.py:174-177`) and is advanced
  before the returned events are durably accepted. No collector is scheduled
  in `compose.yaml`; the table can legitimately be empty or stale.
- `replay_source_events` does not set the RLS tenant context and sees zero
  rows on a `NOBYPASSRLS` runtime role
  (`src/itsm_agent/application/replay.py:26-39`). Run it on the
  administration connection.
- The `itsm_queue_depth` gauge exists
  (`src/itsm_agent/observability/metrics.py:40-44`) but no producer calls
  `observe_queue_depth` in this slice, so do not use `/metrics` as the lag
  source; use the NATS monitor endpoint.
- NATS is single-node in this repository; no cluster failover or replication
  is tested (`docs/nats-stream-config.md:30-33`).
