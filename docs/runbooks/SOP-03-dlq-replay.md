# SOP-03 — Inspect and replay the dead-letter path

Scope: messages that exhausted bounded redelivery or were rejected as poison,
held in the `ITSM_DLQ` JetStream stream.
Audience: on-call operator with NATS access and database read access.

## Purpose

Identify why a message was dead-lettered, decide whether it is replayable,
and replay only a bounded set after confirming the failure is fixed. A
dead-letter is an escalation, never a resolution
(`AGENTS.md`, safety invariant "retry exhaustion escalates").

## Scope

In scope:

- `JetStreamConsumer.dead_letter` (`src/itsm_agent/adapters/messaging/nats_bus.py:183-209`).
- `dispatch_once` bounded-redelivery decision
  (`src/itsm_agent/adapters/messaging/nats_bus.py:251-288`).
- `consume_source_event` poison handling
  (`src/itsm_agent/application/audit_consumer.py:145-184`).
- Streams `ITSM_EVENTS` and `ITSM_DLQ` (`docs/nats-stream-config.md`).
- Subjects `itsm.dlq.events` and `itsm.dlq.escalation`.

Out of scope: ingestion-layer failures (SOP-02) and consumer checkpoint
recovery (SOP-04).

## Preconditions

- The stack is running (`docker compose ps`), including `nats` with the
  monitor port (`-m 8222` in `compose.yaml`).
- `NATS_URL` and `NATS_MONITOR_HOST_PORT` are available in the shell.
- The failed tenant, source, and approximate window are known. The DLQ
  payload records the original subject but not a tenant id.
- The operator has confirmed that the underlying failure (bad schema, missing
  source event, unreachable dependency) is fixed. Replaying into a broken
  consumer only recreates the same DLQ entry.

## Symptoms and triggers

| Symptom | Meaning |
| --- | --- |
| Worker log `message outcome=dead_lettered` | handler failed at `max_deliver` |
| Worker log `poison message on <subject>` | envelope did not validate; dead-lettered immediately |
| `ITSM_DLQ` stream messages increasing | new dead-letters arriving |
| `ITSM_DLQ` has old messages and no owner | backlog never triaged |
| `itsm.dlq.escalation` message observed | redelivery exhausted signal |

The worker passes `max_deliver=3` to `consume_source_event`
(`src/itsm_agent/workers/consumer.py:251,295`); the adapter default is 5
(`src/itsm_agent/adapters/messaging/nats_bus.py:44`). Both are bounded. A poison envelope is dead-lettered on
the first delivery, so its recorded `delivery_attempt` can be `1`.

## Procedure

### 1. Capture the stream and consumer state

```sh
curl -s "http://127.0.0.1:${NATS_MONITOR_HOST_PORT:-8222}/jsz?streams=true&consumers=true" \
  | python3 -m json.tool | head -120
```

Record, for `ITSM_DLQ`:

- `state.messages`
- `state.first_seq` / `state.last_seq`
- the stream's retention and limits

`ITSM_DLQ` uses `LimitsPolicy`; in development the stream has no
`max_bytes`/`max_msgs` bound (`docs/nats-stream-config.md:16-22`). Do not
assume old entries are still present after a long delay.

### 2. Read the dead-letter entries (bounded, no acknowledgement)

Run from the repository root. The script stops after 100 entries or 20
empty polls, whichever comes first.

```sh
uv run python - <<'PY'
import asyncio
import json
import os

import nats
from nats.js.api import ConsumerConfig


async def main() -> None:
    nc = await nats.connect(
        servers=[os.environ.get("NATS_URL", "nats://127.0.0.1:4222")],
        connect_timeout=3.0,
    )
    try:
        js = nc.jetstream()
        sub = await js.pull_subscribe(
            "itsm.dlq.>", config=ConsumerConfig()
        )
        seen = 0
        for _ in range(20):
            try:
                msgs = await sub.fetch(10, timeout=0.5)
            except TimeoutError:
                break
            for msg in msgs:
                body = json.loads(msg.data.decode())
                print(
                    json.dumps(
                        {
                            "subject": msg.subject,
                            "delivery_attempt": body.get("delivery_attempt"),
                            "original_subject": body.get("original_subject"),
                            "error": (body.get("error") or "")[:200],
                            "payload_bytes": len((body.get("payload") or "").encode()),
                        }
                    )
                )
                seen += 1
                if seen >= 100:
                    break
            if seen >= 100:
                break
        print(f"inspected={seen}")
    finally:
        await nc.drain()


asyncio.run(main())
PY
```

This consumer does not ack. Do not ack during inspection: acking advances a
consumer cursor and makes later triage harder to reason about.

### 3. Classify the entry

| Signal | Class | Replayable |
| --- | --- | --- |
| `error` starts with `invalid envelope:` | poison / schema drift | No, until the producer or schema is fixed |
| `error` contains `unknown source event for tenant` | canonical event missing or tenant mismatch | No; investigate as a security/data-integrity issue |
| `error` contains `processing in progress` | concurrent processing | Yes, after the in-flight worker finishes |
| `error` contains a timeout / connection error | transient dependency | Yes, after dependency recovery |
| `delivery_attempt` equals `3` (worker) or `5` (adapter default) | redelivery exhausted | Yes, only after root cause is fixed |

Keep the exact error string for the ticket. The publisher truncates it to
2000 characters (`src/itsm_agent/adapters/messaging/nats_bus.py:189-207`).

### 4. Replay a bounded set

Replay republishes the original payload to its original subject. The
re-published message enters `ITSM_EVENTS` and is processed by the normal
consumer; the consumer's `processing_records` idempotency ledger prevents a
duplicate finding if the event already completed
(`migrations/006_audit_processing.sql:28`).

Set `MAX` deliberately. The loop below stops at `MAX` entries and at 50
empty fetches.

```sh
# Replace <ticket-id> in the printed output only; MAX is the hard bound.
uv run python - <<'PY'
import asyncio
import json
import os

import nats
from nats.js.api import ConsumerConfig

MAX = 10


async def main() -> None:
    nc = await nats.connect(
        servers=[os.environ.get("NATS_URL", "nats://127.0.0.1:4222")],
        connect_timeout=3.0,
    )
    replayed = 0
    try:
        js = nc.jetstream()
        sub = await js.pull_subscribe("itsm.dlq.events", config=ConsumerConfig())
        for _ in range(50):
            if replayed >= MAX:
                break
            try:
                msgs = await sub.fetch(1, timeout=0.5)
            except TimeoutError:
                break
            for msg in msgs:
                body = json.loads(msg.data.decode())
                original = body["original_subject"]
                payload = (body.get("payload") or "").encode()
                await js.publish(original, payload)
                await msg.ack()
                replayed += 1
                print(f"replayed {original} bytes={len(payload)}")
        print(f"replayed_total={replayed}")
    finally:
        await nc.drain()


asyncio.run(main())
PY
```

Notes:

- Only `itsm.dlq.events` is replayed. `itsm.dlq.escalation` is a notification,
  not a source event; replaying it would publish an event with no consumer
  contract.
- `dead_letter` decodes the original payload with `errors="replace"`
  (`src/itsm_agent/adapters/messaging/nats_bus.py:194`). For JSON payloads this is byte-stable; for non-UTF-8
  payloads the replay is lossy. Record that in the ticket.
- Do not replay all entries at once. A large replay is an unbounded retry
  loop in disguise and can overwhelm the consumer and the database.
- Confirm the consumer is healthy before replaying: `docker compose logs
  --tail 100 worker` should show progress, not repeated errors.

### 5. Handle a poison message

A poison message is not fixed by replay. Choose one:

1. **Reject and document** — record the subject, error, and payload hash (not
   the payload) and leave the DLQ entry for retention. This is the default
   for malformed producer output.
2. **Fix at the source** — correct the producer/schema, then replay a single
   entry to prove the fix.
3. **Quarantine outside NATS** — if the payload must be retained for
   investigation, copy it to the approved evidence store with the same
   access controls as raw evidence. Do not commit it to Git or paste it into
   a ticket.

Deleting the DLQ stream is not poison handling. It destroys the only record
of the failure.

### 6. Verify recovery

- The replayed subject appears in `ITSM_EVENTS`, is consumed, and produces
  either a `processing_records` row (`COMPLETED`) or a finding.
- No new entry with the same error appears in `ITSM_DLQ`.
- `ITSM_DLQ` message count is stable or decreasing (new failures may still
  arrive).

```sql
-- Replace <tenant-uuid> and <event-id>.
SELECT tenant_id, source, event_id, processing_version, status, finding_ids,
       completed_at, last_error
FROM processing_records
WHERE tenant_id = '<tenant-uuid>'::uuid
  AND event_id = '<event-id>'::uuid;
```

### 7. Close the loop

- Record the replay bound actually used, the number replayed, and the result
  per message.
- If the same error class recurs, open an engineering issue with the error
  string and the affected subject; do not keep replaying.
- Update the incident ticket with the evidence list below.

## Audit evidence

`ITSM_DLQ` is NATS transport state, not a PostgreSQL audit ledger. There is
no `dlq` table in `migrations/`. The durable audit record for a processed
event is `audit_events` (append-only,
`migrations/001_initial_schema.sql:143-182`), and the consumer's outcome is
recorded in `processing_records`.

For each dead-letter, capture:

- Stream name, subject, stream sequence, and `delivery_attempt`.
- `original_subject`, `error` (truncated), and payload byte length.
- Timestamp of inspection and replay, in UTC.
- The operator's classification (poison / transient / tenant mismatch).
- The replay command bound (`MAX`) and the number replayed.
- Resulting `processing_records.status` and `finding_ids`, or the new DLQ
  entry.

Do not capture the payload body if it may contain secrets or personal data.
`dead_letter` stores `message.payload.decode(...)`, which is the full
original payload.

## Rollback and recovery

- Replay is irreversible at the broker level: the message is republished.
  Idempotency is the protection, not rollback.
- If a replay was a mistake, stop the consumer, inspect
  `processing_records`, and do not delete findings or source events to
  "undo" it. Findings are versioned audit-derived records; removal is a data
  governance action, not an operator cleanup.
- If the consumer is looping, stop the worker (`docker compose stop worker`),
  fix the cause, then start it. Do not delete `ITSM_EVENTS` to clear a loop:
  unacked messages are the only copy after the outbox row is published.
- Restore from backup is the only rollback for a bad database write
  (`docs/production-readiness.md`; migrations are forward-only).

## Escalation

| Condition | Escalate to | Timing |
| --- | --- | --- |
| Poison message suggests schema drift or a producer bug | `<source-owner>` | same business day |
| `unknown source event for tenant` or a tenant mismatch | `<security-lead>` | immediate |
| Replay reproduces the same failure | `<platform-owner>` | within 1 hour |
| DLQ backlog exceeds the agreed threshold | `<platform-owner>` | immediate |
| Suspected secret in a DLQ payload | `<security-lead>` | immediate; do not copy the payload |

## Known limitations

- There is no shipped DLQ inspection or replay CLI. The scripts above are
  operator-run and must be bounded by the operator.
- No component consumes `itsm.dlq.escalation` in this repository; it is an
  observability signal, not an automated pager.
- `ITSM_DLQ` uses limits retention with no configured `max_msgs` in
  development, so it can grow without bound and old entries can be evicted
  only if limits are set (`docs/nats-stream-config.md`).
- Poison detection is envelope-level only. A semantically invalid but
  schema-valid event is processed (and may produce no finding), not
  dead-lettered.
- The DLQ is single-node in this repository; no cluster failover is tested.
