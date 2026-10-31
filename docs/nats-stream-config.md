# NATS JetStream Stream Configuration (Task 7)

## Streams

- `ITSM_EVENTS` (subjects `itsm.events.>`): WorkQueue retention, explicit acks.
  Bounded by acks; messages removed once acked.
- `ITSM_DLQ` (subjects `itsm.dlq.>`): Limits retention; holds dead-lettered
  payloads and escalation events after bounded redelivery (max_deliver).

## Subject naming

- `itsm.events.<source>.<tenant>` for source events (e.g. `itsm.events.cloudtrail.<tenant>`).
- `itsm.dlq.events` for dead-lettered payloads.
- `itsm.dlq.escalation` for escalation events.

## Retention / replication / storage

- WorkQueue retention on ITSM_EVENTS: message removed after ack.
- max_deliver: 5 (configurable via MessagingConfig).
- ack_wait: 30s default.
- Replication factor: 1 in dev; production should use R=3 (cluster).
- Storage limits: set max_bytes / max_msgs per stream in production; dev unbounded.

## Delivery semantics

At-least-once. Consumers deduplicate via inbox unique constraint.
Ack only after durable transition commits. Nak triggers bounded redelivery.
After max_deliver, dead-letter + escalate + term.

## Known limitations

- Single-node dev; no clustering tested.
- Replication assumptions not validated in CI.
