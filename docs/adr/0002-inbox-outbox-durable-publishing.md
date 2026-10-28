# ADR-0002: Inbox/Outbox durable publishing over a message broker

Status: Accepted
Date: 2026-10-28

## Context

Incident events arrive via webhook, must be durably accepted before
acknowledgement (FR-01), then delivered to the workflow worker. The
classic "write to DB, then publish to broker" sequence has a dual-write
problem: the process can crash between the two steps, losing the event,
or publish twice, duplicating it. PRD §2.3 mandates a transactional
outbox or equivalent, an inbox/dedup table, and at-least-once delivery
with idempotent consumers. PostgreSQL is already the durable source of
truth; NATS JetStream is the event backbone.

## Decision

- **Transactional outbox:** business state transitions and their
  corresponding `OutboxEvent` rows are written in the same PostgreSQL
  transaction. A publisher polls/claims unpublished rows, publishes to
  NATS JetStream, and marks `published_at` only after broker ack.
  Publication is safely retryable.
- **Inbox dedup:** every externally sourced event is recorded in an
  `InboxEvent` table with a unique constraint on
  `(source_system, external_event_id)`. Duplicate deliveries are
  detected and acknowledged as duplicates, never reprocessed.
- **Consumer contract:** handlers are idempotent; a message is
  acknowledged only after the required durable transition commits;
  redelivery is bounded, then dead-lettered/escalated with evidence.
- **Reconciliation worker** re-drives stuck outbox rows, unprocessed
  inbox events, and pending ITSM updates.

## Consequences

- No event is lost to a crash between DB commit and publish; no logical
  incident is duplicated under redelivery.
- Consumers must implement dedup — at-least-once is assumed everywhere.
- Outbox polling adds small publish latency (acceptable: seconds-scale
  incident workflow, not a trading system).
- Two tables and a reconciliation loop are permanent maintenance
  surface; tests must cover duplicate, outage, and restart paths
  (PRD §9.1 C/D).

## Alternatives considered

1. **Kafka (or Redpanda) as the backbone.** Rejected: PRD §1.4
   explicitly excludes Kafka without demonstrated need; it adds a heavy
   operational dependency for a single-consumer, low-throughput
   workflow. NATS JetStream provides durable streams, acks, and DLQ with
   a small footprint.
2. **Publish-then-commit (broker first, DB second).** Rejected: a crash
   after publish but before commit loses the durable record — violates
   FR-01 (ack only after durable acceptance).
3. **Exactly-once delivery guarantees.** Rejected: not achievable
   end-to-end across DB + broker + HTTP adapters; designing for
   at-least-once + idempotency is the honest, testable contract.
4. **Postgres LISTEN/NOTIFY instead of JetStream.** Rejected: no
   redelivery, durability, or consumer-ack semantics; NOTIFY is
   fire-and-forget.
