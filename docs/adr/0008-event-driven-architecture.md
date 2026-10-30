# ADR-0008: Event-driven architecture

Status: Accepted
Date: 2026-10-30

## Context

Sources emit events asynchronously; processing must be decoupled, durable, and
resilient to failures. NATS JetStream provides durable streams, acks, and DLQ
with a small footprint.

## Decision

- Use NATS JetStream as the async event backbone.
- Use transactional outbox for DB-to-broker publication.
- Assume at-least-once delivery; consumers deduplicate.
- Batch consumer groups events for deterministic analysis.

## Consequences

- No event lost to crash between DB commit and publish.
- Consumers must be idempotent.
- Small publish latency acceptable for batch audit processing.

## Alternatives considered

1. Kafka. Rejected: heavy operational dependency for current throughput.
2. Synchronous processing. Rejected: couples sources to processing and loses
   resilience.
