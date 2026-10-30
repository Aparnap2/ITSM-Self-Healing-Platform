# Canonical Event Contract

All events use strict Pydantic (`extra="forbid"`). Timestamps are timezone-aware
UTC. Unknown event types are rejected or quarantined.

## Canonical event fields

| Field | Type | Description |
|---|---|---|
| event_id | UUID | Unique event identifier |
| tenant_id | string | Tenant scope |
| source | string | Source system (cloudtrail, pgaudit, github, identity) |
| source_event_id | string | Source-native event ID |
| source_schema_version | string | Source schema version |
| canonical_schema_version | string | Canonical event contract version |
| event_type | string | Canonical event type |
| event_category | string | Category (auth, data, config, access) |
| event_time | datetime (UTC) | When the event occurred at source |
| observed_at | datetime (UTC) | When the system observed it |
| ingested_at | datetime (UTC) | When durably ingested |
| actor_id | string | Actor identity |
| principal_id | string | Principal on whose behalf |
| session_id | string | Session/correlation at source |
| action | string | Action performed |
| resource_type | string | Resource type |
| resource_id | string | Resource identifier |
| outcome | string | success/failure/denied |
| permission_context | object | Permissions/roles at time |
| payload_hash | sha256 | Hash of redacted payload |
| raw_evidence_reference | string | Pointer to raw evidence |
| correlation_metadata | object | Correlation/causation IDs |

## Event-time vs ingestion-time

- `event_time`: authoritative time at source; may be delayed or skewed.
- `observed_at`: when the adapter saw it.
- `ingested_at`: when durably committed to the canonical store.
- Analysis uses event_time for ordering; ingestion-time for SLA/latency.


## Field optionality and unknown identity

Mandatory for every event: `event_id`, `tenant_id`, `source`, `event_type`,
`event_category`, `event_time`, `observed_at`, `ingested_at`, `action`,
`canonical_schema_version`, `payload_hash`.

Nullable/optional: `source_event_id` (source may not provide one),
`source_schema_version`, `actor_id`, `principal_id`, `session_id`,
`resource_type`, `resource_id`, `outcome`, `permission_context`,
`raw_evidence_reference`, `correlation_metadata`.

Unknown identity is represented as `null` plus a provenance note in
`correlation_metadata` (e.g. `{"identity_resolution": "unresolved"}`).
A missing identity is distinct from an explicitly anonymous actor
(`actor_id = "anonymous"` with provenance). Never fabricate identities.

Identity resolution may occur during ingestion (when trivially resolvable) or
as a later projection; the canonical event retains the raw source identifier
regardless. Resolution provenance is recorded on the projection, not by
rewriting the event.


## Canonical event identity and fallback

Primary identity: `(tenant_id, source, source_event_id)`.

- `source_event_id` is nullable. When the source provides no stable ID, the
  adapter computes a source-specific fallback (documented in
  `docs/source-integration-matrix.md`) and records `source_event_id = null` plus
  `correlation_metadata.identity_strategy = "fallback:<name>"`.
- Fallback identities must be stable across adapter versions (same inputs ->
  same identity).
- Legitimate repeated identical events remain distinguishable when the source
  provides distinct IDs or timestamps; payload-hash alone is never the universal
  identity.
- If two different payloads arrive with the same `(tenant_id, source,
  source_event_id)`, ingestion is rejected as a conflict and recorded in the
  ingestion error log; the second is not silently accepted.


## Timestamp ordering (qualified)

`event_time` is the preferred ordering key but is not universally authoritative:

- Late-arriving events are accepted and ordered by `event_time`; projections
  are rebuilt or versioned rather than rewriting the event.
- Clock skew is recorded (`correlation_metadata.clock_skew_seconds`) but the
  source timestamp is never silently rewritten.
- Missing or unreliable timestamps: event is quarantined for review rather
  than assigned a fabricated time; `observed_at`/`ingested_at` are always
  populated by the system.
- `observed_at` and `ingested_at` are preserved on every event.

## Schema versioning

Two versions are tracked independently:
- `source_schema_version`: version of the source system's event format.
- `canonical_schema_version`: version of this normalized contract.


- `schema_version` on every event (e.g., "1.0").
- Backward-compatible additions only within a major version.
- Breaking changes require new major version and migration plan.

## Strict Pydantic

- `extra="forbid"` on all contracts.
- Timestamps normalized to UTC at boundary.
- Unknown fields rejected.


## Mutability boundaries

| Data | Mutability |
|---|---|
| Raw source evidence | Immutable |
| Canonical source event | Immutable |
| Access facts / normalized projections | Rebuildable, versioned |
| Findings | Versioned lifecycle |
| Investigation proposals | Append-only history |
| Reviewer decisions | Append-only history |
| Consumer checkpoints | Mutable operational state |

Append-only triggers apply only to immutable tables, not to rebuildable
projections, which use controlled replacement/versioning.

## Idempotency

Canonical identity of an incoming event is `(tenant_id, source, source_event_id)`.
Source-specific fallbacks (including payload hashing) are defined per source in
`docs/source-integration-matrix.md`. Payload hashing is not a universal identity:
legitimate repeated identical events must be distinguishable.

## Replay semantics

Replaying source evidence may rebuild derived projections, but must not
duplicate original evidence, reviewer decisions, or external side effects, and
must not trigger unbounded LLM investigations. One source event may produce
zero, one, or many normalized domain facts; the relationship is preserved.

## Known limitations

- Schema is initial; will evolve with sources.
- Clock skew handling is best-effort.
