# Privacy, Redaction, and Retention

## Evidence storage and references

- Raw evidence may be stored in PostgreSQL (small payloads) or external object
  storage (large payloads); the choice is per-source and documented in the
  source integration matrix.
- `raw_evidence_reference` points to the retained (redacted) copy, not the
  original source record, unless the source is immutable and directly
  addressable; in that case it points to the original with a hash.
- `payload_hash` is computed over the redacted payload as stored (after
  redaction), so verification matches the retained copy.
- `source_events` is append-only: a database trigger rejects `UPDATE` and
  `DELETE`. Retention therefore **cannot** rewrite `raw_evidence_reference` or
  delete the canonical event.

## Retention and erasure (implemented)

Source: `src/itsm_agent/privacy/retention.py`,
`migrations/008_retention_erasure.sql`, and
`PsycopgRetentionRepository` in
`src/itsm_agent/adapters/persistence/repositories.py`.

| Data class | Default retention | On expiry |
|---|---|---|
| `RAW_EVIDENCE` | 90 days | `ANONYMIZE` (record a tombstone) |
| `CANONICAL_EVENT` | 2555 days | `RETAIN` |
| `DERIVED_PROJECTION` | 90 days | `DELETE_DERIVED` |
| `FINDING` | 2555 days | `RETAIN` |
| `INVESTIGATION` | 365 days | `RETAIN` |
| `REVIEW_DECISION` | 2555 days | `RETAIN` |
| `OPERATIONAL_LOG` | 30 days | `DELETE_DERIVED` |

- A tenant may override a default per data class (`retention_policies`).
- `plan_erasure` is pure and deterministic: it computes per-class cutoffs and
  actions, and blocks the whole request if an active legal hold covers any
  requested class.
- An unknown data class/policy fails closed to `RETAIN`.
- Erasure execution:
  - records an `erasure_requests` row (tenant-scoped, status
    `REQUESTED`/`BLOCKED`/`COMPLETED`);
  - writes `erasure_tombstones` for expired raw evidence **without touching
    the append-only `source_events` row** — the tombstone keeps
    `record_id`, `integrity_hash` (`payload_hash`), class, request id and time;
  - deletes only rebuildable derived projections (`access_facts`);
  - is idempotent per `(erase_request_id, data_class, record_id)`;
  - never cascades into findings or reviewer decisions.
- Erasure requests and tombstones are tenant-isolated by RLS. Legal holds and
  per-tenant policy overrides are filtered by `tenant_id` in queries but are
  not yet under RLS.

## Redaction

- Secrets, tokens, and credentials are redacted at ingestion; never stored or
  logged.
- PII is minimized and redacted unless required for audit; retention follows
  policy.
- Raw payloads are referenced, not inlined, in canonical events.

## PII

- Only necessary identifiers retained.
- User-facing identifiers hashed where feasible.

## Secrets

- No secrets in Git, logs, traces, test output, or audit payloads.
- Secret scan required before merge.

## LLM context minimization

- Only redacted, bounded summaries are passed to LLMs.
- Raw logs and secrets never enter model context.
- Evidence references, not full payloads, are used.

## Known limitations

- A resumable retention scheduler exists
  (`src/itsm_agent/privacy/scheduler.py`), is lifecycle-tested
  (`tests/integration/test_retention_scheduler_lifecycle.py`), and runs as the
  packaged `python -m itsm_agent.workers.retention` process (compose service
  `retention`). It leases due requests, honors legal holds, and escalates
  retry exhaustion; expiry is automatic once the process is deployed.
- `RAW_EVIDENCE` erasure records a tombstone but does not delete an object
  from external object storage. Lifecycle rules on the bucket are still
  required and are not managed by this repository.
- Findings and reviewer decisions are retained by default; anonymization of
  their free-text fields is not implemented.
- Redaction rules are source-specific and may miss novel patterns.
