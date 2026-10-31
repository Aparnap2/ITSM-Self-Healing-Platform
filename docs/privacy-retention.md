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
- Retention expiry: when raw evidence expires, the canonical event remains with
  `raw_evidence_reference` marked `expired` and `payload_hash` retained for
  integrity; findings referencing expired evidence are flagged
  `evidence_expired`.
- Deletion follows legal-hold policy; append-only audit records are not deleted.

## Redaction

- Secrets, tokens, and credentials are redacted at ingestion; never stored or
  logged.
- PII is minimized and redacted unless required for audit; retention follows
  policy.
- Raw payloads are referenced, not inlined, in canonical events.

## Retention

- Canonical events retained per configured retention period.
- Raw evidence retained separately with its own lifecycle.
- Audit events are append-only; deletion follows legal hold policy.

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

- Retention periods are configurable; defaults are conservative.
- Redaction rules are source-specific and may miss novel patterns.
