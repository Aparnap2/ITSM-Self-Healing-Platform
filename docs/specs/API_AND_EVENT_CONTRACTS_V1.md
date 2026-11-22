# API and Event Contracts v1.0

**Status:** H0 inventory.
**Starting SHA:** `3e3a2a014bd4aabee2d03a35e3e03f101ff382f5`

---

## 1. HTTP API endpoints

### 1.1 Ingestion

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/ingest` | Webhook signature (HMAC) | Ingest source event (CloudTrail, PgAudit, GitHub) |

### 1.2 Findings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/findings` | Bearer (OIDC/HMAC) | List findings for tenant |
| GET | `/v1/findings/{id}` | Bearer | Get finding by ID |
| GET | `/v1/findings/{id}/bundle` | Bearer | Evidence bundle (finding + evidence + review decisions) |
| GET | `/v1/findings/{id}/transitions` | Bearer | Lifecycle transition ledger |
| POST | `/v1/findings/{id}/transitions` | Bearer | Apply lifecycle transition |

### 1.3 Health and metrics

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/healthz` | None | Health check |
| GET | `/metrics` | None | Prometheus metrics |

### 1.4 OIDC

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/openid-configuration` | None | OIDC discovery |
| GET | `/jwks` | None | JSON Web Key Set |

## 2. Pydantic domain models

Key models in `src/itsm_agent/domain/models.py`:

| Model | Purpose | Key fields |
|-------|---------|------------|
| `Finding` | Deterministic detection result | id, tenant_id, finding_type, severity, status, title, description, detected_at, rule_version, risk_score, outcome |
| `EvidenceReference` | Finding-to-evidence link | id, finding_id, source_event_id, access_fact_id, content_hash, excerpt, trust_level, collected_at |
| `ReviewDecision` | Append-only reviewer decision | id, tenant_id, finding_id, reviewer_id, decision, decided_at, rationale, evidence_pack_ref |
| `Severity` | Enum | P1–P4 |
| `FindingStatus` | Enum (finding_lifecycle.py) | OPEN, ACKNOWLEDGED, INVESTIGATING, CONFIRMED, RESOLVED, VERIFIED, FALSE_POSITIVE, ACCEPTED_RISK, ESCALATED |

### Finding lifecycle transitions

Defined in `src/itsm_agent/domain/finding_lifecycle.py`. Valid transitions enforced by the domain layer and persisted in `finding_transitions`.

## 3. Event contract

### 3.1 Canonical event (target)

See `PRODUCTION_PARITY_V1.md` §4 for the target `CanonicalEvent` model. Reconcile with `src/itsm_agent/domain/events.py`.

### 3.2 Source adapters

| Source | Collector | Normalization |
|--------|-----------|--------------|
| AWS CloudTrail | `collectors/aws/cloudtrail.py` | CloudTrail event → canonical event |
| PostgreSQL PgAudit | `collectors/postgresql/pgaudit.py` | PgAudit log → canonical event |
| GitHub audit log | `collectors/github/audit_log.py` | GitHub audit → canonical event |

### 3.3 Webhook ingestion

- Endpoint: `POST /v1/ingest`
- Auth: HMAC signature (`x-itsm-signature: sha256=<hex>`)
- Max body: 65536 bytes (configurable)
- Rate limit: 60 requests per 60 seconds (configurable)
- Idempotency: via `idempotency_key` in event

### 3.4 Outbox pattern

- Table: `outbox` (tenant-owned, RLS)
- Columns: id, tenant_id, aggregate_type, aggregate_id, event_type, payload JSONB, status, created_at, published_at
- Status lifecycle: pending → published → (failed → retry)
- Relay: `python -m itsm_agent.workers.relay` polls and publishes to NATS
- Idempotency: via message deduplication on consumer side

## 4. Evidence bundle

Structure (from `src/itsm_agent/reporting/evidence_bundle.py`):

```json
{
  "finding": { "id", "tenant_id", "finding_type", "severity", "status", "title", "description", "detected_at", "rule_version", "outcome" },
  "evidence": [{ "id", "source_event_id", "access_fact_id", "content_hash", "excerpt", "trust_level", "collected_at" }],
  "review_decisions": [{ "id", "tenant_id", "finding_id", "reviewer_id", "decision", "decided_at", "rationale", "evidence_pack_ref" }],
  "bundle_hash": "sha256:..."
}
```

## 5. Investigation contract

### 5.1 Investigation request

- `investigation_requests` table: id, tenant_id, finding_id, requested_by, question, evidence_snapshot_ids, max_tool_calls, max_model_calls, status, created_at
- Status: REQUESTED → COMPLETED/SKIPPED/FAILED

### 5.2 Investigation proposal

- `investigation_proposals` table: id, tenant_id, request_id, finding_id, hypothesis, supporting_evidence, contradicting_evidence, missing_evidence, uncertainty, created_at
- The proposal is advisory only — it cannot change finding status or authorize actions.

### 5.3 Evidence grounding

Two booleans:
- `resolves_to_persisted_evidence`: cited ID exists in persisted evidence rows.
- `in_snapshot`: cited ID was among the IDs shown to the model.

Both must be true for a grounded claim. Trusting either alone is insufficient.

### 5.4 LLM boundary

- Provider: Groq (OpenAI-compatible API)
- Model: `openai/gpt-oss-120b` (configurable)
- Budget: max 3 real calls per run (enforced by operator tooling)
- Per-request bounds: max 2 model calls, 5 tool calls
- On failure: log to `/tmp/llm_debug_<timestamp>.json` and stop
- No retry loops

## 6. Reviewer lifecycle

### 6.1 Transitions

Valid transitions defined in `domain/finding_lifecycle.py`. Applied via `POST /v1/findings/{id}/transitions`.

### 6.2 Reviewer authentication

- OIDC: RS256/ES256, JWKS, pinned CA
- HMAC: development/test only (refused in staging)
- Reviewer directory: `reviewer_authorizations` table (read-only at runtime)

### 6.3 Reviewer separation

- Two distinct principals required for resolve + verify.
- `VERIFIED` transition's principal must differ from `RESOLVED` transition's principal.

## 7. Security boundaries

See `docs/security-boundaries.md`. Key invariants:
- Unknown actions/resources/principals denied.
- Model proposal is not authorization.
- Approval: authenticated, exact-action-bound, unexpired, single-use, checked against current policy.
- No side effect before durable intent + policy decision.
- Uncertain outcomes trigger reconciliation before retry.
- No resolution without independent verification.
- Terminal outcomes require audit records.