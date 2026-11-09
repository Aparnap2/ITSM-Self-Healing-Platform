# Findings and Reviewer Decisions API

Status: implemented on `feat/access-audit-foundation`. Originally landed in
`ca9ce88`/`babcbc0`; authenticated, tenant-membership-checked, RBAC-enforced
and backed by PostgreSQL row-level security in the security-boundary slice.
Contract source: `src/itsm_agent/api/routes/findings.py`.

The surface is read-only over findings and append-only over reviewer decisions.
It is mounted by `create_app` when the two stores are supplied
(`src/itsm_agent/api/app.py`), under the prefix `/v1/findings`.

## 1. Wiring

| Item | Value | Source |
|---|---|---|
| Router prefix | `/v1/findings` | `routes/findings.py` (`APIRouter(prefix=...)`) |
| Mount condition | both stores non-`None` | `api/app.py` (`create_app`) |
| Dependency holder | process-global `_deps`, set by `configure_findings` | `routes/findings.py` |
| Authenticator | `TokenAuthenticator` (HMAC bearer) or any `Authenticator` | `api/auth.py` |
| Findings reader | `PsycopgFindingRepository.get` / `.list_for_tenant` | `repositories.py` |
| Decisions store | `PsycopgReviewDecisionRepository` record/list methods | `repositories.py` |

Dependencies are declared as narrow protocols (`FindingsReader`,
`DecisionsStore`, `Authenticator`), so the routes can be exercised offline with
fakes. Both stores live in
`src/itsm_agent/adapters/persistence/repositories.py`.

If the stores are wired but no authenticator is supplied, every request fails
closed with `503`; the router never serves unauthenticated data.

## 2. Endpoints

| Method | Path | Required permission(s) | Success |
|---|---|---|---|
| GET | `/v1/findings` | `findings:read` | `200` JSON array |
| GET | `/v1/findings/{finding_id}` | `findings:read`, `decisions:read` | `200` JSON object |
| POST | `/v1/findings/{finding_id}/decisions` | `decisions:write` + permission for the decision type | `201` |
| GET | `/v1/findings/{finding_id}/decisions` | `decisions:read` | `200` JSON array |
| GET | `/v1/findings/{finding_id}/bundle` | `findings:read`, `decisions:read` | `200` JSON object |

There is no finding-status transition endpoint; see §9.

### 2a. Evidence bundle

`GET /v1/findings/{finding_id}/bundle?tenant_id=...` returns the deterministic
compliance-evidence bundle for one finding:

- `finding`: the same JSON object shape as the single-finding endpoint;
- `evidence`: the finding's evidence references, sorted by id, with each
  `excerpt` passed through `redact_secrets` **before** hashing and before the
  response is built;
- `review_decisions`: the finding's decision history in the same JSON shape as
  the decisions list endpoint;
- `limitations`: an always-present list stating the bundle is evidence, not
  certification;
- `bundle_hash`: SHA-256 of the canonical JSON of the bundle built above
  (sort_keys, no whitespace). Identical data yields an identical hash, so two
  fetches of an unchanged finding must agree.

The route fails closed with `503` when the evidence-reference store is not
wired, returns `401`/`403`/`404` the same way the single-finding endpoint does,
and requires the same `tenant_id` query parameter. Refusal reasons follow the
standard status table (§7).

## 3. Authentication and tenant scoping

Every request requires a bearer credential:

```text
Authorization: Bearer v1.<payload>.<signature>
GET /v1/findings?tenant_id=6f1c0b1e-6a8f-4a1f-9c0f-2d6a0b6f5f11
```

- The token is verified by `TokenAuthenticator`: HMAC-SHA256 over the payload,
  issuer must be `itsm-audit`, `exp` must be in the future.
- The resulting principal carries `principal_id`, tenant memberships and roles.
- `tenant_id` is a **requested scope**, never trusted as identity. It must be a
  UUID (else `422`) and must be in the principal's `tenant_ids` (else `403`).
- A finding that exists in a different tenant is indistinguishable from a
  missing finding: `404`, with detail `finding not found`.
- PostgreSQL RLS independently scopes every read and write to the same tenant
  (`docs/security-boundaries.md`), so a query bug cannot cross tenants.
- Tenant scope for a decision is derived from the verified principal and the
  verified finding; the body cannot override either.

## 4. Finding representation

```json
{
  "id": "0d6f0a52-6f6e-4e0a-9b0f-51a1f9a1f111",
  "tenant_id": "6f1c0b1e-6a8f-4a1f-9c0f-2d6a0b6f5f11",
  "finding_type": "MISSING_APPROVAL",
  "severity": "P2",
  "status": "OPEN",
  "title": "Privileged action without approval: AssumeRole",
  "description": "Privileged action AssumeRole by arn:aws:iam::123:user/alice ...",
  "detected_at": "2026-01-01T12:00:00+00:00",
  "rule_version": "detection-rules-v1",
  "risk_score": 60,
  "outcome": "SUSPICIOUS"
}
```

| Field | Type | Notes |
|---|---|---|
| `id` | string (UUID) | Finding id |
| `tenant_id` | string (UUID) | Owning tenant |
| `finding_type` | string | Detection rule output, e.g. `MISSING_APPROVAL`, `PRIVILEGE_ESCALATION` |
| `severity` | string | `P1`–`P4` (`Severity` StrEnum; migration 006 CHECK) |
| `status` | string | Default `OPEN`; values constrained by migration 004 CHECK |
| `title`, `description` | string | Human-readable summary |
| `detected_at` | string (ISO 8601) | Timezone-aware |
| `rule_version` | string | Detection rule set version, currently `detection-rules-v1` |
| `risk_score` | integer | Score set by the emitting rule (current rules use 30, 50, 60, 70) |
| `outcome` | string | `VIOLATION`, `SUSPICIOUS`, `COVERAGE_GAP`, `INCONCLUSIVE` |

`GET /v1/findings` returns an array of these objects ordered by
`(detected_at, id)`, with no pagination. `GET /v1/findings/{finding_id}` adds a
`review_decisions` array to the object.

## 5. Decision request

`POST /v1/findings/{finding_id}/decisions` body
(`FindingDecisionRequest`, Pydantic v2, `extra="forbid"`):

| Field | Type | Constraints | Required |
|---|---|---|---|
| `decision` | string | one of four enum values (below) | yes |
| `rationale` | string | 1–2000 characters, stripped | yes |
| `evidence_pack_ref` | string or null | opaque reference | no |

`decision` must match `DECISION_PATTERN` exactly: `CONFIRMED`, `FALSE_POSITIVE`,
`ACCEPTED_RISK`, or `NEEDS_MORE_EVIDENCE`.

`reviewer_id` is **not** accepted in the body. Sending it (or any other unknown
field) is a `422`; the stored actor is `principal.principal_id` from the
verified credential.

```json
{
  "decision": "CONFIRMED",
  "rationale": "AssumeRole from an unapproved IP range; no change ticket found.",
  "evidence_pack_ref": "bundle-2026-01-01-0007"
}
```

Success response (`201`) echoes only the stored id and a fixed status. Repeated
`POST`s append additional decisions; there is no "latest decision wins" logic.

## 6. Decision representation

`GET /v1/findings/{finding_id}/decisions` returns decisions ordered by
`(decided_at, id)`:

```json
[
  {
    "id": "c2f7d3aa-6a06-4a4e-9f0e-2a1e4b8c9d10",
    "reviewer_id": "analyst-17",
    "decision": "CONFIRMED",
    "decided_at": "2026-11-01T09:15:00+00:00",
    "rationale": "AssumeRole from an unapproved IP range; no change ticket found.",
    "evidence_pack_ref": "bundle-2026-01-01-0007"
  }
]
```

`tenant_id` and `finding_id` are validated on read but are not echoed in the
decision JSON. `reviewer_id` is the authenticated principal that created the
decision.

## 7. Status codes

| Code | When |
|---|---|
| `200` | Successful read (list, detail, decisions) |
| `201` | Decision recorded |
| `401` | Missing, malformed, forged, wrong-issuer, or expired credential (`WWW-Authenticate: Bearer`) |
| `403` | Principal is not a member of the requested tenant, or lacks the required permission/decision type |
| `404` | Finding absent **or** owned by another tenant (`{"detail": "finding not found"}`) |
| `422` | Missing/malformed id or body (enum, lengths, unknown fields such as `reviewer_id`) |
| `503` | Stores or authenticator not configured (fail closed) |

Authorization happens before any write: an under-privileged or cross-tenant
`POST` leaves the decision table unchanged.

## 8. Evidence-first invariants

- **PostgreSQL is canonical.** Findings (`findings`) and reviewer decisions
  (`review_decisions`, migration 005) live in PostgreSQL; the API reads and
  appends to those tables only.
- **NATS is transport only.** JetStream carries `SourceEvent` messages and
  retains them for delivery/redelivery; PostgreSQL, not the stream, is the
  authoritative record of findings and decisions.
- **Delivery is at-least-once.** Deduplication uses `processing_records`,
  unique on `(tenant_id, source, event_id, processing_version)`
  (migration 006), so redelivery produces no duplicate findings.
- **Deterministic detection never calls an LLM.** Detection is rule code in
  `src/itsm_agent/detection/engine.py`; model use is confined to the bounded
  investigation layer (`src/itsm_agent/investigations/orchestrator.py`).
- **Uncertainty is preserved in outcomes.** A privileged action with no
  approval at all under full source coverage yields `MISSING_APPROVAL` /
  `SUSPICIOUS`, not `VIOLATION`; `VIOLATION` requires negative approval
  evidence (denied, revoked, expired, mismatched).

## 9. What is not implemented

- **No management plane.** There is no endpoint to create/rotate principals,
  grant roles, or manage tenants; tokens are minted out-of-band
  (`mint_token`) and roles are embedded in the token.
- **No key rotation or revocation.** A single symmetric secret signs tokens;
  there is no key id, rotation window, or revocation list. A valid token works
  until `exp`.
- **No server-side role freshness.** A role change requires issuing a new
  token; there is no lookup of current grants per request.
- **No pagination, filtering, or sorting.** No `limit`/`offset`, no
  severity/status/outcome filters.
- **No update or delete.** The repository exposes only `INSERT` and `SELECT`;
  append-only is enforced by the application and by the absence of routes,
  not by a database trigger on `review_decisions`.
- **No finding status transition.** Recording a decision does not change
  `findings.status`.
- **No evidence-link validation.** `evidence_pack_ref` is stored as an opaque
  optional string and is not resolved against an evidence bundle.
- **No rate limiting.** The sliding-window limiter is wired to the ingestion
  router only.
- **No OpenAPI schema.** `create_app` sets `docs_url`, `redoc_url`, and
  `openapi_url` to `None`; this document is the contract.
- **Dependencies are process-global.** `_deps` is a module variable, so the
  last `configure_findings` call in a process wins across app instances.

## 10. Sources

| Commit | Content |
|---|---|
| `371dffb` | `ReviewDecision` model, append-only tenant-scoped repository, integration tests |
| `0a80cb2` | `migrations/006_audit_processing.sql` (`processing_records`, severity CHECK P1–P4) |
| `00d11a9` | `tests/integration/test_audit_pipeline_durable.py` |
| `98e83ef` | Repository exports; truncate `processing_records` between tests |
| `ee55c3a` | Approval-evidence detection (`detect_approval_violation`) and outcome semantics |
| `ca9ce88` | `api/routes/findings.py`, `create_app(..., findings_repo=..., review_decisions_repo=...)`, `PsycopgFindingRepository.get` |
| `babcbc0` | `tests/unit/test_findings_api.py`, `tests/integration/test_findings_api.py` (real PostgreSQL) |
| `cedd0f4` | `api/auth.py`, `api/rbac.py`, migrations 007–009, RLS/tenant plumbing, retention, authenticated API tests |
| `27b90db` | Static SQL for outbox claim/count and inbox dedup (bandit B608) |
