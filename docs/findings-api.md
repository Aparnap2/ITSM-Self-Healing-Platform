# Findings and Reviewer Decisions API (Task 14)

Status: implemented on `feat/access-audit-foundation` (commit `ca9ce88`), with
10 offline unit tests and 7 real-PostgreSQL integration tests (`babcbc0`).
Contract source: `src/itsm_agent/api/routes/findings.py`.

The surface is read-only over findings and append-only over reviewer decisions.
It is mounted by `create_app` only when both repositories are supplied
(`src/itsm_agent/api/app.py`), under the prefix `/v1/findings`.

## 1. Wiring

| Item | Value | Source |
|---|---|---|
| Router prefix | `/v1/findings` | `routes/findings.py` (`APIRouter(prefix=...)`) |
| Mount condition | both repositories non-`None` | `api/app.py` (`create_app`) |
| Dependency holder | process-global `_deps`, set by `configure_findings` | `routes/findings.py` |
| Findings reader | `PsycopgFindingRepository.get` / `.list_for_tenant` | `repositories.py` |
| Decisions store | `PsycopgReviewDecisionRepository` record/list methods | `repositories.py` |

Dependencies are declared as narrow protocols (`FindingsReader`,
`DecisionsStore`), so the routes can be exercised offline with fakes. Both
repositories live in `src/itsm_agent/adapters/persistence/repositories.py`.

## 2. Endpoints

| Method | Path | Purpose | Success |
|---|---|---|---|
| GET | `/v1/findings` | List findings for a tenant | `200` JSON array |
| GET | `/v1/findings/{finding_id}` | One finding plus its review decisions | `200` JSON object |
| POST | `/v1/findings/{finding_id}/decisions` | Append reviewer decision | `201` (see §5) |
| GET | `/v1/findings/{finding_id}/decisions` | List decisions for a finding | `200` JSON array |

These are the four routes currently defined in the module. There is no
finding-status transition endpoint; see §7.

## 3. Tenant scoping

Every request requires `tenant_id` as a UUID query parameter:

```text
GET /v1/findings?tenant_id=6f1c0b1e-6a8f-4a1f-9c0f-2d6a0b6f5f11
GET /v1/findings/{finding_id}?tenant_id=6f1c0b1e-...
POST /v1/findings/{finding_id}/decisions?tenant_id=6f1c0b1e-...
```

- A missing or malformed `tenant_id` is a `422` (FastAPI request validation).
- Tenant scoping is enforced in the SQL predicates
  (`WHERE tenant_id = %s AND id = %s`; decisions filtered by
  `tenant_id` and `finding_id`).
- A finding that exists in a different tenant is indistinguishable from a
  missing finding: `404`, with detail `finding not found`.
- `POST` also checks the finding through the tenant-scoped read first, so a
  decision cannot be appended to another tenant's finding.
- The tenant is **not** derived from an authenticated principal — there is no
  authentication on this surface (§7).

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
| `outcome` | string | Emitted values: `VIOLATION`, `SUSPICIOUS`, `COVERAGE_GAP`, `INCONCLUSIVE` |

`GET /v1/findings` returns an array of these objects ordered by
`(detected_at, id)`, with no pagination. `GET /v1/findings/{finding_id}` adds a
`review_decisions` array to the object:

```json
{
  "id": "...",
  "tenant_id": "...",
  "finding_type": "...",
  "severity": "P2",
  "status": "OPEN",
  "title": "...",
  "description": "...",
  "detected_at": "2026-01-01T12:00:00+00:00",
  "rule_version": "detection-rules-v1",
  "risk_score": 60,
  "outcome": "SUSPICIOUS",
  "review_decisions": []
}
```

## 5. Decision request

`POST /v1/findings/{finding_id}/decisions` body
(`FindingDecisionRequest`, Pydantic v2):

| Field | Type | Constraints | Required |
|---|---|---|---|
| `reviewer_id` | string | 1–128 characters | yes |
| `decision` | string | one of four enum values (below) | yes |
| `rationale` | string | 1–2000 characters | yes |
| `evidence_pack_ref` | string or null | opaque reference, no format/length constraint | no |

`decision` must match `DECISION_PATTERN` exactly: `CONFIRMED`, `FALSE_POSITIVE`,
`ACCEPTED_RISK`, or `NEEDS_MORE_EVIDENCE`.

```json
{
  "reviewer_id": "analyst-17",
  "decision": "CONFIRMED",
  "rationale": "AssumeRole from an unapproved IP range; no change ticket found.",
  "evidence_pack_ref": "bundle-2026-01-01-0007"
}
```

Success response (`201`) echoes only the stored id and a fixed status — it does
not return the full decision:

```json
{"id": "c2f7d3aa-6a06-4a4e-9f0e-2a1e4b8c9d10", "status": "recorded"}
```

Repeated `POST`s append additional decisions. There is no uniqueness
constraint and no "latest decision wins" logic.

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
decision JSON.

## 7. Status codes

| Code | When |
|---|---|
| `200` | Successful read (list, detail, decisions) |
| `201` | Decision recorded |
| `404` | Finding absent **or** owned by another tenant (`{"detail": "finding not found"}`) |
| `422` | Missing/malformed id; invalid decision body (enum, lengths) |
| `503` | Findings dependencies absent (`{"detail": "findings store not configured"}`) |

Note on `503`: the guard lives in the route module (`_deps_or_503`). The stock
`create_app` only mounts the router when both repositories are provided, so a
process built without them returns `404` for these paths; `503` applies when the
router is embedded without configured dependencies (e.g. imported directly in
tests).

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

- **No authentication or authorization.** `reviewer_id` is client-supplied and
  unverified; no token, signature, or session is checked on this router.
- **No RBAC.** Any caller who can reach the process can record any decision for
  any tenant id they name.
- **No row-level security.** Tenant isolation is query-level (`WHERE
  tenant_id = ...`), not enforced by PostgreSQL RLS or a session-bound tenant.
- **No pagination, filtering, or sorting.** No `limit`/`offset`, no
  severity/status/outcome filters; the list endpoint returns every finding for
  the tenant.
- **No update or delete.** The repository exposes only `INSERT` and `SELECT`;
  there is no update/delete route, and no DB trigger enforces immutability on
  `review_decisions` (migration 005 defines none) — append-only is an
  application-level property.
- **No finding status transition.** Recording a decision does not change
  `findings.status`; there is no `PATCH`/`PUT` endpoint.
- **No evidence-link validation.** `evidence_pack_ref` is stored as an opaque
  optional string and is not resolved against an evidence bundle.
- **Unknown body fields are ignored,** not rejected (Pydantic's default
  `extra="ignore"` on `FindingDecisionRequest`), unlike the domain models'
  `extra="forbid"`.
- **No rate limiting.** The sliding-window limiter is wired to the ingestion
  router only.
- **No OpenAPI schema.** `create_app` sets `docs_url`, `redoc_url`, and
  `openapi_url` to `None`; this document is the contract.
- **Dependencies are process-global.** `_deps` is a module variable, so the
  last `configure_findings` call in a process wins across app instances.

## 10. Sources

| Commit | Content |
|---|---|
| `371dffb` | `ReviewDecision` model, append-only tenant-scoped repository, 3 integration tests |
| `0a80cb2` | `migrations/006_audit_processing.sql` (`processing_records`, severity CHECK P1–P4) |
| `00d11a9` | `tests/integration/test_audit_pipeline_durable.py` |
| `98e83ef` | Repository exports; truncate `processing_records` between tests |
| `ee55c3a` | Approval-evidence detection (`detect_approval_violation`) and outcome semantics |
| `ca9ce88` | `api/routes/findings.py`, `create_app(..., findings_repo=..., review_decisions_repo=...)`, `PsycopgFindingRepository.get` |
| `babcbc0` | `tests/unit/test_findings_api.py` (10 tests), `tests/integration/test_findings_api.py` (7 tests, real PostgreSQL) |
