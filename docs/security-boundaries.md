# Security Boundaries

Status: implemented on `feat/access-audit-foundation` (security-boundary
slice). This document distinguishes **enforced in code and tested** from
**planned / not covered**. Nothing here makes the system production ready.

## 1. Reviewer authentication

- Every findings/reviewer request requires `Authorization: Bearer <token>`.
- `src/itsm_agent/api/auth.py` verifies the token and returns an immutable
  `Principal` (`principal_id`, `tenant_ids`, `roles`, `expires_at`, issuer).
- Tokens are `v1.<base64url(payload)>.<base64url(HMAC-SHA256)>`, signed with a
  server-held secret; claims include `sub`, `tenants`, `roles`, `iss`, `iat`,
  `exp`.
- Verification is fail-closed: missing header, non-`Bearer` scheme, malformed
  envelope, bad signature, wrong issuer, expired token, empty tenant list, and
  empty role list are all rejected with `401`.
- The actor (`reviewer_id`) and tenant scope come **only** from the verified
  principal. `reviewer_id` is not accepted in a request body; the decision
  schema is `extra="forbid"`, so sending one is a `422`.
- If the API is composed without an authenticator, the router returns `503`
  rather than serving unauthenticated data.

The HMAC implementation exists to avoid a new dependency for this slice. Any
real identity provider (OIDC/JWT, mTLS) can replace it behind the
`Authenticator` protocol without changing routes. It is not a home-grown
password system.

## 2. Authorization (RBAC)

`src/itsm_agent/api/rbac.py` defines a fixed allowlist:

| Role | Permissions |
|---|---|
| `auditor` | `findings:read`, `decisions:read` |
| `analyst` | auditor + `decisions:write`, `decision:needs_more_evidence` |
| `reviewer` | analyst + `decision:confirm`, `decision:false_positive`, `decision:accepted_risk` |
| `admin` | every permission, including `admin:manage` |

- Tenant membership is checked before permission: a requested `tenant_id` that
  is not in the principal's `tenant_ids` is `403`.
- Every decision type maps to exactly one permission; an unknown decision type
  is denied (and rejected by the request schema) **before any write**.
- Authorization is deny-by-default: unknown roles fail token validation, and
  unknown permissions grant nothing.

## 3. Tenant isolation in PostgreSQL (RLS)

`migrations/007_tenant_isolation.sql` enables **and forces** row-level
security on every tenant-owned table:

`source_events`, `source_checkpoints`, `identity_mappings`, `access_facts`,
`findings`, `evidence_references`, `coverage_status`, `review_decisions`,
`processing_records`, `event_inbox`, `outbox`.

- Every policy is
  `tenant_id = NULLIF(current_setting('itsm.tenant_id', true), '')::uuid`
  for both `USING` and `WITH CHECK`.
- The context is written with `set_config('itsm.tenant_id', …, true)`
  (`is_local=true`, transaction-local) in
  `src/itsm_agent/adapters/persistence/tenant.py`.
- For business tables, with no context the predicate is `NULL`: zero rows are
  visible and no row passes `WITH CHECK`. Missing context fails **closed**,
  not open.
- `event_inbox` and `outbox` also contain pre-tenant legacy rows
  (`tenant_id IS NULL`) from the incident webhook. Their policy additionally
  permits those NULL rows only when **no** tenant context is set: a
  tenant-scoped session sees only its own rows, and a no-context system
  session sees only legacy NULL rows. Neither can see the other's rows, and a
  tenant-scoped session cannot insert a NULL-tenant row.
- A pooled connection cannot leak one tenant's context into the next
  transaction; this is covered by a test using a `min_size=max_size=1` pool.
- `FORCE ROW LEVEL SECURITY` makes the policy apply to the table owner too.
  Only a superuser or a role with `BYPASSRLS` escapes.
- A `tenants` registry lets the relay and retention jobs enumerate tenants
  without reading tenant-owned rows. The runtime role may `SELECT` it and
  `INSERT` idempotently on ingest, but `UPDATE`/`DELETE`/`TRUNCATE` are
  revoked (`migrations/014_least_privilege_tenant_registry.sql`): tenancy
  lifecycle belongs to the administration plane.
- `evidence_references` gained a `tenant_id` plus composite foreign keys
  `(tenant_id, finding_id) → findings(tenant_id, id)`, so even a query-level
  bypass cannot attach evidence to another tenant's finding.
- `event_inbox` uniqueness is now tenant-scoped
  (`migrations/009_tenant_scoped_inbox.sql`): a tenant cannot exhaust another
  tenant's dedup namespace by submitting a colliding event id.

### Required deployment property

The application must connect with a dedicated **`NOBYPASSRLS`, non-superuser**
role. The role that owns the tables is also subject to the policy because of
`FORCE`, but `BYPASSRLS`/superuser would silently disable isolation. The local
and CI `itsm` role is a superuser, so the integration tests create a separate
constrained login role for the RLS assertions.

## 4. Evidence integrity and erasure

`migrations/008_retention_erasure.sql` adds `retention_policies`,
`legal_holds`, `erasure_requests` and `erasure_tombstones`, and
`src/itsm_agent/privacy/retention.py` implements planning.

- `source_events` is append-only and is **never** updated or deleted by
  retention. Erasing a raw payload records a tombstone carrying the original
  `payload_hash`, so integrity remains verifiable while the payload is
  acknowledged gone.
- Derived, rebuildable `access_facts` may be deleted.
- Findings and review decisions are retained audit records; there is no
  cascading delete of audit history.
- An active legal hold blocks execution and the request is marked `BLOCKED`.
- Policy lookup fails closed to `RETAIN` for an unknown data class.

## 5. Not covered (honest gaps)

- The HMAC secret is a single server-wide symmetric key; there is no key
  rotation, revocation list, or clock-skew allowance. A token is valid until
  `exp`.
- The HMAC bearer carries roles in the token and has no server-side freshness
  or revocation check. The OIDC relying party (`src/itsm_agent/api/oidc.py`)
  resolves current tenant/role state from `reviewer_authorizations` on every
  request. There is still no admin API for managing principals, tenants, or
  roles.
- Forced RLS now covers the incident/remediation tables too. Migration
  `011_tenant_owned_workflow.sql` adds `tenant_id` and forced RLS to
  `incidents`, `workflow_state`, `action_intents`, `approvals`, and
  `audit_events`; they are in `TENANT_RLS_TABLES` in
  `src/itsm_agent/adapters/persistence/privileges.py`.
- The ingestion webhook still authenticates with the existing HMAC webhook
  signature; it is not yet tied to the reviewer principal model.
- No rate limiting or audit trail of authentication failures beyond structured
  logs.
- Retention runs on a timer via the packaged
  `python -m itsm_agent.workers.retention` process (compose service
  `retention`). The scheduler is implemented and lifecycle-tested
  (`src/itsm_agent/privacy/scheduler.py`,
  `tests/integration/test_retention_scheduler_lifecycle.py`); the worker
  refuses to start against a role that can bypass RLS. Raw evidence is
  tombstoned, not deleted from external object storage.
- RLS tests run against a real PostgreSQL role, but the project's CI service
  account is a superuser; a production deployment must still prove its own
  role is `NOBYPASSRLS`. The startup check is implemented:
  `verify_runtime_database` (`privileges.py`) is called from the API lifespan
  (`src/itsm_agent/api/app.py`) and worker startup
  (`src/itsm_agent/workers/consumer.py`).
