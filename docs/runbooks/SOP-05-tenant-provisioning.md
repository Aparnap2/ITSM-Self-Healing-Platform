# SOP-05 — Provision and retire a tenant

Scope: the `tenants` registry row, reviewer authorization rows, and the RLS
context a tenant-scoped session must carry.
Audience: operator with the administration database connection; runtime
credentials are never used for provisioning.

## Purpose

Create a tenant that the outbox relay and retention jobs can enumerate,
attach a reviewer who may act for it, prove that row-level security (RLS)
fails closed, and retire the tenant without orphaning records.

Provisioning is an administration-plane action. The runtime role can register
a tenant idempotently during ingestion but cannot rename or delete one
(`migrations/014_least_privilege_tenant_registry.sql`).

## Scope

In scope:

- `tenants` (`migrations/007_tenant_isolation.sql:25-29`).
- `reviewer_authorizations` (`migrations/010_runtime_role.sql:47-69`).
- RLS policies for tenant-owned tables
  (`migrations/007_tenant_isolation.sql`, `migrations/011_tenant_owned_workflow.sql`).
- Tenant context helper
  (`src/itsm_agent/adapters/persistence/tenant.py`).
- Runtime role checks (`src/itsm_agent/adapters/persistence/privileges.py`).

Out of scope: creating database roles or credentials, IdP account creation,
and data-erasure policy changes.

## Preconditions

- Migrations `migrations/010_runtime_role.sql`,
  `migrations/011_tenant_owned_workflow.sql`, and
  `migrations/014_least_privilege_tenant_registry.sql` are applied. Verify:

```sh
uv run python -m migrations.apply --dsn "$ADMIN_DATABASE_URL"
```

- `ADMIN_DATABASE_URL` points at the owner/administration connection. Never
  use the runtime `DATABASE_URL` for the writes below.
- The tenant UUID is fixed and written in the change ticket. Use a fresh
  UUIDv4; never reuse `00000000-0000-0000-0000-000000000001`
  (`system-legacy`, reserved by `migrations/011_tenant_owned_workflow.sql:25-27`).
- The reviewer's `issuer` and `subject` come from the identity provider, and
  the role is one of `auditor`, `analyst`, `reviewer`, `admin`
  (`src/itsm_agent/api/auth.py:42-48`; permissions in
  `src/itsm_agent/api/rbac.py:31-58`).
- A change ticket exists. Tenant lifecycle is not a break-glass action.

## Symptoms and triggers

| Trigger | Why it needs this SOP |
| --- | --- |
| New customer or environment | no registry row; the relay will not enumerate it |
| Reviewer joins or changes scope | authorization row missing or stale |
| Reviewer leaves | authorization must be deactivated |
| Tenant offboarding | data must be erased before the registry row is removed |
| Suspected cross-tenant read | verify RLS flags and runtime role before changing data |

A missing `tenants` row is not only a metadata gap: `OutboxRelay.run()`
enumerates `PsycopgTenantRepository.list_tenant_ids()` and performs one
scoped pass per tenant (`src/itsm_agent/adapters/messaging/outbox_relay.py:97-114`).
Without a registry row, that tenant's outbox is never relayed.

## Procedure

### 1. Open the administration connection

```sh
psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1
```

### 2. Create the tenant registry row

```sql
INSERT INTO tenants (id, name)
VALUES ('<tenant-uuid>'::uuid, '<tenant-name>')
ON CONFLICT (id) DO NOTHING;

SELECT id, name, created_at
FROM tenants
WHERE id = '<tenant-uuid>'::uuid;
```

Use a human-readable `name` that identifies the customer or environment. Do
not put secrets, email addresses, or personal data in it: the registry is
readable by the runtime role.

### 3. Read the reviewer's current authorization before writing

```sql
SELECT issuer, subject, tenant_ids, roles, active, authorization_version,
       updated_at
FROM reviewer_authorizations
WHERE issuer = '<issuer>' AND subject = '<subject>';
```

If the row exists, the write below replaces `tenant_ids` and `roles`. Include
all tenants and roles the reviewer must retain, not only the new tenant.

### 4. Attach or update the reviewer authorization

```sql
INSERT INTO reviewer_authorizations (
    issuer, subject, tenant_ids, roles, active, authorization_version
) VALUES (
    '<issuer>',
    '<subject>',
    ARRAY['<tenant-uuid>']::uuid[],
    ARRAY['reviewer']::text[],
    true,
    '<authorization-version>'
)
ON CONFLICT (issuer, subject) DO UPDATE SET
    tenant_ids = EXCLUDED.tenant_ids,
    roles = EXCLUDED.roles,
    active = EXCLUDED.active,
    authorization_version = EXCLUDED.authorization_version,
    updated_at = now();
```

Notes:

- `tenant_ids` and `roles` must be non-empty; the table has check constraints
  (`migrations/010_runtime_role.sql:56-60`).
- A reviewer may cover several tenants; the array is the full membership
  list, not a delta.
- `authorization_version` is required and is carried into the principal.
  Increment it on every change so the change is distinguishable in audit
  evidence.
- The runtime role may `SELECT` this table but never write it
  (`src/itsm_agent/adapters/persistence/privileges.py:82-85,244-249`). Only the administration connection may
  change it.

`PsycopgReviewerDirectory` reads this table by `(issuer, subject)` when the
API is composed with the OIDC authenticator
(`src/itsm_agent/api/oidc.py:104-132`). The HMAC bearer authenticator carries
roles in the token and does not read this table; provisioning the directory
alone does not change an HMAC token's claims.

### 5. Verify the registry is visible and immutable at runtime

```sql
SELECT has_table_privilege('itsm_app', 'tenants', 'SELECT') AS can_select,
       has_table_privilege('itsm_app', 'tenants', 'INSERT') AS can_insert,
       has_table_privilege('itsm_app', 'tenants', 'UPDATE') AS can_update,
       has_table_privilege('itsm_app', 'tenants', 'DELETE') AS can_delete,
       has_table_privilege('itsm_app', 'tenants', 'TRUNCATE') AS can_truncate;
```

Expected: `t, t, f, f, f`. The runtime `INSERT` exists only for idempotent
registration during ingestion (`PsycopgTenantRepository.ensure`, called from
`src/itsm_agent/adapters/persistence/ingestion_sink.py:85`).

Prove the denial behaviourally:

```sql
BEGIN;
SET LOCAL ROLE itsm_app;
UPDATE tenants SET name = name WHERE id = '<tenant-uuid>'::uuid;
-- Expected: ERROR: permission denied for table tenants (SQLSTATE 42501)
ROLLBACK;

BEGIN;
SET LOCAL ROLE itsm_app;
DELETE FROM tenants WHERE id = '<tenant-uuid>'::uuid;
-- Expected: ERROR: permission denied for table tenants (SQLSTATE 42501)
ROLLBACK;
```

This mirrors `tests/integration/test_migration_safety.py:644-675`.

### 6. Verify RLS is enabled and forced

```sql
SELECT c.relname,
       c.relrowsecurity  AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND c.relname = ANY (ARRAY[
      'source_events', 'source_checkpoints', 'identity_mappings',
      'access_facts', 'findings', 'evidence_references', 'coverage_status',
      'review_decisions', 'processing_records', 'event_inbox', 'outbox',
      'incidents', 'workflow_state', 'action_intents', 'approvals',
      'audit_events', 'erasure_requests', 'erasure_tombstones'
  ])
ORDER BY c.relname;
```

Every row must be `t, t`. `FORCE` matters because it applies the policy to
the table owner as well; only a superuser or a `BYPASSRLS` role escapes
(`migrations/007_tenant_isolation.sql:10-12`).

### 7. Verify the tenant context fails closed

Under the runtime role with the tenant set:

```sql
BEGIN;
SET LOCAL ROLE itsm_app;
SELECT set_config('itsm.tenant_id', '<tenant-uuid>', true);
SELECT current_setting('itsm.tenant_id', true) AS tenant_context;
SELECT count(*) AS visible_source_events FROM source_events;
ROLLBACK;
```

Expected: `tenant_context` equals the UUID; `visible_source_events` counts
only that tenant's rows.

Under the runtime role with no context:

```sql
BEGIN;
SET LOCAL ROLE itsm_app;
SELECT current_setting('itsm.tenant_id', true) AS tenant_context;
SELECT count(*) AS visible_source_events FROM source_events;
ROLLBACK;
```

Expected: `tenant_context` is empty/NULL and `visible_source_events` is `0`
even when the table has rows for the tenant verified in the previous step.
This is the fail-closed property implemented by
`src/itsm_agent/adapters/persistence/tenant.py:30-47`.

### 8. Verify the application boundary (optional, requires a token)

Use a token issued by the configured authenticator; do not paste it into the
ticket or shell history.

```sh
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer ${REVIEWER_TOKEN}" \
  "http://127.0.0.1:${API_HOST_PORT:-8000}/v1/findings?tenant_id=<tenant-uuid>"
```

- A member of the tenant gets `200`.
- A principal that does not carry the tenant gets `403`.
- A missing or invalid token gets `401`.

The API also refuses to start with a database role that can bypass RLS:
`verify_runtime_database` is called from the app lifespan
(`src/itsm_agent/api/app.py`) and the worker (`src/itsm_agent/workers/consumer.py:82-84`),
and raises `DatabaseSafetyError`
(`src/itsm_agent/adapters/persistence/privileges.py:95-103,253-270`).

## Verification checklist

- [ ] `tenants` row exists with the expected id and name.
- [ ] `reviewer_authorizations` row is active and lists the tenant.
- [ ] `itsm_app` has `SELECT, INSERT` and lacks `UPDATE, DELETE, TRUNCATE`
      on `tenants`.
- [ ] A runtime `UPDATE`/`DELETE` on `tenants` fails with `42501`.
- [ ] Every tenant-owned table shows `rls_enabled = t` and `rls_forced = t`.
- [ ] With context, only the tenant's rows are visible.
- [ ] Without context, zero rows are visible.
- [ ] The API returns `200` for a member and `403` for a non-member.
- [ ] No secret or token is in the ticket.

## Offboarding

Order matters: deactivate access, erase data, verify zero rows, then remove
the registry row.

### 1. Deactivate reviewer authorizations

```sql
UPDATE reviewer_authorizations
SET active = false,
    authorization_version = '<new-version>',
    updated_at = now()
WHERE tenant_ids @> ARRAY['<tenant-uuid>']::uuid[];

SELECT issuer, subject, tenant_ids, roles, active, authorization_version
FROM reviewer_authorizations
WHERE tenant_ids @> ARRAY['<tenant-uuid>']::uuid[];
```

A reviewer who also covers other tenants keeps those memberships; remove the
UUID from the array only if the reviewer should lose this tenant but keep the
others, and still increment `authorization_version`.

### 2. Run the retention/erasure path

Erasure is programmatic and tenant-scoped
(`src/itsm_agent/privacy/retention.py`,
`migrations/008_retention_erasure.sql`). The scheduler is implemented and
lifecycle-tested but is not wired into an always-on worker in this baseline,
so an operator must invoke `run_once`/`run_forever`
(`src/itsm_agent/privacy/scheduler.py`). Raw evidence is tombstoned, not
deleted from `source_events`; derived `access_facts` may be deleted; findings
and review decisions are retained audit records.

### 3. Verify no tenant-owned rows remain

```sql
SELECT 'source_events' AS table_name, count(*) FROM source_events WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'event_inbox', count(*) FROM event_inbox WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'outbox', count(*) FROM outbox WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'findings', count(*) FROM findings WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'review_decisions', count(*) FROM review_decisions WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'processing_records', count(*) FROM processing_records WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'incidents', count(*) FROM incidents WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'workflow_state', count(*) FROM workflow_state WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'action_intents', count(*) FROM action_intents WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'approvals', count(*) FROM approvals WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'audit_events', count(*) FROM audit_events WHERE tenant_id = '<tenant-uuid>'::uuid
UNION ALL SELECT 'erasure_requests', count(*) FROM erasure_requests WHERE tenant_id = '<tenant-uuid>'::uuid;
```

Do not remove the `tenants` row while any count is non-zero. Migration 014's
header warns that deletion can orphan tenant-owned rows that the relay and
retention scheduler enumerate
(`migrations/014_least_privilege_tenant_registry.sql:4-14`).

### 4. Remove the registry row (administration only)

```sql
DELETE FROM tenants
WHERE id = '<tenant-uuid>'::uuid
  AND NOT EXISTS (
      SELECT 1 FROM source_events WHERE tenant_id = '<tenant-uuid>'::uuid
  )
  AND NOT EXISTS (
      SELECT 1 FROM findings WHERE tenant_id = '<tenant-uuid>'::uuid
  );
```

The `NOT EXISTS` guards are intentionally narrow; the full check is the
step-3 query. The runtime role cannot execute this statement.

### 5. Revoke external access

Disable the IdP account or group membership outside this repository. This
SOP does not manage identity-provider credentials.

## Rollback and recovery

- A wrongly created tenant with zero rows: delete the registry row and the
  authorization row; there is nothing else to undo.
- A wrongly created tenant with rows: do not delete the registry row.
  Deactivate it, follow the retention policy, and escalate. Deleting the row
  first makes the rows invisible to the relay and retention enumeration.
- A wrongly attached reviewer: set `active = false`, increment
  `authorization_version`, and record the correction.
- Migrations are forward-only; there is no down migration
  (`docs/migration-safety.md`, `docs/production-readiness.md`).

## Escalation

| Condition | Escalate to | Timing |
| --- | --- | --- |
| Tenant UUID collides with an existing row | `<platform-owner>` | before writing |
| Runtime `UPDATE`/`DELETE` on `tenants` succeeds | `<security-lead>` | immediate; stop the service |
| RLS flag is `false` on any tenant table | `<security-lead>` | immediate |
| A non-member receives `200` | `<security-lead>` | immediate |
| Offboarding needs data beyond the retention policy | `<data-owner>` | before erasure |
| Reviewer authorization change is disputed | `<security-lead>` | before writing |

## Evidence to capture

- Change ticket id and approver.
- Tenant UUID and name (no personal data in the name).
- `reviewer_authorizations` row before and after, including
  `authorization_version`.
- Output of the privilege, RLS, and context checks.
- The HTTP status codes from the boundary check (not the token).
- For offboarding: erasure request id, tombstone count, and the step-3
  zero-row result.
- Timestamps in UTC.

## Known limitations

- There is no provisioning CLI or admin API. SQL on the administration
  connection is the only supported path
  (`docs/security-boundaries.md:116-120`).
- The runtime role can `INSERT` into `tenants` by design, for idempotent
  registration on ingest. That is not an authorization to create tenancy;
  `UPDATE`, `DELETE`, and `TRUNCATE` are revoked
  (`migrations/014_least_privilege_tenant_registry.sql`).
- `reviewer_authorizations` is not under RLS. It is a directory table; the
  runtime role can `SELECT` all rows and cannot write them
  (`src/itsm_agent/adapters/persistence/privileges.py:82-85`). The application filters by `(issuer, subject)`.
- Roles are carried in the token or read from the directory; there is no
  key-rotation or server-side revocation list beyond `active` and
  `authorization_version` (`docs/security-boundaries.md:113-115`).
- The `system-legacy` tenant (`00000000-0000-0000-0000-000000000001`) is
  infrastructure. No reviewer may be a member; migration 011 assigns
  unmatched legacy rows to it.
- Retention has no always-on scheduler worker in this baseline: the
  scheduler exists and is lifecycle-tested
  (`src/itsm_agent/privacy/scheduler.py`,
  `tests/integration/test_retention_scheduler_lifecycle.py`), but it is not
  wired to a deployed entrypoint, so offboarding erasure remains
  operator-driven and can be incomplete if the step is skipped.
- The startup RLS assertion proves the role is `NOBYPASSRLS`; it does not
  prove the deployed database is the one you intended to connect to.
