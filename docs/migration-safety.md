# Migration safety harness

`tests/integration/test_migration_safety.py` proves the schema contracts hold
on both the fresh-install and upgrade paths. It creates and drops a unique
scratch database per test, so it never mutates the suite's shared `itsm_test`
database.

## What it asserts

| Test | Contract |
| --- | --- |
| `test_fresh_apply_records_all_migrations_and_role` | Every migration file is recorded; `itsm_app` is `NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT`; forced RLS and a policy exist on every tenant-owned table; append-only tables reject `UPDATE`/`DELETE`/`TRUNCATE`; the runtime role cannot read `schema_migrations`; the system tenant exists |
| `test_apply_twice_is_idempotent` | A second apply records zero files |
| `test_upgrade_backfill_matching_source_event` | An incident whose `external_event_id` matches a canonical `source_events.source_event_id` inherits that event's tenant; children inherit the parent |
| `test_single_tenant_backfill_uses_that_tenant` | With exactly one non-system tenant, unmatched legacy rows go to it |
| `test_multiple_tenants_without_match_use_system_tenant` | With multiple tenants, unmatched legacy rows go to `system-legacy` |
| `test_upgrade_preserves_existing_rows` | Pre-existing key columns and row counts are unchanged by the upgrade |
| `test_upgrade_adds_tenant_constraints_and_indexes` | `tenant_id` is `NOT NULL` on the workflow tables; composite tenant FKs, the `(tenant_id, id)` uniqueness anchor, and tenant indexes exist |
| `test_injected_failing_migration_is_not_recorded` | A failing migration is rolled back entirely, is not recorded in `schema_migrations`, and a corrected rerun applies cleanly |
| `test_system_tenant_rows_invisible_to_other_tenant` | A session scoped to another tenant cannot read system-tenant rows, even as `itsm_app` |
| `test_tenant_registry_is_readable_and_insertable_but_immutable_at_runtime` | `itsm_app` can select and idempotently insert tenants, but `UPDATE`/`DELETE` fail with `42501` (migration 014) |

Marker: `integration` + `security`.

## Deterministic backfill policy

Migration `011_tenant_owned_workflow.sql` backfills `incidents` (and then
children) as follows:

1. Match `incidents.external_event_id` to `source_events.source_event_id` and
   copy that event's tenant.
2. If exactly one **non-system** tenant exists, assign the remaining rows to
   it.
3. Otherwise assign the remaining rows to the fixed `system-legacy` tenant
   (`00000000-0000-0000-0000-000000000001`), which no reviewer belongs to.

Rule 2 previously counted the system tenant itself, which made it
unreachable; the harness caught this and the migration now excludes the system
row from the count.

## Running

```
ITSM_TEST_PG_DSN=postgresql://itsm:itsm@localhost:5544/itsm_test \
ITSM_TEST_NATS_URL=nats://localhost:4224 \
ITSM_TEST_STRICT=1 \
uv run pytest tests/integration/test_migration_safety.py -q
```

## Limitations

- The failure-injection test uses a synthetic `099_` file in a temporary
  migration directory; it does not exercise a real PostgreSQL crash or an
  interrupted connection mid-file.
- Catalog equivalence is asserted on named constraints and indexes rather than
  a full `pg_dump --schema-only` diff.
- Editing a migration that has already been applied to a long-lived database
  does not re-run it there; schema changes to applied migrations require a new
  forward migration in deployed environments.
