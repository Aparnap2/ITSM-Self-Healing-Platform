-- 009_tenant_scoped_inbox.sql
-- Tenant-scope the ingestion dedup key.
--
-- Background: 001 created a *global* uniqueness constraint on
-- (source_system, external_event_id). Once tenants share one database, a
-- tenant that submits an event id used by another tenant would either be
-- deduplicated against a row it cannot see (cross-tenant denial of service)
-- or, worse, be treated as a duplicate of another tenant's event. The dedup
-- namespace must therefore include the tenant.
--
-- Legacy rows written before tenant context existed keep tenant_id IS NULL and
-- retain the old global dedup semantics through a partial index, so mixed
-- old/new rows cannot collide.

BEGIN;

ALTER TABLE event_inbox DROP CONSTRAINT IF EXISTS uq_inbox_source_event;

-- One event id per (tenant, source system, external id).
CREATE UNIQUE INDEX IF NOT EXISTS uq_inbox_tenant_source_event
    ON event_inbox (tenant_id, source_system, external_event_id)
    WHERE tenant_id IS NOT NULL;

-- Pre-tenant rows keep global dedup among themselves.
CREATE UNIQUE INDEX IF NOT EXISTS uq_inbox_legacy_source_event
    ON event_inbox (source_system, external_event_id)
    WHERE tenant_id IS NULL;

-- Superseded by the unique index above.
DROP INDEX IF EXISTS ix_inbox_tenant_source_event;

COMMIT;
