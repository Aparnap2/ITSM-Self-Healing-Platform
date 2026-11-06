-- 014_least_privilege_tenant_registry.sql
-- Runtime least-privilege hardening for the tenant registry.
--
-- ``tenants`` is administration-plane data: tenancy is created and retired by
-- the provisioning plane, not by the API or worker. Migration 010's broad
-- ``GRANT ... ON ALL TABLES`` gave the runtime role UPDATE/DELETE on it, which
-- would let a compromised runtime rename or delete tenancy (and, via DELETE,
-- orphan tenant-owned rows that the outbox relay and retention scheduler
-- enumerate).
--
-- The runtime role keeps exactly what ingestion needs:
--   * SELECT  — enumerate tenants for scoped relay/retention passes;
--   * INSERT  — idempotent ``ON CONFLICT DO NOTHING`` registration on ingest.
-- It loses UPDATE, DELETE and TRUNCATE.
--
-- Migration 010's ALTER DEFAULT PRIVILEGES still grants write on *future*
-- tables; this file is scoped to the existing registry table. New
-- administration-plane tables must be narrowed in the migration that creates
-- them.
--
-- This file is idempotent and fails closed if the table is absent.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'tenants'
           AND c.relkind = 'r'
    ) THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.tenants FROM itsm_app';
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.tenants FROM PUBLIC';
        EXECUTE 'GRANT SELECT, INSERT ON public.tenants TO itsm_app';
    END IF;
END $$;

COMMIT;
