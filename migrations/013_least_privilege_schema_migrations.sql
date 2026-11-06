-- 013_least_privilege_schema_migrations.sql
-- Runtime least-privilege hardening, owner-approved.
--
-- The migration applier creates ``schema_migrations`` at runtime, so it may
-- legitimately be absent when migrations are applied by another tool (e.g.
-- the guarded psql loop used by CI). The runtime role never reads or writes
-- the bookkeeping table; if present it must have no privileges on it.
--
-- This file is idempotent and fails closed only when the table exists and the
-- REVOKE itself errors.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'schema_migrations'
    ) THEN
        EXECUTE 'REVOKE ALL ON public.schema_migrations FROM itsm_app';
        EXECUTE 'REVOKE ALL ON public.schema_migrations FROM PUBLIC';
    END IF;
END $$;

COMMIT;
