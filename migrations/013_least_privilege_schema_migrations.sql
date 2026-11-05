-- 013_least_privilege_schema_migrations.sql
-- Runtime least-privilege hardening, owner-approved.
--
-- The migration applier creates ``schema_migrations`` before migration 010
-- runs, so 010's broad "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"
-- included the bookkeeping table. The application never queries or writes
-- it: migrations are an administration-plane concern. The runtime role must
-- not be able to rewrite migration history.

BEGIN;

REVOKE ALL ON schema_migrations FROM itsm_app;
REVOKE ALL ON schema_migrations FROM PUBLIC;

COMMIT;
