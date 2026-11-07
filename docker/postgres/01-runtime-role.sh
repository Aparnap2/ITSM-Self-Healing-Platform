#!/bin/sh
# Create the least-privileged runtime login role on a fresh database.
#
# Migration 010 creates `itsm_app` as NOLOGIN on purpose: in a real deployment
# the platform attaches credentials out of band. For the local compose stack
# this init hook performs that step so api/worker/relay can connect as the
# constrained role instead of the superuser. Grants are still applied by the
# migrations; this script only creates the role and its password.
#
# Runs only when the postgres volume is first initialised. Existing volumes
# need `make compose-reset` or a manual ALTER ROLE.
set -eu

: "${ITSM_RUNTIME_DB_PASSWORD:?ITSM_RUNTIME_DB_PASSWORD must be set}"
: "${POSTGRES_USER:?POSTGRES_USER must be set}"
: "${POSTGRES_DB:?POSTGRES_DB must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v runtime_password="$ITSM_RUNTIME_DB_PASSWORD" <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'itsm_app') THEN
        CREATE ROLE itsm_app
            NOLOGIN
            NOSUPERUSER
            NOBYPASSRLS
            NOCREATEDB
            NOCREATEROLE
            INHERIT;
    END IF;
END
$$;

ALTER ROLE itsm_app
    LOGIN
    NOSUPERUSER
    NOBYPASSRLS
    NOCREATEDB
    NOCREATEROLE
    PASSWORD :'runtime_password';
SQL
