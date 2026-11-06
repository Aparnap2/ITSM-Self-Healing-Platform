"""Migration safety harness (Slice 3 acceptance).

These tests prove the schema migrations preserve the security contracts across
both fresh installation and upgrade. They use hermetic scratch databases and
never mutate the suite's shared ``itsm_test`` database.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from psycopg import AsyncConnection, Error, sql
from psycopg.conninfo import make_conninfo

from itsm_agent.adapters.persistence.migrations import apply_migrations
from itsm_agent.adapters.persistence.privileges import (
    APPEND_ONLY_TABLES,
    TENANT_RLS_TABLES,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]

PG_DSN = os.environ.get("ITSM_TEST_PG_DSN", "postgresql://itsm:itsm@localhost:5432/itsm_test")
STRICT = os.environ.get("ITSM_TEST_STRICT") == "1"
MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"
SYSTEM_TENANT = "00000000-0000-0000-0000-000000000001"


def _dsn(database: str) -> str:
    return make_conninfo(PG_DSN, dbname=database)


def _migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"))


async def _apply(dsn: str, monkeypatch: pytest.MonkeyPatch, upto: int | None = None) -> None:
    """Apply all migrations, or those with file number <= ``upto``."""
    from itsm_agent.adapters.persistence import migrations as migrations_module

    files = (
        _migration_files()
        if upto is None
        else [f for f in _migration_files() if int(f.name.split("_")[0]) <= upto]
    )
    monkeypatch.setattr(migrations_module, "_migration_files", lambda: files)
    await apply_migrations(dsn)


@pytest.fixture
async def scratch_db(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[str]:
    name = f"itsm_mig_{secrets.token_hex(8)}"
    admin = await AsyncConnection.connect(PG_DSN, autocommit=True)
    try:
        await admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        yield _dsn(name)
    finally:
        try:
            await admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
        finally:
            await admin.close()


@pytest.fixture
async def fresh_db(monkeypatch: pytest.MonkeyPatch, scratch_db: str) -> AsyncIterator[str]:
    await _apply(scratch_db, monkeypatch)
    yield scratch_db


@pytest.fixture
async def legacy_db(monkeypatch: pytest.MonkeyPatch, scratch_db: str) -> AsyncIterator[str]:
    await _apply(scratch_db, monkeypatch, upto=10)
    yield scratch_db


async def _scalar(dsn: str, query: str, params: tuple[object, ...] = ()) -> object:
    async with await AsyncConnection.connect(dsn) as conn:
        row = await (await conn.execute(query, params)).fetchone()
    assert row is not None, f"query returned no rows: {query}"
    return row[0]


async def _rows(dsn: str, query: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    async with await AsyncConnection.connect(dsn) as conn:
        return list(await (await conn.execute(query, params)).fetchall())


async def _schema_migrations(dsn: str) -> set[str]:
    async with await AsyncConnection.connect(dsn) as conn:
        rows = await (await conn.execute("SELECT filename FROM schema_migrations")).fetchall()
    return {row[0] for row in rows}


async def _assert_schema_contract(dsn: str) -> None:
    assert await _scalar(dsn, "SELECT count(*) FROM schema_migrations") == len(_migration_files())

    async with await AsyncConnection.connect(dsn) as conn:
        # Every tenant-owned application table is RLS-enabled and forced.
        rows = await (
            await conn.execute(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'public'
                   AND c.relkind = 'r'
                   AND c.relname = ANY(%s)
                """,
                (list(TENANT_RLS_TABLES),),
            )
        ).fetchall()
    observed = {name: (enabled, forced) for name, enabled, forced in rows}
    for table in TENANT_RLS_TABLES:
        assert table in observed, f"{table}: expected RLS metadata missing"
        assert observed[table][0], f"{table}: row-level security not enabled"
        assert observed[table][1], f"{table}: row-level security not forced"

    # Required policies and migration objects.
    async with await AsyncConnection.connect(dsn) as conn:
        for table in TENANT_RLS_TABLES:
            row = await (
                await conn.execute(
                    """
                    SELECT 1 FROM pg_policy p
                      JOIN pg_class c ON c.oid = p.polrelid
                      JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = 'public' AND c.relname = %s
                    """,
                    (table,),
                )
            ).fetchone()
            assert row == (1,), f"{table}: expected policy missing"

        for table in APPEND_ONLY_TABLES:
            await assert_append_only_role(conn, table)


async def assert_append_only_role(conn: AsyncConnection, table: str) -> None:
    await conn.execute("SET ROLE itsm_app")
    try:
        write_update = await (
            await conn.execute("SELECT has_table_privilege(current_user, %s, 'UPDATE')", (table,))
        ).fetchone()
        write_delete = await (
            await conn.execute("SELECT has_table_privilege(current_user, %s, 'DELETE')", (table,))
        ).fetchone()
        write_truncate = await (
            await conn.execute("SELECT has_table_privilege(current_user, %s, 'TRUNCATE')", (table,))
        ).fetchone()
        assert write_update == (False,)
        assert write_delete == (False,)
        assert write_truncate == (False,)
    finally:
        await conn.execute("RESET ROLE")


async def _assert_runtime_role(dsn: str) -> None:
    async with await AsyncConnection.connect(dsn) as conn:
        row = await (
            await conn.execute(
                """
                SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole, rolinherit
                  FROM pg_roles WHERE rolname = 'itsm_app'
                """
            )
        ).fetchone()
    assert row is not None
    assert row == (False, False, False, False, False, True)

    async with await AsyncConnection.connect(dsn) as conn:
        await conn.execute("SET ROLE itsm_app")
        for table in APPEND_ONLY_TABLES:
            row = await (
                await conn.execute(
                    "SELECT has_table_privilege(current_user, %s, 'UPDATE'), "
                    "has_table_privilege(current_user, %s, 'DELETE')",
                    (table, table),
                )
            ).fetchone()
            assert row == (False, False), f"{table}: append-only grants missing"
        row = await (
            await conn.execute(
                "SELECT has_table_privilege(current_user, 'reviewer_authorizations', 'INSERT')"
            )
        ).fetchone()
        assert row == (False,)
        row = await (
            await conn.execute(
                "SELECT has_table_privilege(current_user, 'schema_migrations', 'SELECT')"
            )
        ).fetchone()
        assert row == (False,)
        row = await (
            await conn.execute(
                "SELECT has_table_privilege(current_user, 'tenants', 'SELECT'), "
                "has_table_privilege(current_user, 'tenants', 'INSERT'), "
                "has_table_privilege(current_user, 'tenants', 'UPDATE'), "
                "has_table_privilege(current_user, 'tenants', 'DELETE'), "
                "has_table_privilege(current_user, 'tenants', 'TRUNCATE')"
            )
        ).fetchone()
        # Registry: enumerate + idempotent registration only. Tenancy lifecycle
        # (rename/delete/truncate) is administration-plane.
        assert row == (True, True, False, False, False)
        await conn.execute("RESET ROLE")

    async with await AsyncConnection.connect(dsn) as conn:
        row = await (
            await conn.execute(
                "SELECT count(*) FROM tenants WHERE id = %s AND name = 'system-legacy'",
                (SYSTEM_TENANT,),
            )
        ).fetchone()
        assert row == (1,)


async def _insert_tenants(dsn: str, tenant_ids: tuple[uuid.UUID, ...]) -> None:
    async with await AsyncConnection.connect(dsn) as conn:
        for tenant_id in tenant_ids:
            await conn.execute(
                "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, f"test-{tenant_id.hex[:8]}"),
            )
        await conn.commit()


async def _insert_legacy_payload(
    dsn: str,
    *,
    incident_id: uuid.UUID,
    correlation_id: uuid.UUID,
    external_event_id: str | None,
) -> None:
    now = datetime.now(UTC)
    async with await AsyncConnection.connect(dsn) as conn:
        await conn.execute(
            """
            INSERT INTO incidents (
                id, source_system, source_incident_id, external_event_id,
                title, description, service_name, severity, status,
                created_at, updated_at, correlation_id
            ) VALUES (%(id)s, 'mockoon-itsm', 'LEGACY-1', %(external_event_id)s,
                      'legacy', 'legacy incident', 'payments-api', 'P2', 'NEW',
                      %(created_at)s, %(updated_at)s, %(correlation_id)s)
            """,
            {
                "id": incident_id,
                "external_event_id": external_event_id,
                "created_at": now,
                "updated_at": now,
                "correlation_id": correlation_id,
            },
        )
        await conn.execute(
            """
            INSERT INTO workflow_state (
                id, incident_id, workflow_version, status, current_node,
                checkpoint_ref, attempt_count, started_at, updated_at, correlation_id
            ) VALUES (%(id)s, %(incident_id)s, 'v1', 'PENDING', 'start',
                      NULL, 0, now(), now(), %(correlation_id)s)
            """,
            {
                "id": uuid.uuid4(),
                "incident_id": incident_id,
                "correlation_id": correlation_id,
            },
        )
        await conn.commit()


async def test_fresh_apply_records_all_migrations_and_role(fresh_db: str) -> None:
    expected = {f.name for f in _migration_files()}
    assert await _schema_migrations(fresh_db) == expected
    await _assert_schema_contract(fresh_db)
    await _assert_runtime_role(fresh_db)


async def test_apply_twice_is_idempotent(fresh_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from itsm_agent.adapters.persistence import migrations as migrations_module

    monkeypatch.setattr(migrations_module, "_migration_files", _migration_files)
    applied = await apply_migrations(fresh_db)
    assert applied == []


async def test_upgrade_backfill_matching_source_event(
    legacy_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenants = (uuid.uuid4(), uuid.uuid4())
    now = datetime.now(UTC)
    incident_id = uuid.uuid4()
    workflow_id = uuid.uuid4()
    correlation_id = uuid.uuid4()

    async with await AsyncConnection.connect(legacy_db) as conn:
        for tenant_id in tenants:
            await conn.execute(
                "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, f"test-{tenant_id.hex[:8]}"),
            )
        await conn.execute(
            """
            INSERT INTO source_events (
                id, tenant_id, source, source_event_id, idempotency_key,
                canonical_schema_version, event_type, event_category,
                event_time, observed_at, action, payload_hash
            ) VALUES (%(id)s, %(tenant_id)s, 'cloudtrail', %(source_event_id)s,
                      %(key)s, '1.0', 'AssumeRole', 'auth', now(), now(),
                      'sts:AssumeRole', %(hash)s)
            """,
            [
                {
                    "id": uuid.uuid4(),
                    "tenant_id": tenants[0],
                    "source_event_id": f"ext-{incident_id.hex}",
                    "key": f"key-{incident_id.hex}",
                    "hash": "0" * 64,
                },
                {
                    "id": uuid.uuid4(),
                    "tenant_id": tenants[1],
                    "source_event_id": f"other-{uuid.uuid4().hex}",
                    "key": f"key-{uuid.uuid4().hex}",
                    "hash": "0" * 64,
                },
            ][0],
        )
        await conn.execute(
            """
            INSERT INTO incidents (
                id, source_system, source_incident_id, external_event_id,
                title, description, service_name, severity, status,
                created_at, updated_at, correlation_id
            ) VALUES (%(id)s, 'mockoon-itsm', %(source_incident_id)s,
                      %(external_event_id)s, 'legacy', 'legacy incident',
                      'payments-api', 'P2', 'NEW', %(created_at)s, %(updated_at)s,
                      %(correlation_id)s)
            """,
            {
                "id": incident_id,
                "source_incident_id": f"LEGACY-{incident_id.hex}",
                "external_event_id": f"ext-{incident_id.hex}",
                "created_at": now,
                "updated_at": now,
                "correlation_id": correlation_id,
            },
        )
        await conn.execute(
            """
            INSERT INTO workflow_state (
                id, incident_id, workflow_version, status, current_node,
                checkpoint_ref, attempt_count, started_at, updated_at, correlation_id
            ) VALUES (%(id)s, %(incident_id)s, 'v1', 'PENDING', 'start',
                      NULL, 0, now(), now(), %(correlation_id)s)
            """,
            {
                "id": workflow_id,
                "incident_id": incident_id,
                "correlation_id": correlation_id,
            },
        )
        await conn.execute(
            """
            INSERT INTO action_intents (
                id, incident_id, workflow_id, action_type, resource_id,
                idempotency_key, proposal_hash, status, attempt_number,
                intent_recorded_at, adapter_name
            ) VALUES (%(id)s, %(incident_id)s, %(workflow_id)s, 'RESTART_SERVICE',
                      'payments-api', %(key)s, %(hash)s, 'INTENT_RECORDED', 1,
                      now(), 'test-adapter')
            """,
            {
                "id": uuid.uuid4(),
                "incident_id": incident_id,
                "workflow_id": workflow_id,
                "key": f"action-{uuid.uuid4().hex}",
                "hash": "a" * 64,
            },
        )
        await conn.commit()

    await _apply(legacy_db, monkeypatch)
    row = await _rows(
        legacy_db,
        "SELECT tenant_id FROM incidents WHERE id = %s",
        (incident_id,),
    )
    assert row == [(tenants[0],)]
    child = await _rows(
        legacy_db,
        "SELECT tenant_id FROM workflow_state WHERE id = %s",
        (workflow_id,),
    )
    assert child == [(tenants[0],)]


async def test_upgrade_preserves_existing_rows(
    legacy_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = uuid.uuid4()
    incident_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    now = datetime.now(UTC)
    async with await AsyncConnection.connect(legacy_db) as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (tenant, "single"),
        )
        await conn.execute(
            """
            INSERT INTO incidents (
                id, source_system, source_incident_id, external_event_id,
                title, description, service_name, severity, status,
                created_at, updated_at, correlation_id
            ) VALUES (%(id)s, 'mockoon-itsm', 'LEGACY-1', 'legacy-ext',
                      'legacy', 'preserve me', 'payments-api', 'P3', 'NEW',
                      %(created_at)s, %(updated_at)s, %(correlation_id)s)
            """,
            {
                "id": incident_id,
                "created_at": now,
                "updated_at": now,
                "correlation_id": correlation_id,
            },
        )
        await conn.commit()

    before_incident = await _rows(
        legacy_db,
        "SELECT title, status, service_name FROM incidents WHERE id = %s",
        (incident_id,),
    )
    before_count = await _scalar(legacy_db, "SELECT count(*) FROM incidents")
    await _apply(legacy_db, monkeypatch)
    after_incident = await _rows(
        legacy_db,
        "SELECT title, status, service_name FROM incidents WHERE id = %s",
        (incident_id,),
    )
    after_count = await _scalar(legacy_db, "SELECT count(*) FROM incidents")
    assert after_incident == before_incident
    assert after_count == before_count


async def test_injected_failing_migration_is_not_recorded(
    scratch_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from itsm_agent.adapters.persistence import migrations as migrations_module

    tmp = tmp_path / "migrations"
    tmp.mkdir()
    for path in _migration_files():
        (tmp / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "099_injected_failure.sql").write_text(
        "BEGIN; CREATE TABLE migration_safety_boom(id uuid); SELECT 1 / 0; COMMIT;",
        encoding="utf-8",
    )
    monkeypatch.setattr(migrations_module, "MIGRATIONS_DIR", tmp)
    with pytest.raises(Error):
        await apply_migrations(scratch_db)
    assert "099_injected_failure.sql" not in await _schema_migrations(scratch_db)
    assert (
        await _scalar(
            scratch_db,
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relname='migration_safety_boom'",
        )
        == 0
    )
    (tmp / "099_injected_failure.sql").write_text(
        "BEGIN; CREATE TABLE migration_safety_boom(id uuid); COMMIT;"
    )
    await apply_migrations(scratch_db)
    assert "099_injected_failure.sql" in await _schema_migrations(scratch_db)


async def test_single_tenant_backfill_uses_that_tenant(
    legacy_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = uuid.uuid4()
    incident_id = uuid.uuid4()
    await _insert_tenants(legacy_db, (tenant,))
    await _insert_legacy_payload(
        legacy_db,
        incident_id=incident_id,
        correlation_id=uuid.uuid4(),
        external_event_id=None,
    )

    await _apply(legacy_db, monkeypatch)

    assert await _rows(
        legacy_db, "SELECT tenant_id FROM incidents WHERE id = %s", (incident_id,)
    ) == [(tenant,)]


async def test_multiple_tenants_without_match_use_system_tenant(
    legacy_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenants = (uuid.uuid4(), uuid.uuid4())
    incident_id = uuid.uuid4()
    await _insert_tenants(legacy_db, tenants)
    await _insert_legacy_payload(
        legacy_db,
        incident_id=incident_id,
        correlation_id=uuid.uuid4(),
        external_event_id="unmatched-event",
    )

    await _apply(legacy_db, monkeypatch)

    assert await _rows(
        legacy_db, "SELECT tenant_id FROM incidents WHERE id = %s", (incident_id,)
    ) == [(uuid.UUID(SYSTEM_TENANT),)]


async def test_upgrade_adds_tenant_constraints_and_indexes(
    legacy_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _apply(legacy_db, monkeypatch)

    # NOT NULL on every tenant-owned workflow column added by migration 011.
    nullable = await _rows(
        legacy_db,
        """
        SELECT table_name, column_name
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND column_name = 'tenant_id'
           AND table_name = ANY(%s)
           AND is_nullable <> 'NO'
        """,
        (
            [
                "incidents",
                "workflow_state",
                "action_intents",
                "approvals",
                "audit_events",
            ],
        ),
    )
    assert nullable == []

    # Composite tenant-bound foreign keys and uniqueness anchors.
    constraints = {
        row[0]
        for row in await _rows(
            legacy_db,
            """
            SELECT conname FROM pg_constraint
             WHERE conname = ANY(%s)
            """,
            (
                [
                    "fk_workflow_state_tenant_incident",
                    "fk_action_intents_tenant_incident",
                    "fk_approvals_tenant_incident",
                    "fk_audit_events_tenant_incident",
                    "uq_incidents_tenant_id",
                ],
            ),
        )
    }
    assert constraints == {
        "fk_workflow_state_tenant_incident",
        "fk_action_intents_tenant_incident",
        "fk_approvals_tenant_incident",
        "fk_audit_events_tenant_incident",
        "uq_incidents_tenant_id",
    }

    indexes = {
        row[0]
        for row in await _rows(
            legacy_db,
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname = ANY(%s)",
            (
                [
                    "ix_incidents_tenant_status",
                    "ix_workflow_state_tenant",
                    "ix_action_intents_tenant",
                    "ix_approvals_tenant",
                    "ix_audit_events_tenant",
                ],
            ),
        )
    }
    assert indexes == {
        "ix_incidents_tenant_status",
        "ix_workflow_state_tenant",
        "ix_action_intents_tenant",
        "ix_approvals_tenant",
        "ix_audit_events_tenant",
    }


async def test_system_tenant_rows_invisible_to_other_tenant(
    fresh_db: str,
) -> None:
    # The system-legacy tenant owns backfilled pre-tenant rows. A session
    # scoped to another tenant must not see them, even as the runtime role.
    other = uuid.uuid4()
    async with await AsyncConnection.connect(fresh_db) as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, 'rls-other') ON CONFLICT DO NOTHING",
            (other,),
        )
        await conn.execute(
            """
            INSERT INTO incidents (
                id, tenant_id, source_system, source_incident_id, external_event_id,
                title, description, service_name, severity, status,
                created_at, updated_at, correlation_id
            ) VALUES (%s, %s, 'mockoon-itsm', 'SYS-1', NULL, 'system row',
                      'only the system tenant may read this', 'payments-api', 'P2',
                      'NEW', now(), now(), %s)
            """,
            (uuid.uuid4(), uuid.UUID(SYSTEM_TENANT), uuid.uuid4()),
        )
        await conn.execute("SET ROLE itsm_app")
        try:
            await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(other),))
            visible = await (
                await conn.execute(
                    "SELECT count(*) FROM incidents WHERE source_incident_id = 'SYS-1'"
                )
            ).fetchone()
        finally:
            await conn.execute("RESET ROLE")
        await conn.rollback()

    assert visible == (0,)


async def test_tenant_registry_is_readable_and_insertable_but_immutable_at_runtime(
    fresh_db: str,
) -> None:
    """Migration 014 narrows the runtime grants on the tenant registry.

    Verified behaviorally, not only through catalog flags: the runtime role can
    register a tenant idempotently but a rename or delete is rejected by
    PostgreSQL with insufficient privilege.
    """
    tenant_id = uuid.uuid4()
    async with await AsyncConnection.connect(fresh_db) as conn:
        await conn.execute("SET ROLE itsm_app")
        try:
            await conn.execute(
                "INSERT INTO tenants (id, name) VALUES (%s, 'runtime-registered') "
                "ON CONFLICT (id) DO NOTHING",
                (tenant_id,),
            )
            with pytest.raises(Error) as update_error:
                await conn.execute(
                    "UPDATE tenants SET name = 'renamed' WHERE id = %s", (tenant_id,)
                )
            assert getattr(update_error.value, "sqlstate", None) == "42501"
            # A rollback also reverts ``SET ROLE``; re-enter the runtime role.
            await conn.rollback()
            await conn.execute("SET ROLE itsm_app")
            with pytest.raises(Error) as delete_error:
                await conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
            assert getattr(delete_error.value, "sqlstate", None) == "42501"
        finally:
            await conn.rollback()
            await conn.execute("RESET ROLE")
