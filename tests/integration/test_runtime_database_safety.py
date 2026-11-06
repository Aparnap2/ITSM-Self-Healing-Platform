"""Integration: runtime database-role safety (Slice 1 of the P0 sequence).

These tests connect as *real* PostgreSQL roles — never the suite superuser —
and assert that ``assert_runtime_database_safety`` fails closed whenever the
role could bypass row-level security. They also prove the
``reviewer_authorizations`` privilege contract: the runtime role can execute
the directory read the OIDC authenticator needs, cannot write, and cannot read
another issuer's authorizations.

Roles are created per test and dropped in teardown (``DROP OWNED BY`` so granted
privileges cannot leak between tests). This requires the maintenance connection
to be a superuser, which is true for the project's local and CI Postgres.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from typing import Protocol

import pytest
from psycopg import AsyncConnection, errors, sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.privileges import (
    DatabaseSafetyError,
    assert_runtime_database_safety,
    verify_runtime_database,
)
from itsm_agent.api.oidc import PsycopgReviewerDirectory

pytestmark = [pytest.mark.integration, pytest.mark.security]


class RuntimeRoleFactory(Protocol):
    async def __call__(
        self,
        *,
        superuser: bool = False,
        bypassrls: bool = False,
        tables: tuple[str, ...] = (),
        member_of: str | None = None,
    ) -> str: ...


RLS_TABLES: tuple[str, ...] = (
    "source_events",
    "source_checkpoints",
    "identity_mappings",
    "access_facts",
    "findings",
    "evidence_references",
    "coverage_status",
    "review_decisions",
    "processing_records",
    "event_inbox",
    "outbox",
    "incidents",
    "workflow_state",
    "action_intents",
    "approvals",
    "audit_events",
    "erasure_requests",
    "erasure_tombstones",
    "retention_policies",
    "legal_holds",
)

#: Every table the runtime role must be able to DML, plus the SELECT-only
#: directory table. Granting against this full list is what the production
#: ``itsm_app`` role receives from migration 010.
TENANT_REGISTRY_TABLES: tuple[str, ...] = ("tenants",)
DML_TABLES: tuple[str, ...] = RLS_TABLES + TENANT_REGISTRY_TABLES
APPEND_ONLY_TABLES: tuple[str, ...] = ("source_events", "audit_events", "erasure_tombstones")
READ_ONLY_TABLES: tuple[str, ...] = ("reviewer_authorizations",)

ISSUER = "https://issuer.example.test"


def _role_dsn(base_dsn: str, role: str, password: str) -> str:
    parts = {k: str(v) for k, v in conninfo_to_dict(base_dsn).items() if v is not None}
    parts.update({"user": role, "password": password, "dbname": parts.get("dbname", "itsm_test")})
    return make_conninfo("", **parts)


async def _admin(pg_dsn: str) -> AsyncConnection:
    return await AsyncConnection.connect(pg_dsn, autocommit=True)


async def _create_role(
    admin: AsyncConnection,
    role: str,
    password: str,
    *,
    superuser: bool = False,
    bypassrls: bool = False,
) -> None:
    await admin.execute(
        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} {} {}").format(
            sql.Identifier(role),
            sql.Literal(password),
            sql.SQL("SUPERUSER" if superuser else "NOSUPERUSER"),
            sql.SQL("BYPASSRLS" if bypassrls else "NOBYPASSRLS"),
        )
    )
    await admin.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))


async def _grant_dml(admin: AsyncConnection, role: str, tables: tuple[str, ...]) -> None:
    await admin.execute(
        sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO {}").format(
            sql.SQL(", ").join(sql.Identifier(table) for table in tables),
            sql.Identifier(role),
        )
    )
    for table in APPEND_ONLY_TABLES:
        await admin.execute(
            sql.SQL("REVOKE UPDATE, DELETE ON {} FROM {}").format(
                sql.Identifier(table), sql.Identifier(role)
            )
        )
    for table in TENANT_REGISTRY_TABLES:
        await admin.execute(
            sql.SQL("REVOKE UPDATE, DELETE, TRUNCATE ON {} FROM {}").format(
                sql.Identifier(table), sql.Identifier(role)
            )
        )


@pytest.fixture
async def role_factory(pg_dsn: str) -> AsyncIterator[RuntimeRoleFactory]:
    """Create and tear down throwaway PostgreSQL roles."""
    created: list[str] = []
    admin = await _admin(pg_dsn)

    def _new_role(prefix: str) -> tuple[str, str]:
        role = f"itsm_safe_{prefix}_{secrets.token_hex(4)}"
        password = secrets.token_urlsafe(24)
        created.append(role)
        return role, password

    async def make(
        *,
        superuser: bool = False,
        bypassrls: bool = False,
        tables: tuple[str, ...] = (),
        member_of: str | None = None,
    ) -> str:
        role, password = _new_role("role")
        await _create_role(admin, role, password, superuser=superuser, bypassrls=bypassrls)
        if tables:
            await _grant_dml(admin, role, tables)
        for table in READ_ONLY_TABLES:
            await admin.execute(
                sql.SQL("GRANT SELECT ON {} TO {}").format(
                    sql.Identifier(table), sql.Identifier(role)
                )
            )
        if member_of is not None:
            await admin.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(member_of), sql.Identifier(role))
            )
        return _role_dsn(pg_dsn, role, password)

    yield make
    for role in created:
        await admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        await admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    await admin.close()


async def _connect(dsn: str) -> AsyncConnection:
    return await AsyncConnection.connect(dsn)


async def _as_role_assert(role_dsn: str) -> None:
    conn = await _connect(role_dsn)
    try:
        await assert_runtime_database_safety(conn)
    finally:
        await conn.close()


async def test_safe_constrained_role_passes(role_factory: RuntimeRoleFactory, pg_dsn: str) -> None:
    """A least-privileged role with every required grant is accepted."""
    dsn = await role_factory(tables=DML_TABLES)
    await _as_role_assert(dsn)


async def test_superuser_is_rejected(role_factory: RuntimeRoleFactory) -> None:
    dsn = await role_factory(superuser=True)
    with pytest.raises(DatabaseSafetyError, match="SUPERUSER"):
        await _as_role_assert(dsn)


async def test_bypassrls_is_rejected(role_factory: RuntimeRoleFactory) -> None:
    dsn = await role_factory(bypassrls=True)
    with pytest.raises(DatabaseSafetyError, match="BYPASSRLS"):
        await _as_role_assert(dsn)


async def test_privileged_role_membership_is_rejected(
    role_factory: RuntimeRoleFactory, pg_dsn: str
) -> None:
    """Membership in a BYPASSRLS role (SET ROLE) must fail closed."""
    admin = await _admin(pg_dsn)
    try:
        privileged = f"itsm_priv_{secrets.token_hex(4)}"
        await admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER BYPASSRLS").format(
                sql.Identifier(privileged), sql.Literal(secrets.token_urlsafe(16))
            )
        )
        await admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(privileged))
        )
        dsn = await role_factory(member_of=privileged)
        with pytest.raises(DatabaseSafetyError, match="SET ROLE"):
            await _as_role_assert(dsn)
    finally:
        await admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(privileged)))
        await admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(privileged)))
        await admin.close()


async def test_row_security_off_is_rejected(role_factory: RuntimeRoleFactory) -> None:
    dsn = await role_factory(tables=DML_TABLES)
    conn = await _connect(dsn)
    try:
        await conn.execute("SET row_security = off")
        with pytest.raises(DatabaseSafetyError, match="row_security"):
            await assert_runtime_database_safety(conn)
    finally:
        await conn.close()


async def test_missing_dml_grant_is_rejected(role_factory: RuntimeRoleFactory) -> None:
    """No grants at all => the assertion must not pass."""
    dsn = await role_factory()
    with pytest.raises(DatabaseSafetyError, match="lacks required DML"):
        await _as_role_assert(dsn)


async def test_rls_not_enabled_is_rejected(role_factory: RuntimeRoleFactory, pg_dsn: str) -> None:
    admin = await _admin(pg_dsn)
    try:
        await admin.execute("ALTER TABLE findings DISABLE ROW LEVEL SECURITY")
    finally:
        await admin.close()
    dsn = await role_factory(tables=DML_TABLES)
    try:
        with pytest.raises(DatabaseSafetyError, match="row-level security is not ENABLED"):
            await _as_role_assert(dsn)
    finally:
        admin = await _admin(pg_dsn)
        try:
            await admin.execute("ALTER TABLE findings ENABLE ROW LEVEL SECURITY")
            await admin.execute("ALTER TABLE findings FORCE ROW LEVEL SECURITY")
        finally:
            await admin.close()


async def test_rls_not_forced_is_rejected(role_factory: RuntimeRoleFactory, pg_dsn: str) -> None:
    admin = await _admin(pg_dsn)
    try:
        await admin.execute(
            "DO $$ BEGIN"
            " IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'itsm') THEN"
            "  ALTER TABLE findings NO FORCE ROW LEVEL SECURITY;"
            " END IF; END $$"
        )
    finally:
        await admin.close()
    dsn = await role_factory(tables=DML_TABLES)
    try:
        with pytest.raises(DatabaseSafetyError, match="row-level security is not FORCED"):
            await _as_role_assert(dsn)
    finally:
        admin = await _admin(pg_dsn)
        try:
            await admin.execute("ALTER TABLE findings FORCE ROW LEVEL SECURITY")
        finally:
            await admin.close()


async def test_append_only_write_grant_is_rejected(
    role_factory: RuntimeRoleFactory, pg_dsn: str
) -> None:
    """A runtime role that can UPDATE append-only rows must fail closed."""
    dsn = await role_factory(tables=DML_TABLES)
    admin = await _admin(pg_dsn)
    try:
        await admin.execute(
            sql.SQL("GRANT UPDATE ON {} TO {}").format(
                sql.Identifier("audit_events"), sql.Identifier(_user_of(dsn))
            )
        )
        with pytest.raises(DatabaseSafetyError, match="UPDATE append-only"):
            await _as_role_assert(dsn)
    finally:
        await admin.close()


def _user_of(dsn: str) -> str:
    return str(conninfo_to_dict(dsn)["user"])


async def test_verify_runtime_database_uses_the_pool(role_factory: RuntimeRoleFactory) -> None:
    """`verify_runtime_database` must open a pooled connection and fail closed."""
    dsn = await role_factory(superuser=True)
    pool = create_pool(PersistenceConfig(dsn=dsn))
    await pool.open()
    try:
        with pytest.raises(DatabaseSafetyError):
            await verify_runtime_database(pool)
    finally:
        await pool.close()


async def test_reviewer_directory_read_succeeds_as_runtime_role(
    role_factory: RuntimeRoleFactory, pg_dsn: str
) -> None:
    """The real application operation: the OIDC directory read must work.

    The runtime role (SELECT only on the directory table) must resolve a
    seeded active authorization through ``PsycopgReviewerDirectory``.
    """
    admin = await _admin(pg_dsn)
    try:
        await admin.execute("DELETE FROM reviewer_authorizations")
        tenant_id = uuid.uuid4()
        await admin.execute("INSERT INTO tenants (id, name) VALUES (%s, 'slice1')", (tenant_id,))
        await admin.execute(
            """
            INSERT INTO reviewer_authorizations
                (issuer, subject, tenant_ids, roles, active, authorization_version)
            VALUES (%s, 'reviewer-1', %s, %s, TRUE, 'v1')
            """,
            (ISSUER, [str(tenant_id)], ["reviewer"]),
        )
    finally:
        await admin.close()

    role_dsn = await role_factory(tables=DML_TABLES)
    pool = create_pool(PersistenceConfig(dsn=role_dsn))
    await pool.open()
    try:
        resolved = await PsycopgReviewerDirectory(pool).resolve(issuer=ISSUER, subject="reviewer-1")
        assert resolved is not None
        assert resolved.active is True
        assert resolved.tenant_ids == (tenant_id,)
        assert resolved.roles == ("reviewer",)
    finally:
        await pool.close()
        admin = await _admin(pg_dsn)
        try:
            await admin.execute(
                "DELETE FROM reviewer_authorizations WHERE issuer = %s",
                (ISSUER,),
            )
            await admin.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        finally:
            await admin.close()


async def test_reviewer_directory_write_is_impossible_as_runtime_role(
    role_factory: RuntimeRoleFactory,
) -> None:
    """The runtime role must not be able to grant itself an authorization."""
    role_dsn = await role_factory(tables=DML_TABLES)
    conn = await _connect(role_dsn)
    try:
        with pytest.raises(errors.InsufficientPrivilege):
            await conn.execute(
                """
                INSERT INTO reviewer_authorizations
                    (issuer, subject, tenant_ids, roles, active, authorization_version)
                VALUES ('https://evil.example.test', 'attacker',
                        ARRAY['00000000-0000-0000-0000-000000000001'::uuid],
                        ARRAY['admin'], TRUE, 'v1')
                """
            )
    finally:
        await conn.close()


async def test_reviewer_directory_is_not_tenant_scoped_but_issuer_scoped(
    role_factory: RuntimeRoleFactory, pg_dsn: str
) -> None:
    """A runtime role reading another issuer's row must get nothing.

    Proves the fix does not silently widen access across reviewers: the lookup
    is keyed on ``(issuer, subject)``, so a different issuer sees no row even
    with SELECT on the table.
    """
    admin = await _admin(pg_dsn)
    try:
        await admin.execute("DELETE FROM reviewer_authorizations")
        tenant_id = uuid.uuid4()
        await admin.execute("INSERT INTO tenants (id, name) VALUES (%s, 'slice1-b')", (tenant_id,))
        await admin.execute(
            """
            INSERT INTO reviewer_authorizations
                (issuer, subject, tenant_ids, roles, active, authorization_version)
            VALUES (%s, 'reviewer-1', %s, %s, TRUE, 'v1')
            """,
            (ISSUER, [str(tenant_id)], ["reviewer"]),
        )
    finally:
        await admin.close()

    role_dsn = await role_factory(tables=DML_TABLES)
    pool = create_pool(PersistenceConfig(dsn=role_dsn))
    await pool.open()
    try:
        missing = await PsycopgReviewerDirectory(pool).resolve(
            issuer="https://other.example.test", subject="reviewer-1"
        )
        assert missing is None
        found = await PsycopgReviewerDirectory(pool).resolve(issuer=ISSUER, subject="reviewer-1")
        assert found is not None
    finally:
        await pool.close()
        admin = await _admin(pg_dsn)
        try:
            await admin.execute(
                "DELETE FROM reviewer_authorizations WHERE issuer = %s",
                (ISSUER,),
            )
            await admin.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        finally:
            await admin.close()


# ---------------------------------------------------------------------------
# Tenant registry: SELECT + INSERT only, never UPDATE/DELETE/TRUNCATE
# ---------------------------------------------------------------------------


def _role_name(dsn: str) -> str:
    return str(conninfo_to_dict(dsn)["user"])


@pytest.mark.parametrize("privilege", ["UPDATE", "DELETE", "TRUNCATE"])
async def test_tenant_registry_write_grant_is_rejected(
    role_factory: RuntimeRoleFactory,
    pg_dsn: str,
    privilege: str,
) -> None:
    """Tenancy lifecycle is administration-plane; runtime must not hold it."""
    dsn = await role_factory(tables=DML_TABLES)
    admin = await _admin(pg_dsn)
    try:
        await admin.execute(
            sql.SQL("GRANT {} ON tenants TO {}").format(
                sql.SQL(privilege), sql.Identifier(_role_name(dsn))
            )
        )
    finally:
        await admin.close()

    with pytest.raises(DatabaseSafetyError, match="tenant registry"):
        await _as_role_assert(dsn)


async def test_tenant_registry_requires_insert_for_idempotent_registration(
    role_factory: RuntimeRoleFactory,
    pg_dsn: str,
) -> None:
    dsn = await role_factory(tables=DML_TABLES)
    admin = await _admin(pg_dsn)
    try:
        await admin.execute(
            sql.SQL("REVOKE INSERT ON tenants FROM {}").format(sql.Identifier(_role_name(dsn)))
        )
    finally:
        await admin.close()

    with pytest.raises(DatabaseSafetyError, match="cannot register a tenant"):
        await _as_role_assert(dsn)


async def test_runtime_can_register_but_cannot_mutate_confirmed_tenants(
    role_factory: RuntimeRoleFactory,
    pg_dsn: str,
) -> None:
    """Behavioural proof, not just a catalog assertion."""
    dsn = await role_factory(tables=DML_TABLES)
    tenant_id = uuid.uuid4()
    conn = await _connect(dsn)
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            (tenant_id, "original"),
        )
        # A second idempotent registration must not change the stored name.
        await conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            (tenant_id, "attacker-renamed"),
        )
        row = await (
            await conn.execute("SELECT name FROM tenants WHERE id = %s", (tenant_id,))
        ).fetchone()
        assert row is not None and row[0] == "original"

        with pytest.raises(errors.InsufficientPrivilege):
            await conn.execute("UPDATE tenants SET name = 'renamed' WHERE id = %s", (tenant_id,))
        await conn.rollback()
        with pytest.raises(errors.InsufficientPrivilege):
            await conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
    finally:
        await conn.close()
        admin = await _admin(pg_dsn)
        try:
            await admin.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        finally:
            await admin.close()
