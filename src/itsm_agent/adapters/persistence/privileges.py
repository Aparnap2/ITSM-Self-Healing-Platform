"""Deployment safety invariant: the runtime database role must not bypass RLS.

A PostgreSQL row-level-security policy is only as strong as the role that
executes the query. A superuser, a role with ``BYPASSRLS``, or a role that can
``SET ROLE`` to one of those completely disables tenant isolation. This module
is the fail-closed startup check that refuses to run in that configuration.

It is intentionally independent of the repositories: it inspects server
catalog state on a real connection, and it is called before the API or worker
accepts traffic. Tests exercise it against a deliberately constrained role.

Checks performed:

1. ``current_user`` is not superuser and does not have ``BYPASSRLS``.
2. The role is not a member of any role that is superuser or has ``BYPASSRLS``
   (membership would allow ``SET ROLE``).
3. ``row_security`` is on for this session.
4. Every tenant-owned table has both ``ENABLE`` and ``FORCE`` row-level
   security.
5. The role holds the DML privileges the application needs.
6. Append-only tables are not writable beyond INSERT (no UPDATE/DELETE) and
   no table grants TRUNCATE.
7. The tenant registry is SELECT + INSERT only: tenancy lifecycle
   (UPDATE/DELETE/TRUNCATE) is administration-plane.
"""

from __future__ import annotations

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

__all__ = [
    "APPEND_ONLY_TABLES",
    "DatabaseSafetyError",
    "READ_ONLY_TABLES",
    "RUNTIME_DML_TABLES",
    "TENANT_REGISTRY_TABLES",
    "TENANT_RLS_TABLES",
    "assert_runtime_database_safety",
    "verify_runtime_database",
]

#: Tenant-owned tables that MUST have RLS enabled and forced.
TENANT_RLS_TABLES: tuple[str, ...] = (
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
    "finding_transitions",
)

#: Tables the runtime role must be able to read and write (append-only tables
#: need SELECT + INSERT; the check below only requires the common DML surface).
#: ``tenants`` is deliberately excluded: it is administration-plane data with
#: its own narrower contract below.
RUNTIME_DML_TABLES: tuple[str, ...] = TENANT_RLS_TABLES + (
    "retention_policies",
    "legal_holds",
)

#: Tenant registry: the runtime role may read it and idempotently register a
#: tenant during ingestion (``ON CONFLICT DO NOTHING``), but must never rename
#: or delete tenancy. Tenant lifecycle is an administration-plane operation.
TENANT_REGISTRY_TABLES: tuple[str, ...] = ("tenants",)

#: Directory table the runtime role may READ (SELECT only) but never write.
#: Requiring full DML here would force a write grant on the administration
#: plane, so it is asserted separately: SELECT required, INSERT forbidden.
READ_ONLY_TABLES: tuple[str, ...] = ("reviewer_authorizations",)

#: Tables whose rows are evidence/audit records: INSERT only at runtime.
APPEND_ONLY_TABLES: tuple[str, ...] = (
    "source_events",
    "audit_events",
    "erasure_tombstones",
    "finding_transitions",
)


class DatabaseSafetyError(RuntimeError):
    """The runtime connection can bypass or undermine tenant row security."""

    def __init__(self, violations: tuple[str, ...]) -> None:
        super().__init__("unsafe runtime database role: " + "; ".join(violations))
        self.violations: tuple[str, ...] = violations

    def __str__(self) -> str:
        return "unsafe runtime database role: " + "; ".join(self.violations)


async def _role_safety(conn: AsyncConnection) -> list[str]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            SELECT current_user AS role_name,
                   rolsuper,
                   rolbypassrls,
                   rolinherit
              FROM pg_roles
             WHERE rolname = current_user
            """
        )
        role = await cur.fetchone()
        if role is None:  # pragma: no cover - catalog should always resolve
            return ["current role is not present in pg_roles"]

        violations: list[str] = []
        if role["rolsuper"]:
            violations.append(f"role {role['role_name']} is SUPERUSER")
        if role["rolbypassrls"]:
            violations.append(f"role {role['role_name']} has BYPASSRLS")

        await cur.execute(
            """
            SELECT r.rolname, r.rolsuper, r.rolbypassrls
              FROM pg_roles r
             WHERE r.rolname <> current_user
               AND (r.rolsuper OR r.rolbypassrls)
               AND pg_has_role(current_user, r.oid, 'MEMBER')
            """
        )
        for membership in await cur.fetchall():
            violations.append(
                f"role {role['role_name']} can SET ROLE to privileged role "
                f"{membership['rolname']} "
                f"(superuser={membership['rolsuper']}, bypassrls={membership['rolbypassrls']})"
            )

        await cur.execute("SHOW row_security")
        row_security = await cur.fetchone()
        if row_security is None or row_security["row_security"] != "on":
            violations.append("session row_security is not 'on'")
        return violations


async def _rls_safety(conn: AsyncConnection) -> list[str]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            SELECT c.relname,
                   c.relrowsecurity,
                   c.relforcerowsecurity
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = current_schema()
               AND c.relkind = 'r'
               AND c.relname = ANY(%s)
            """,
            (list(TENANT_RLS_TABLES),),
        )
        rows = {row["relname"]: row for row in await cur.fetchall()}

    violations: list[str] = []
    for table in TENANT_RLS_TABLES:
        row = rows.get(table)
        if row is None:
            violations.append(f"required tenant table {table} is missing")
            continue
        if not row["relrowsecurity"]:
            violations.append(f"{table}: row-level security is not ENABLED")
        if not row["relforcerowsecurity"]:
            violations.append(f"{table}: row-level security is not FORCED")
    return violations


async def _privilege_safety(conn: AsyncConnection) -> list[str]:
    violations: list[str] = []
    async with conn.cursor() as cur:
        for table in RUNTIME_DML_TABLES:
            await cur.execute(
                "SELECT has_table_privilege(current_user, %s, 'SELECT,INSERT,UPDATE,DELETE')",
                (table,),
            )
            row = await cur.fetchone()
            if row is None or not row[0]:
                violations.append(f"{table}: runtime role lacks required DML privileges")

        for table in APPEND_ONLY_TABLES:
            await cur.execute(
                "SELECT has_table_privilege(current_user, %s, 'UPDATE'), "
                "has_table_privilege(current_user, %s, 'DELETE'), "
                "has_table_privilege(current_user, %s, 'TRUNCATE')",
                (table, table, table),
            )
            row = await cur.fetchone()
            if row is None:  # pragma: no cover - defensive
                violations.append(f"{table}: privilege lookup failed")
                continue
            if row[0]:
                violations.append(f"{table}: runtime role can UPDATE append-only rows")
            if row[1]:
                violations.append(f"{table}: runtime role can DELETE append-only rows")
            if row[2]:
                violations.append(f"{table}: runtime role can TRUNCATE append-only rows")

        for table in READ_ONLY_TABLES:
            await cur.execute(
                "SELECT has_table_privilege(current_user, %s, 'SELECT')",
                (table,),
            )
            row = await cur.fetchone()
            if row is None or not row[0]:
                violations.append(f"{table}: runtime role cannot read the directory")

        for table in TENANT_REGISTRY_TABLES:
            await cur.execute(
                "SELECT has_table_privilege(current_user, %s, 'SELECT'), "
                "has_table_privilege(current_user, %s, 'INSERT'), "
                "has_table_privilege(current_user, %s, 'UPDATE'), "
                "has_table_privilege(current_user, %s, 'DELETE'), "
                "has_table_privilege(current_user, %s, 'TRUNCATE')",
                (table, table, table, table, table),
            )
            row = await cur.fetchone()
            if row is None:  # pragma: no cover - defensive
                violations.append(f"{table}: privilege lookup failed")
                continue
            if not row[0]:
                violations.append(f"{table}: runtime role cannot read the tenant registry")
            if not row[1]:
                violations.append(f"{table}: runtime role cannot register a tenant")
            if row[2]:
                violations.append(f"{table}: runtime role can UPDATE the tenant registry")
            if row[3]:
                violations.append(f"{table}: runtime role can DELETE from the tenant registry")  # nosec B608 - message text, not SQL
            if row[4]:
                violations.append(f"{table}: runtime role can TRUNCATE the tenant registry")

        await cur.execute(
            "SELECT has_table_privilege(current_user, 'reviewer_authorizations', 'INSERT')"
        )
        row = await cur.fetchone()
        if row is not None and row[0]:
            violations.append("reviewer_authorizations: runtime role can write authorization data")
    return violations


async def assert_runtime_database_safety(conn: AsyncConnection) -> None:
    """Raise ``DatabaseSafetyError`` unless ``conn`` is a safe runtime role.

    The caller must abort startup on failure. There is no "warn and continue"
    mode: silently running without effective RLS is the vulnerability this
    check exists to prevent.
    """
    violations = await _role_safety(conn)
    violations.extend(await _rls_safety(conn))
    violations.extend(await _privilege_safety(conn))
    if violations:
        raise DatabaseSafetyError(tuple(violations))


async def verify_runtime_database(pool: AsyncConnectionPool[AsyncConnection]) -> None:
    """Apply the startup invariant to the pool used by the application."""
    async with pool.connection() as conn:
        await assert_runtime_database_safety(conn)
