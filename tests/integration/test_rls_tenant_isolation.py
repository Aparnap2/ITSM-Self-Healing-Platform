"""Integration: PostgreSQL RLS tenant isolation with a constrained DB role.

These tests do not use the suite's superuser connection to assert isolation.
They create a dedicated ``NOBYPASSRLS`` login role, connect as it, and verify
that the database itself — not the query filter — enforces tenant boundaries:

- no tenant context  -> zero rows (fail closed);
- tenant A context   -> only tenant A rows;
- cross-tenant write -> rejected by the WITH CHECK policy;
- pooled connections -> context does not survive a transaction;
- repositories       -> tenant-safe even when they reuse a pooled connection;
- workers            -> cannot process an event under the wrong tenant context.

The role is created per test run and dropped in teardown. This requires the
migration/maintenance connection to be a superuser, which is true for the
project's local and CI Postgres service.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID

import pytest
from psycopg import AsyncConnection, errors, sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.messaging.outbox_relay import OutboxRelay
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.privileges import TENANT_RLS_TABLES
from itsm_agent.adapters.persistence.repositories import (
    PsycopgFindingRepository,
    PsycopgOutboxRepository,
    PsycopgProcessingRecordRepository,
    PsycopgTenantRepository,
)
from itsm_agent.adapters.persistence.tenant import tenant_transaction
from itsm_agent.application.audit_consumer import process_source_event
from itsm_agent.collectors.aws.cloudtrail import normalize_record
from itsm_agent.domain.models import Finding, Severity

pytestmark = pytest.mark.integration

TENANT_TABLES = TENANT_RLS_TABLES


def _role_dsn(base_dsn: str, role: str, password: str) -> str:
    parts = {k: str(v) for k, v in conninfo_to_dict(base_dsn).items() if v is not None}
    parts.update({"user": role, "password": password, "dbname": parts.get("dbname", "itsm_test")})
    return make_conninfo("", **parts)


def _scalar(row: tuple[object, ...] | None) -> object:
    assert row is not None
    return row[0]


async def _admin(pg_dsn: str) -> AsyncConnection:
    return await AsyncConnection.connect(pg_dsn, autocommit=True)


@pytest.fixture
async def constrained_role(pg_dsn: str) -> AsyncIterator[tuple[str, str]]:
    role = f"itsm_rls_{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(24)
    admin = await _admin(pg_dsn)
    created = False
    try:
        await admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        created = True
        await admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role))
        )
        await admin.execute(
            sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO {}").format(
                sql.SQL(", ").join(sql.Identifier(table) for table in TENANT_TABLES),
                sql.Identifier(role),
            )
        )
        yield role, _role_dsn(pg_dsn, role, password)
    finally:
        if created:
            await admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            await admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        await admin.close()


async def _seed_finding(pool: AsyncConnectionPool[AsyncConnection], tenant: UUID) -> UUID:
    repo = PsycopgFindingRepository(pool)
    finding = Finding(
        id=uuid.uuid4(),
        tenant_id=tenant,
        finding_type="PRIVILEGE_ESCALATION",
        severity=Severity.P2,
        status="OPEN",
        title=f"finding-{uuid.uuid4().hex}",
        description="detected by deterministic rule",
        detected_at=datetime.now(UTC),
        rule_version="rule-v1",
        risk_score=60,
        outcome="VIOLATION",
    )
    stored = await repo.upsert(finding)
    return stored.id


@pytest.fixture
async def admin_pool(pg_dsn: str) -> AsyncIterator[AsyncConnectionPool[AsyncConnection]]:
    pool = create_pool(PersistenceConfig(dsn=pg_dsn, min_size=1, max_size=2))
    await pool.open()
    try:
        async with pool.connection() as conn:
            await conn.execute("TRUNCATE findings, review_decisions, outbox CASCADE")
        yield pool
    finally:
        await pool.close()


async def test_no_context_sees_no_rows(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    _, dsn = constrained_role
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    await _seed_finding(admin_pool, t1)
    await _seed_finding(admin_pool, t2)

    async with await AsyncConnection.connect(dsn) as conn:
        rows = await (await conn.execute("SELECT id FROM findings")).fetchall()
    assert rows == []


async def test_tenant_context_sees_only_own_rows(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    _, dsn = constrained_role
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    a = await _seed_finding(admin_pool, t1)
    await _seed_finding(admin_pool, t2)

    async with await AsyncConnection.connect(dsn) as conn, conn.transaction():
        await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(t1),))
        rows = await (await conn.execute("SELECT id FROM findings")).fetchall()
    assert [row[0] for row in rows] == [a]


async def test_cross_tenant_insert_is_rejected(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    _, dsn = constrained_role
    t1, t2 = uuid.uuid4(), uuid.uuid4()

    with pytest.raises(errors.InsufficientPrivilege):
        async with await AsyncConnection.connect(dsn) as conn, conn.transaction():
            await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(t1),))
            await conn.execute(
                """
                INSERT INTO findings (
                    id, tenant_id, finding_type, severity, status, title, description,
                    detected_at, rule_version, risk_score, outcome
                ) VALUES (%s, %s, 'T', 'P2', 'OPEN', 'x', 'd', now(), 'v1', 1, 'VIOLATION')
                """,
                (uuid.uuid4(), t2),
            )


async def test_transaction_local_context_does_not_leak_on_a_pooled_connection(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    _, dsn = constrained_role
    tenant = uuid.uuid4()
    await _seed_finding(admin_pool, tenant)

    # min_size=max_size=1 guarantees the second transaction reuses the same socket.
    pool = create_pool(PersistenceConfig(dsn=dsn, min_size=1, max_size=1))
    await pool.open()
    try:
        async with tenant_transaction(pool, tenant) as conn:
            inside = _scalar(await (await conn.execute("SELECT count(*) FROM findings")).fetchone())
        async with pool.connection() as conn:
            leaked = _scalar(await (await conn.execute("SELECT count(*) FROM findings")).fetchone())
    finally:
        await pool.close()

    assert inside == 1
    assert leaked == 0, "tenant context survived the transaction on a reused connection"


async def test_direct_repository_calls_are_tenant_safe(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    _, dsn = constrained_role
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    a = await _seed_finding(admin_pool, t1)
    b = await _seed_finding(admin_pool, t2)

    pool = create_pool(PersistenceConfig(dsn=dsn, min_size=1, max_size=1))
    await pool.open()
    try:
        repo = PsycopgFindingRepository(pool)
        mine = await repo.list_for_tenant(t1)
        theirs = await repo.list_for_tenant(t2)
        cross = await repo.get(t1, b)
    finally:
        await pool.close()

    assert [f.id for f in mine] == [a]
    assert [f.id for f in theirs] == [b]
    assert cross is None


async def test_outbox_rows_are_tenant_isolated(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    _, dsn = constrained_role
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    outbox = PsycopgOutboxRepository(admin_pool)
    for tenant in (t1, t2):
        await outbox.append(
            event_type="SourceEventIngested",
            aggregate_id=uuid.uuid4(),
            payload={"tenant": str(tenant)},
            tenant_id=tenant,
        )

    async with await AsyncConnection.connect(dsn) as conn, conn.transaction():
        await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(t1),))
        rows = await (await conn.execute("SELECT tenant_id FROM outbox")).fetchall()
    assert [row[0] for row in rows] == [t1]


async def test_worker_cannot_process_under_the_wrong_tenant_context(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    """A tampered message tenant cannot unlock the canonical event: the RLS
    scoped read returns nothing and processing fails closed."""
    _, dsn = constrained_role
    owner, intruder = uuid.uuid4(), uuid.uuid4()
    async with admin_pool.connection() as conn:
        await conn.execute("INSERT INTO tenants (id) VALUES (%s) ON CONFLICT DO NOTHING", (owner,))
    record = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA",
            "arn": "arn:aws:iam::123:user/alice",
            "accountId": "123",
            "userName": "alice",
        },
        "eventTime": "2026-01-01T12:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/Admin"},
        "requestID": "req-1",
        "eventID": f"evt-{uuid.uuid4().hex}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    event = normalize_record(record, owner)

    # Ingest as the system (admin) connection, which owns the RLS bypass.
    async with admin_pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO source_events (
                id, tenant_id, source, idempotency_key, canonical_schema_version,
                event_type, event_category, event_time, observed_at, action, payload_hash
            ) VALUES (%s, %s, %s, %s, '1.0', %s, 'access', now(), now(), %s, %s)
            """,
            (
                event.event_id,
                owner,
                event.source,
                event.idempotency_key,
                event.event_type,
                event.action,
                event.payload_hash,
            ),
        )

    pool = create_pool(PersistenceConfig(dsn=dsn, min_size=1, max_size=2))
    await pool.open()
    try:
        tampered = event.model_copy(update={"tenant_id": intruder})
        with pytest.raises(ValueError):
            await process_source_event(
                event=tampered,
                pool=pool,
                findings_repo=PsycopgFindingRepository(pool),
                processing_repo=PsycopgProcessingRecordRepository(pool),
                covered_sources={"cloudtrail"},
                clock_now=lambda: datetime.now(UTC),
            )
        async with admin_pool.connection() as conn:
            count = _scalar(
                await (
                    await conn.execute(
                        "SELECT count(*) FROM processing_records WHERE tenant_id = %s",
                        (intruder,),
                    )
                ).fetchone()
            )
    finally:
        await pool.close()

    assert count == 0


class _RecordingPublisher:
    """Minimal JetStreamPublisher stand-in; no network."""

    def __init__(self) -> None:
        self.published: list[tuple[str, bytes]] = []

    async def publish(self, subject: str, payload: bytes) -> None:
        self.published.append((subject, payload))


async def test_relay_claims_publishes_and_marks_within_one_tenant(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    """The relay's claim AND acknowledge must both carry the tenant context.

    A tenant-scoped UPDATE without context would silently affect zero rows,
    leaving every event leased and re-delivered forever.
    """
    _, dsn = constrained_role
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    outbox = PsycopgOutboxRepository(admin_pool)
    event_a = await outbox.append(
        event_type="SourceEventIngested",
        aggregate_id=uuid.uuid4(),
        payload={"tenant": str(tenant_a)},
        tenant_id=tenant_a,
    )
    event_b = await outbox.append(
        event_type="SourceEventIngested",
        aggregate_id=uuid.uuid4(),
        payload={"tenant": str(tenant_b)},
        tenant_id=tenant_b,
    )

    pool = create_pool(PersistenceConfig(dsn=dsn, min_size=1, max_size=2))
    await pool.open()
    publisher = _RecordingPublisher()
    try:
        relay = OutboxRelay(
            PsycopgOutboxRepository(pool),
            publisher,  # type: ignore[arg-type]
            tenants=PsycopgTenantRepository(pool),
            backoff_seconds=0.0,
        )
        assert await relay.relay_once(tenant_a) == 1
    finally:
        await pool.close()

    assert len(publisher.published) == 1
    async with admin_pool.connection() as conn:
        rows = await (await conn.execute("SELECT id, status FROM outbox ORDER BY id")).fetchall()
    statuses = {row[0]: row[1] for row in rows}
    assert statuses[event_a.id] == "published"
    assert statuses[event_b.id] == "pending"


async def test_transport_tables_keep_legacy_rows_out_of_tenant_sessions(
    constrained_role: tuple[str, str], admin_pool: AsyncConnectionPool[AsyncConnection]
) -> None:
    """Legacy NULL-tenant transport rows are visible only without a tenant context."""
    _, dsn = constrained_role
    tenant = uuid.uuid4()
    tenant_row = await PsycopgOutboxRepository(admin_pool).append(
        event_type="SourceEventIngested",
        aggregate_id=uuid.uuid4(),
        payload={"tenant": str(tenant)},
        tenant_id=tenant,
    )
    async with admin_pool.connection() as conn:
        legacy_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO outbox (id, tenant_id, event_type, aggregate_id, payload)
            VALUES (%s, NULL, 'IncidentCreated', %s, '{}'::jsonb)
            """,
            (legacy_id, uuid.uuid4()),
        )

    async with await AsyncConnection.connect(dsn) as conn, conn.transaction():
        legacy_visible = await (await conn.execute("SELECT id FROM outbox")).fetchall()

    async with await AsyncConnection.connect(dsn) as conn, conn.transaction():
        await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(tenant),))
        tenant_visible = await (await conn.execute("SELECT id FROM outbox")).fetchall()

    assert {row[0] for row in legacy_visible} == {legacy_id}
    assert {row[0] for row in tenant_visible} == {tenant_row.id}


async def test_tenant_session_cannot_write_a_tenant_less_transport_row(
    constrained_role: tuple[str, str],
) -> None:
    _, dsn = constrained_role
    with pytest.raises(errors.InsufficientPrivilege):
        async with await AsyncConnection.connect(dsn) as conn, conn.transaction():
            await conn.execute(
                "SELECT set_config('itsm.tenant_id', %s, true)", (str(uuid.uuid4()),)
            )
            await conn.execute(
                """
                INSERT INTO outbox (id, tenant_id, event_type, aggregate_id, payload)
                VALUES (%s, NULL, 'IncidentCreated', %s, '{}'::jsonb)
                """,
                (uuid.uuid4(), uuid.uuid4()),
            )
