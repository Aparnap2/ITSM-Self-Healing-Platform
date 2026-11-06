"""Integration: tenant propagation through workflow and evidence relationships.

Slice 2 of the database-security programme. These tests establish that the
tenant isolation boundary is not only present on the routing tables, but
also survives the relationships used by the incident/workflow path:

- tenant-scoped repository reads do not see another tenant's rows;
- composite tenant-bound foreign keys reject a mismatched parent;
- a constrained runtime role cannot use a pooled connection with stale context;
- an explicit rollback does not leak the tenant context;
- rows owned by the legacy SYSTEM tenant are not visible to a tenant session.

The tests use real PostgreSQL and the migration-issued ``itsm_app`` role for
RLS-bypass-sensitive assertions, plus the suite's migration/maintenance DSN
for deterministic seed and verification operations.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from psycopg import AsyncConnection, errors

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.adapters.persistence.tenant import tenant_transaction
from itsm_agent.domain.models import (
    ActionAttemptRecord,
    ActionStatus,
    ActionType,
    ApprovalRequestRecord,
    ApprovalStatus,
    AuditEventRecord,
    Incident,
    IncidentStatus,
    Severity,
    WorkflowRun,
    WorkflowStatus,
)
from itsm_agent.domain.tenancy import SYSTEM_TENANT_ID

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
async def runtime_bundle(runtime_dsn: str) -> AsyncIterator[RepositoryBundle]:
    """A repository bundle backed by the constrained migration runtime role.

    Repository assertions in this module intentionally do not use the suite's
    administrative DSN: RLS does not apply to a superuser, so using the
    control-plane connection here would not prove tenant isolation.
    """
    pool = create_pool(PersistenceConfig(dsn=runtime_dsn, min_size=2, max_size=2))
    await pool.open()
    try:
        yield RepositoryBundle(pool)
    finally:
        await pool.close()


@dataclass(frozen=True)
class _Seed:
    incident: Incident
    workflow: WorkflowRun
    action: ActionAttemptRecord
    approval: ApprovalRequestRecord


def _incident(tenant_id: UUID, external_id: str) -> Incident:
    now = datetime.now(UTC)
    return Incident(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        source_system="test",
        source_incident_id=f"INC-{external_id}",
        external_event_id=external_id,
        title="impactful failure",
        description="Synthetic Slice 2 failure",
        service_name="payments-api",
        severity=Severity.P2,
        status=IncidentStatus.NEW,
        created_at=now,
        updated_at=now,
        correlation_id=uuid.uuid4(),
    )


def _workflow(tenant_id: UUID, incident_id: UUID, version: str = "slice2-v1") -> WorkflowRun:
    now = datetime.now(UTC)
    return WorkflowRun(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        workflow_version=version,
        status=WorkflowStatus.PENDING,
        current_node="start",
        attempt_count=0,
        started_at=now,
        updated_at=now,
        correlation_id=uuid.uuid4(),
    )


def _action(tenant_id: UUID, incident_id: UUID, workflow_id: UUID) -> ActionAttemptRecord:
    return ActionAttemptRecord(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        workflow_id=workflow_id,
        action_type=ActionType.RESTART_SERVICE,
        resource_id="payments-api",
        idempotency_key=f"slice2-{uuid.uuid4().hex}",
        proposal_hash="a" * 64,
        status=ActionStatus.INTENT_RECORDED,
        attempt_number=1,
        intent_recorded_at=datetime.now(UTC),
        adapter_name="test-adapter",
    )


def _approval(tenant_id: UUID, incident_id: UUID, workflow_id: UUID) -> ApprovalRequestRecord:
    now = datetime.now(UTC)
    return ApprovalRequestRecord(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        workflow_id=workflow_id,
        proposal_hash="b" * 64,
        action_type=ActionType.RESTART_SERVICE,
        resource_id="payments-api",
        parameters_hash="c" * 64,
        status=ApprovalStatus.PENDING,
        requested_at=now,
        expires_at=now + timedelta(minutes=15),
        replay_nonce_hash="d" * 64,
    )


def _audit(tenant_id: UUID, incident_id: UUID, workflow_id: UUID) -> AuditEventRecord:
    return AuditEventRecord(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        occurred_at=datetime.now(UTC),
        correlation_id=uuid.uuid4(),
        incident_id=incident_id,
        workflow_id=workflow_id,
        actor_type="SYSTEM",
        actor_id="slice2-test",
        event_type="SLICE2_INVARIANT",
        entity_type="incident",
        entity_id=incident_id,
        payload_redacted={"tenant": str(tenant_id)},
    )


async def _seed(bundle: RepositoryBundle) -> dict[UUID, _Seed]:
    tenants: dict[UUID, _Seed] = {}
    for tenant_id in (uuid.uuid4(), uuid.uuid4()):
        scoped = bundle.for_tenant(tenant_id)
        await bundle.tenants.ensure(tenant_id)
        incident = await scoped.incidents.create(_incident(tenant_id, f"evt-{uuid.uuid4().hex}"))
        workflow = await scoped.workflow_state.create(_workflow(tenant_id, incident.id))
        action = await scoped.action_intents.record(_action(tenant_id, incident.id, workflow.id))
        approval = await scoped.approvals.create(_approval(tenant_id, incident.id, workflow.id))
        await scoped.audit.append(_audit(tenant_id, incident.id, workflow.id))
        tenants[tenant_id] = _Seed(
            incident=incident,
            workflow=workflow,
            action=action,
            approval=approval,
        )
    return tenants


async def test_cross_tenant_composite_foreign_keys_are_rejected(
    runtime_bundle: RepositoryBundle,
) -> None:
    seeded = await _seed(runtime_bundle)
    tenant_a, tenant_b = list(seeded)
    incident_a = seeded[tenant_a].incident
    incident_b = seeded[tenant_b].incident
    workflow_a = seeded[tenant_a].workflow
    workflow_b = seeded[tenant_b].workflow

    # Child tenant A references parent tenant B: invalid regardless of the
    # caller's tenant filter because the FK is composite (tenant_id, id).
    with pytest.raises(errors.ForeignKeyViolation):
        await runtime_bundle.for_tenant(tenant_a).workflow_state.create(
            _workflow(tenant_a, incident_b.id, version="cross-fk")
        )

    with pytest.raises(errors.ForeignKeyViolation):
        await runtime_bundle.for_tenant(tenant_a).action_intents.record(
            _action(tenant_a, incident_b.id, workflow_b.id)
        )

    with pytest.raises(errors.ForeignKeyViolation):
        await runtime_bundle.for_tenant(tenant_b).approvals.create(
            _approval(tenant_b, incident_a.id, workflow_a.id)
        )

    with pytest.raises(errors.ForeignKeyViolation):
        await runtime_bundle.for_tenant(tenant_a).audit.append(
            _audit(tenant_a, incident_b.id, workflow_b.id)
        )


async def test_repository_tenant_sessions_do_not_return_cross_tenant_rows(
    runtime_bundle: RepositoryBundle,
) -> None:
    seeded = await _seed(runtime_bundle)
    tenant_a, tenant_b = list(seeded)
    incident_a = seeded[tenant_a].incident
    incident_b = seeded[tenant_b].incident
    workflow_a = seeded[tenant_a].workflow
    workflow_b = seeded[tenant_b].workflow
    action_b = seeded[tenant_b].action
    approval_b = seeded[tenant_b].approval

    scoped = runtime_bundle.for_tenant(tenant_a)

    assert await scoped.incidents.get(incident_a.id) is not None
    assert await scoped.incidents.get(incident_b.id) is None
    assert (
        await scoped.incidents.find_by_external_event("test", incident_b.external_event_id or "")
        is None
    )
    assert await scoped.workflow_state.get(workflow_a.id) is not None
    assert await scoped.workflow_state.get(workflow_b.id) is None
    assert await scoped.action_intents.get_by_idempotency_key(action_b.idempotency_key) is None
    assert await scoped.approvals.get(approval_b.id) is None


async def test_repository_tenant_sessions_do_not_mutate_cross_tenant_rows(
    runtime_bundle: RepositoryBundle,
) -> None:
    seeded = await _seed(runtime_bundle)
    tenant_a, tenant_b = list(seeded)
    workflow_b = seeded[tenant_b].workflow

    with pytest.raises(LookupError):
        await runtime_bundle.for_tenant(tenant_a).workflow_state.update(
            workflow_b.id,
            status="SUCCEEDED",
            current_node="done",
        )

    remaining = await runtime_bundle.for_tenant(tenant_b).workflow_state.get(workflow_b.id)
    assert remaining is not None
    assert remaining.status == WorkflowStatus.PENDING


async def test_rollback_resets_tenant_context_on_a_pooled_constrained_role(
    runtime_dsn: str,
) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    pool = create_pool(PersistenceConfig(dsn=runtime_dsn, min_size=1, max_size=1))
    await pool.open()
    try:
        async with pool.connection() as admin_conn:
            for tenant_id in (tenant_a, tenant_b):
                await admin_conn.execute(
                    "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (tenant_id, f"slice2-{tenant_id.hex[:8]}"),
                )

        with pytest.raises(RuntimeError):
            async with tenant_transaction(pool, tenant_a) as conn:
                scope = await (
                    await conn.execute("SELECT current_setting('itsm.tenant_id', true)")
                ).fetchone()
                assert scope == (str(tenant_a),)
                raise RuntimeError("slice2 explicit rollback")

        # The next pooled user must not see either tenant A's context or rows.
        async with pool.connection() as conn:
            scope = await (
                await conn.execute("SELECT current_setting('itsm.tenant_id', true)")
            ).fetchone()
            assert scope == ("",)
            count = await (await conn.execute("SELECT count(*) FROM incidents")).fetchone()
            assert count == (0,)
    finally:
        await pool.close()


async def _seed_system_incident(pg_dsn: str) -> Incident:
    system_incident = _incident(SYSTEM_TENANT_ID, f"sys-{uuid.uuid4().hex}")
    async with await AsyncConnection.connect(pg_dsn) as conn, conn.transaction():
        await conn.execute(
            "SELECT set_config('itsm.tenant_id', %s, true)",
            (str(SYSTEM_TENANT_ID),),
        )
        await conn.execute(
            """
                INSERT INTO incidents (
                    id, tenant_id, source_system, source_incident_id,
                    external_event_id, title, description, service_name, severity,
                    status, created_at, updated_at, correlation_id,
                    current_workflow_id, resolution_summary, audit_reference
                ) VALUES (
                    %(id)s, %(tenant_id)s, %(source_system)s, %(source_incident_id)s,
                    %(external_event_id)s, %(title)s, %(description)s,
                    %(service_name)s, %(severity)s, %(status)s, %(created_at)s,
                    %(updated_at)s, %(correlation_id)s, NULL, NULL, NULL
                )
                """,
            system_incident.model_dump(),
        )
    return system_incident


async def test_system_tenant_rows_are_not_visible_to_a_tenant_context(
    runtime_bundle: RepositoryBundle, pg_dsn: str
) -> None:
    system = await _seed_system_incident(pg_dsn)
    tenant = uuid.uuid4()
    await runtime_bundle.tenants.ensure(tenant)

    async with runtime_bundle.transaction(tenant) as conn:
        visible = await (
            await conn.execute(
                "SELECT count(*) FROM incidents WHERE id = %s",
                (system.id,),
            )
        ).fetchone()

    assert visible == (0,)
