"""Psycopg 3 async repository implementations (Phase 3).

Contract notes:
- All methods are async and typed; domain models cross the boundary (no raw dicts).
- ``conn=`` allows a caller to compose several writes into ONE transaction —
  required for the fail-closed audit contract and transactional outbox.
- Without ``conn``, each method runs in its own pooled transaction.
- ``DuplicateIdempotencyKeyError`` / ``ApprovalNotPendingError`` fail closed.
- Tenant-scoped methods establish the RLS context themselves via
  ``_tenant_session``. Passing ``conn=`` means the CALLER owns the transaction
  and MUST already have opened it with
  :func:`itsm_agent.adapters.persistence.tenant.tenant_transaction` (or
  otherwise set ``itsm.tenant_id`` transaction-locally); ``_tenant_session``
  then yields that connection unchanged and does not re-scope it.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.tenant import tenant_transaction
from itsm_agent.domain.events import SourceEvent
from itsm_agent.domain.models import (
    EvidenceReference,
    Finding,
    IdentityMapping,
    ReviewDecision,
)
from itsm_agent.domain.tenancy import SYSTEM_TENANT_ID
from itsm_agent.ports.repositories import (
    ActionIntent,
    ApprovalNotPendingError,
    ApprovalRequest,
    AuditEvent,
    InboxEvent,
    InboxReceipt,
    Incident,
    OutboxEvent,
    SourceCheckpoint,
    TerminalStateConflictError,
    WorkflowState,
)
from itsm_agent.privacy.retention import (
    DEFAULT_POLICIES,
    DataClass,
    ErasureRequest,
    ErasureTombstone,
    ExpiryAction,
    LegalHold,
    RetentionPolicy,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _erasure_request_from_row(row: dict[str, Any]) -> ErasureRequest:
    return ErasureRequest(
        id=row["id"],
        tenant_id=row["tenant_id"],
        requested_by=row["requested_by"],
        reason=row["reason"],
        data_classes=tuple(DataClass(value) for value in row["data_classes"]),
        status=row["status"],
        requested_at=row["requested_at"],
        completed_at=row["completed_at"],
    )


class _BaseRepository:
    def __init__(
        self,
        pool: AsyncConnectionPool[AsyncConnection],
        tenant_id: UUID | None = None,
    ) -> None:
        self._pool = pool
        self._tenant_id = tenant_id

    def for_tenant(self, tenant_id: UUID) -> _BaseRepository:
        """Return a repository bound to a tenant RLS context."""
        return type(self)(self._pool, tenant_id)

    @asynccontextmanager
    async def _session(self, conn: AsyncConnection | None) -> AsyncIterator[AsyncConnection]:
        if conn is not None:
            yield conn
        elif self._tenant_id is not None:
            async with self._tenant_session(self._tenant_id, None) as scoped:
                yield scoped
        else:
            async with self._pool.connection() as pooled, pooled.transaction():
                yield pooled

    @asynccontextmanager
    async def _tenant_session(
        self, tenant_id: UUID, conn: AsyncConnection | None
    ) -> AsyncIterator[AsyncConnection]:
        """Yield a connection with ``itsm.tenant_id`` set transaction-locally.

        ``conn is not None`` means the caller owns the transaction and MUST have
        established the tenant context itself (``tenant_transaction``); the
        connection is yielded unchanged. Otherwise a pooled transaction is
        opened with the RLS context set before yielding.
        """
        if conn is not None:
            yield conn
        else:
            async with tenant_transaction(self._pool, tenant_id) as scoped:
                yield scoped

    def _session_for(
        self, tenant_id: UUID | None, conn: AsyncConnection | None
    ) -> AbstractAsyncContextManager[AsyncConnection]:
        """Select a tenant-scoped session when a tenant is given, else a plain one."""
        if tenant_id is None:
            if conn is None:
                return self._session(None)
            return self._session(conn)
        return self._tenant_session(tenant_id, conn)


class PsycopgIncidentRepository(_BaseRepository):
    def __init__(
        self, pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID | None = None
    ) -> None:
        super().__init__(pool, tenant_id or SYSTEM_TENANT_ID)

    async def create(self, incident: Incident, *, conn: AsyncConnection | None = None) -> Incident:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    INSERT INTO incidents (
                        id, tenant_id, source_system, source_incident_id, external_event_id,
                        title, description, service_name, severity, status,
                        created_at, updated_at, correlation_id, current_workflow_id,
                        resolution_summary, audit_reference
                    ) VALUES (
                        %(id)s, %(tenant_id)s, %(source_system)s, %(source_incident_id)s,
                        %(external_event_id)s, %(title)s, %(description)s,
                        %(service_name)s, %(severity)s, %(status)s,
                        %(created_at)s, %(updated_at)s, %(correlation_id)s,
                        %(current_workflow_id)s, %(resolution_summary)s,
                        %(audit_reference)s
                    )
                    """,
                incident.model_dump(),
            )
        return incident

    async def get(
        self, incident_id: UUID, *, conn: AsyncConnection | None = None
    ) -> Incident | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
            row = await cur.fetchone()
        return Incident.model_validate(row) if row else None

    async def find_by_source(
        self, source_system: str, source_incident_id: str, *, conn: AsyncConnection | None = None
    ) -> Incident | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM incidents WHERE source_system = %s AND source_incident_id = %s",
                (source_system, source_incident_id),
            )
            row = await cur.fetchone()
        return Incident.model_validate(row) if row else None

    async def find_by_external_event(
        self, source_system: str, external_event_id: str, *, conn: AsyncConnection | None = None
    ) -> Incident | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM incidents WHERE source_system = %s AND external_event_id = %s",
                (source_system, external_event_id),
            )
            row = await cur.fetchone()
        return Incident.model_validate(row) if row else None

    async def update_status(
        self,
        incident_id: UUID,
        status: str,
        *,
        resolution_summary: str | None = None,
        audit_reference: str | None = None,
        current_workflow_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> Incident:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                UPDATE incidents SET
                    status = %(status)s,
                    resolution_summary = COALESCE(%(resolution_summary)s, resolution_summary),
                    audit_reference = COALESCE(%(audit_reference)s, audit_reference),
                    current_workflow_id = COALESCE(%(current_workflow_id)s, current_workflow_id),
                    updated_at = %(now)s
                WHERE id = %(id)s
                RETURNING *
                """,
                {
                    "status": status,
                    "resolution_summary": resolution_summary,
                    "audit_reference": audit_reference,
                    "current_workflow_id": current_workflow_id,
                    "now": _utcnow(),
                    "id": incident_id,
                },
            )
            row = await cur.fetchone()
        if row is None:
            raise LookupError(f"incident not found: {incident_id}")
        return Incident.model_validate(row)


class PsycopgInboxRepository(_BaseRepository):
    async def try_record(
        self,
        *,
        source_system: str,
        external_event_id: str,
        payload_hash: str,
        tenant_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> InboxReceipt:
        """Dedup gate: INSERT ... ON CONFLICT DO NOTHING on the tenant-scoped
        unique key ``(tenant_id, source_system, external_event_id)``. Concurrent
        duplicates race on the constraint, so exactly one caller sees NEW. A
        tenant-less caller falls back to the legacy global key (pre-tenant
        rows only)."""
        # Targetless ON CONFLICT DO NOTHING catches whichever partial unique
        # index applies: the tenant-scoped key for tenant rows, or the legacy
        # global key for pre-tenant rows. No SQL is built from variables.
        async with self._session(conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO event_inbox (
                    id, tenant_id, source_system, external_event_id, payload_hash, status
                )
                VALUES (%s, %s, %s, %s, %s, 'RECEIVED')
                ON CONFLICT DO NOTHING
                """,
                (uuid4(), tenant_id, source_system, external_event_id, payload_hash),
            )
            inserted = cur.rowcount == 1
        return InboxReceipt.NEW if inserted else InboxReceipt.DUPLICATE

    async def get(
        self, source_system: str, external_event_id: str, *, conn: AsyncConnection | None = None
    ) -> InboxEvent | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM event_inbox WHERE source_system = %s AND external_event_id = %s",
                (source_system, external_event_id),
            )
            row = await cur.fetchone()
        return InboxEvent.model_validate(row) if row else None

    async def mark_processed(
        self, inbox_event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> None:
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                "UPDATE event_inbox SET status = 'PROCESSED' WHERE id = %s", (inbox_event_id,)
            )

    async def mark_failed(
        self, inbox_event_id: UUID, error: str, *, conn: AsyncConnection | None = None
    ) -> None:
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                UPDATE event_inbox
                SET status = 'DEAD_LETTERED', attempt_count = attempt_count + 1, last_error = %s
                WHERE id = %s
                """,
                (error[:2000], inbox_event_id),
            )


class PsycopgOutboxRepository(_BaseRepository):
    async def append(
        self,
        *,
        event_type: str,
        aggregate_id: UUID,
        payload: dict[str, object],
        tenant_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> OutboxEvent:
        """Must be called inside the SAME transaction as the business state
        change (transactional outbox, ADR-0002)."""
        event = OutboxEvent(
            id=uuid4(),
            event_type=event_type,
            aggregate_id=aggregate_id,
            payload=payload,
            created_at=_utcnow(),
        )
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO outbox (id, tenant_id, event_type, aggregate_id, payload, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    event.id,
                    tenant_id,
                    event.event_type,
                    event.aggregate_id,
                    Jsonb(event.payload),
                    event.created_at,
                ),
            )
        return event

    async def claim_pending(
        self,
        limit: int = 10,
        *,
        lease_seconds: float = 60.0,
        tenant_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> list[OutboxEvent]:
        """Claim pending rows with FOR UPDATE SKIP LOCKED (multi-relay safe).
        Claim bumps attempts and pushes next_attempt_at forward as a lease so
        a crashed relay's rows become claimable again after the lease expires.

        When ``tenant_id`` is given the claim runs under that tenant's RLS
        context (and filters explicitly, as defense in depth). When omitted it
        keeps the system/legacy behaviour of claiming across all tenants.
        """
        lease_until = _utcnow() + timedelta(seconds=lease_seconds)
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    UPDATE outbox SET attempts = attempts + 1, next_attempt_at = %(lease)s
                    WHERE id IN (
                        SELECT id FROM outbox
                        WHERE status = 'pending' AND next_attempt_at <= now()
                          AND (
                              %(tenant_id)s::uuid IS NULL
                              OR tenant_id = %(tenant_id)s
                          )
                        ORDER BY created_at, id
                        LIMIT %(limit)s
                        FOR UPDATE SKIP LOCKED
                    )
                    RETURNING *
                    """,
                {"lease": lease_until, "limit": limit, "tenant_id": tenant_id},
            )
            rows = await cur.fetchall()
        return [OutboxEvent.model_validate(r) for r in rows]

    async def mark_published(
        self,
        outbox_event_id: UUID,
        *,
        tenant_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> None:
        """Call ONLY after broker acknowledgement (ADR-0002)."""
        async with self._session_for(tenant_id, conn) as c:  # noqa: SIM117
            await c.execute(
                """
                UPDATE outbox
                SET status = 'published', published_at = %s, last_error = NULL
                WHERE id = %s
                """,
                (_utcnow(), outbox_event_id),
            )

    async def mark_failed(
        self,
        outbox_event_id: UUID,
        error: str,
        *,
        backoff_seconds: float = 5.0,
        max_attempts: int = 10,
        tenant_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> None:
        next_at = _utcnow() + timedelta(seconds=backoff_seconds)
        async with self._session_for(tenant_id, conn) as c:  # noqa: SIM117
            await c.execute(
                """
                UPDATE outbox
                SET last_error = %s, next_attempt_at = %s,
                    status = CASE WHEN attempts >= %s THEN 'failed' ELSE 'pending' END
                WHERE id = %s
                """,
                (error[:2000], next_at, max_attempts, outbox_event_id),
            )

    async def count_pending(
        self, *, tenant_id: UUID | None = None, conn: AsyncConnection | None = None
    ) -> int:
        async with self._session_for(tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                SELECT count(*) FROM outbox
                 WHERE status = 'pending'
                   AND (%s::uuid IS NULL OR tenant_id = %s)
                """,
                (tenant_id, tenant_id),
            )
            row = await cur.fetchone()
        return int(row[0]) if row else 0


class PsycopgActionIntentRepository(_BaseRepository):
    def __init__(
        self, pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID | None = None
    ) -> None:
        super().__init__(pool, tenant_id or SYSTEM_TENANT_ID)

    async def record(
        self, intent: ActionIntent, *, conn: AsyncConnection | None = None
    ) -> ActionIntent:
        """Persist intent BEFORE any side effect (FR-07). Raises
        DuplicateIdempotencyKeyError if the key already exists — the caller
        must treat the existing intent as authoritative, never re-execute."""
        async with self._session(conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                    INSERT INTO action_intents (
                        id, tenant_id, incident_id, workflow_id, action_type, resource_id,
                        idempotency_key, proposal_hash, status, attempt_number,
                        intent_recorded_at, adapter_name
                    ) VALUES (
                        %(id)s, %(tenant_id)s, %(incident_id)s, %(workflow_id)s,
                        %(action_type)s, %(resource_id)s, %(idempotency_key)s,
                        %(proposal_hash)s, %(status)s, %(attempt_number)s,
                        %(intent_recorded_at)s, %(adapter_name)s
                    )
                    """,
                intent.model_dump(),
            )
        return intent

    async def get_by_idempotency_key(
        self, idempotency_key: str, *, conn: AsyncConnection | None = None
    ) -> ActionIntent | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM action_intents WHERE idempotency_key = %s", (idempotency_key,)
            )
            row = await cur.fetchone()
        return ActionIntent.model_validate(row) if row else None

    async def mark_result(
        self,
        idempotency_key: str,
        *,
        status: str,
        result_code: str | None = None,
        result_summary: str | None = None,
        result_evidence_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> ActionIntent:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    UPDATE action_intents SET
                        status = %(status)s,
                        started_at = CASE
                            WHEN %(status)s = 'RUNNING'
                            THEN COALESCE(started_at, %(now)s)
                            ELSE started_at
                        END,
                        result_code = %(result_code)s,
                        result_summary = %(result_summary)s,
                        result_evidence_id = %(result_evidence_id)s,
                        finished_at = COALESCE(finished_at, %(now)s)
                    WHERE idempotency_key = %(key)s
                    RETURNING *
                    """,
                {
                    "status": status,
                    "result_code": result_code,
                    "result_summary": result_summary,
                    "result_evidence_id": result_evidence_id,
                    "now": _utcnow(),
                    "key": idempotency_key,
                },
            )
            row = await cur.fetchone()
        if row is None:
            raise LookupError(f"action intent not found: {idempotency_key}")
        return ActionIntent.model_validate(row)


class PsycopgApprovalRepository(_BaseRepository):
    def __init__(
        self, pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID | None = None
    ) -> None:
        super().__init__(pool, tenant_id or SYSTEM_TENANT_ID)

    async def create(
        self, approval: ApprovalRequest, *, conn: AsyncConnection | None = None
    ) -> ApprovalRequest:
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO approvals (
                    id, tenant_id, incident_id, workflow_id, proposal_hash, action_type,
                    resource_id, parameters_hash, status, requested_at, expires_at,
                    replay_nonce_hash
                ) VALUES (
                    %(id)s, %(tenant_id)s, %(incident_id)s, %(workflow_id)s,
                    %(proposal_hash)s, %(action_type)s, %(resource_id)s,
                    %(parameters_hash)s, %(status)s, %(requested_at)s,
                    %(expires_at)s, %(replay_nonce_hash)s
                )
                """,
                approval.model_dump(),
            )
        return approval

    async def get(
        self, approval_id: UUID, *, conn: AsyncConnection | None = None
    ) -> ApprovalRequest | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute("SELECT * FROM approvals WHERE id = %s", (approval_id,))
            row = await cur.fetchone()
        return ApprovalRequest.model_validate(row) if row else None

    async def decide(
        self,
        approval_id: UUID,
        *,
        decision: str,
        approver_id: str,
        nonce_hash: str,
        reason: str | None = None,
        decided_at: datetime,
        conn: AsyncConnection | None = None,
    ) -> ApprovalRequest:
        """Single-use decision: atomic UPDATE ... WHERE status='PENDING'.
        A replayed/expired/already-decided request raises
        ApprovalNotPendingError (fail closed)."""
        if decision not in ("APPROVED", "REJECTED"):
            raise ValueError(f"invalid approval decision: {decision}")
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    UPDATE approvals SET
                        status = %(decision)s,
                        decided_at = %(decided_at)s,
                        approver_id = %(approver_id)s,
                        decision_reason = %(reason)s,
                        replay_nonce_hash = %(nonce_hash)s
                    WHERE id = %(id)s AND status = 'PENDING'
                    RETURNING *
                    """,
                {
                    "decision": decision,
                    "decided_at": decided_at,
                    "approver_id": approver_id,
                    "reason": reason,
                    "nonce_hash": nonce_hash,
                    "id": approval_id,
                },
            )
            row = await cur.fetchone()
        if row is None:
            raise ApprovalNotPendingError(
                f"approval {approval_id} is not PENDING (replay/expired/already decided)"
            )
        return ApprovalRequest.model_validate(row)


class PsycopgAuditRepository(_BaseRepository):
    def __init__(
        self, pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID | None = None
    ) -> None:
        super().__init__(pool, tenant_id or SYSTEM_TENANT_ID)

    async def append(self, event: AuditEvent, *, conn: AsyncConnection | None = None) -> AuditEvent:
        """Append-only (DB trigger rejects UPDATE/DELETE).

        Fail-closed contract: pass ``conn`` to write the audit record in the
        SAME transaction as the side effect it witnesses. If this insert
        fails, the shared transaction rolls back and the side effect never
        commits. Callers that cannot share a transaction must append the
        audit record BEFORE the side effect and abort on failure.
        """
        async with self._tenant_session(event.tenant_id, conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO audit_events (
                    id, tenant_id, occurred_at, correlation_id, incident_id, workflow_id,
                    actor_type, actor_id, event_type, entity_type, entity_id,
                    payload_redacted, previous_hash, event_hash
                ) VALUES (
                    %(id)s, %(tenant_id)s, %(occurred_at)s, %(correlation_id)s,
                    %(incident_id)s, %(workflow_id)s, %(actor_type)s, %(actor_id)s,
                    %(event_type)s, %(entity_type)s, %(entity_id)s,
                    %(payload_redacted)s, %(previous_hash)s, %(event_hash)s
                )
                """,
                {
                    **event.model_dump(),
                    "payload_redacted": Jsonb(event.payload_redacted),
                },
            )
        return event


class PsycopgWorkflowStateRepository(_BaseRepository):
    def __init__(
        self, pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID | None = None
    ) -> None:
        super().__init__(pool, tenant_id or SYSTEM_TENANT_ID)

    async def create(
        self, state: WorkflowState, *, conn: AsyncConnection | None = None
    ) -> WorkflowState:
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO workflow_state (
                    id, tenant_id, incident_id, workflow_version, status, current_node,
                    checkpoint_ref, attempt_count, started_at, updated_at,
                    correlation_id
                ) VALUES (
                    %(id)s, %(tenant_id)s, %(incident_id)s, %(workflow_version)s,
                    %(status)s, %(current_node)s, %(checkpoint_ref)s,
                    %(attempt_count)s, %(started_at)s, %(updated_at)s,
                    %(correlation_id)s
                )
                """,
                state.model_dump(),
            )
        return state

    async def get(
        self, workflow_id: UUID, *, conn: AsyncConnection | None = None
    ) -> WorkflowState | None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute("SELECT * FROM workflow_state WHERE id = %s", (workflow_id,))
            row = await cur.fetchone()
        return WorkflowState.model_validate(row) if row else None

    async def update(
        self,
        workflow_id: UUID,
        *,
        status: str,
        current_node: str,
        checkpoint_ref: str | None = None,
        attempt_count: int | None = None,
        last_error_code: str | None = None,
        finished: bool = False,
        conn: AsyncConnection | None = None,
    ) -> WorkflowState:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    UPDATE workflow_state SET
                        status = %(status)s,
                        current_node = %(current_node)s,
                        checkpoint_ref = COALESCE(%(checkpoint_ref)s, checkpoint_ref),
                        attempt_count = COALESCE(%(attempt_count)s, attempt_count),
                        last_error_code = %(last_error_code)s,
                        updated_at = %(now)s,
                        finished_at = CASE WHEN %(finished)s THEN %(now)s ELSE finished_at END
                    WHERE id = %(id)s
                    RETURNING *
                    """,
                {
                    "status": status,
                    "current_node": current_node,
                    "checkpoint_ref": checkpoint_ref,
                    "attempt_count": attempt_count,
                    "last_error_code": last_error_code,
                    "now": _utcnow(),
                    "finished": finished,
                    "id": workflow_id,
                },
            )
            row = await cur.fetchone()
        if row is None:
            raise LookupError(f"workflow state not found: {workflow_id}")
        return WorkflowState.model_validate(row)


class PsycopgTerminalStateRepository(_BaseRepository):
    """Atomic terminal transition (workflow run + incident) in one transaction.

    Lock order is incident -> workflow_state on both paths; every writer uses
    the same order so concurrent finalizers cannot deadlock. A workflow that is
    already finished, or an incident already in a terminal status, raises
    ``TerminalStateConflictError`` rather than overwriting committed state.
    """

    _TERMINAL_INCIDENT_STATUSES = ("RESOLVED", "ESCALATED", "REJECTED")

    def __init__(
        self, pool: AsyncConnectionPool[AsyncConnection], tenant_id: UUID | None = None
    ) -> None:
        super().__init__(pool, tenant_id or SYSTEM_TENANT_ID)

    async def finalize(
        self,
        *,
        workflow_id: UUID,
        incident_id: UUID,
        workflow_status: str,
        current_node: str,
        attempt_count: int,
        last_error_code: str | None,
        incident_status: str,
        resolution_summary: str | None = None,
        conn: AsyncConnection | None = None,
    ) -> None:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT status FROM incidents WHERE id = %s FOR UPDATE",
                (incident_id,),
            )
            incident_row = await cur.fetchone()
            if incident_row is None:
                raise LookupError(f"incident not found: {incident_id}")
            if incident_row["status"] in self._TERMINAL_INCIDENT_STATUSES:
                raise TerminalStateConflictError(
                    f"incident {incident_id} already terminal: {incident_row['status']}"
                )

            await cur.execute(
                "SELECT finished_at FROM workflow_state WHERE id = %s FOR UPDATE",
                (workflow_id,),
            )
            workflow_row = await cur.fetchone()
            if workflow_row is None:
                raise LookupError(f"workflow state not found: {workflow_id}")
            if workflow_row["finished_at"] is not None:
                raise TerminalStateConflictError(f"workflow {workflow_id} already finished")

            now = _utcnow()
            await cur.execute(
                """
                UPDATE incidents SET
                    status = %(status)s,
                    resolution_summary = COALESCE(%(summary)s, resolution_summary),
                    current_workflow_id = %(workflow_id)s,
                    updated_at = %(now)s
                WHERE id = %(id)s
                """,
                {
                    "status": incident_status,
                    "summary": resolution_summary,
                    "workflow_id": workflow_id,
                    "now": now,
                    "id": incident_id,
                },
            )
            await cur.execute(
                """
                UPDATE workflow_state SET
                    status = %(status)s,
                    current_node = %(node)s,
                    attempt_count = %(attempts)s,
                    last_error_code = %(error)s,
                    updated_at = %(now)s,
                    finished_at = %(now)s
                WHERE id = %(id)s
                """,
                {
                    "status": workflow_status,
                    "node": current_node,
                    "attempts": attempt_count,
                    "error": last_error_code,
                    "now": now,
                    "id": workflow_id,
                },
            )


class PsycopgReviewDecisionRepository(_BaseRepository):
    async def record(
        self, decision: ReviewDecision, *, conn: AsyncConnection | None = None
    ) -> ReviewDecision:
        async with self._session_for(decision.tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO review_decisions (
                    id, tenant_id, finding_id, reviewer_id, decision,
                    decided_at, rationale, evidence_pack_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    decision.id,
                    decision.tenant_id,
                    decision.finding_id,
                    decision.reviewer_id,
                    decision.decision,
                    decision.decided_at,
                    decision.rationale,
                    decision.evidence_pack_ref,
                ),
            )
        return decision

    async def list_for_finding(
        self, tenant_id: UUID, finding_id: UUID, *, conn: AsyncConnection | None = None
    ) -> list[ReviewDecision]:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT * FROM review_decisions
                WHERE tenant_id = %s AND finding_id = %s
                ORDER BY decided_at, id
                """,
                (tenant_id, finding_id),
            )
            rows = await cur.fetchall()
        return [
            ReviewDecision(
                id=r["id"],
                tenant_id=r["tenant_id"],
                finding_id=r["finding_id"],
                reviewer_id=r["reviewer_id"],
                decision=r["decision"],
                decided_at=r["decided_at"],
                rationale=r["rationale"],
                evidence_pack_ref=r["evidence_pack_ref"],
            )
            for r in rows
        ]

    async def list_for_tenant(
        self, tenant_id: UUID, *, conn: AsyncConnection | None = None
    ) -> list[ReviewDecision]:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM review_decisions WHERE tenant_id = %s ORDER BY decided_at, id",
                (tenant_id,),
            )
            rows = await cur.fetchall()
        return [
            ReviewDecision(
                id=r["id"],
                tenant_id=r["tenant_id"],
                finding_id=r["finding_id"],
                reviewer_id=r["reviewer_id"],
                decision=r["decision"],
                decided_at=r["decided_at"],
                rationale=r["rationale"],
                evidence_pack_ref=r["evidence_pack_ref"],
            )
            for r in rows
        ]


class PsycopgEvidenceReferenceRepository(_BaseRepository):
    async def list_for_tenant_finding(
        self, tenant_id: UUID, finding_id: UUID, *, conn: AsyncConnection | None = None
    ) -> list[EvidenceReference]:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT id, finding_id, source_event_id, access_fact_id,
                       content_hash, excerpt, trust_level, collected_at
                FROM evidence_references
                WHERE tenant_id = %s AND finding_id = %s
                ORDER BY collected_at, id
                """,
                (tenant_id, finding_id),
            )
            rows = await cur.fetchall()
        return [
            EvidenceReference(
                id=r["id"],
                finding_id=r["finding_id"],
                source_event_id=r["source_event_id"],
                access_fact_id=r["access_fact_id"],
                content_hash=r["content_hash"],
                excerpt=r["excerpt"],
                trust_level=r["trust_level"],
                collected_at=r["collected_at"],
            )
            for r in rows
        ]


class PsycopgSourceEventRepository(_BaseRepository):
    async def insert(
        self, event: SourceEvent, *, conn: AsyncConnection | None = None
    ) -> SourceEvent:
        async with self._session_for(event.tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO source_events (
                    id, tenant_id, source, source_event_id, idempotency_key,
                    source_schema_version, canonical_schema_version, event_type,
                    event_category, event_time, observed_at, ingested_at,
                    actor_id, principal_id, session_id, action, resource_type,
                    resource_id, outcome, permission_context, payload_hash,
                    raw_evidence_reference, correlation_metadata
                ) VALUES (
                    %(id)s, %(tenant_id)s, %(source)s, %(source_event_id)s,
                    %(idempotency_key)s, %(source_schema_version)s,
                    %(canonical_schema_version)s, %(event_type)s, %(event_category)s,
                    %(event_time)s, %(observed_at)s, %(ingested_at)s, %(actor_id)s,
                    %(principal_id)s, %(session_id)s, %(action)s, %(resource_type)s,
                    %(resource_id)s, %(outcome)s, %(permission_context)s,
                    %(payload_hash)s, %(raw_evidence_reference)s,
                    %(correlation_metadata)s
                )
                """,
                {
                    "id": event.event_id,
                    "tenant_id": event.tenant_id,
                    "source": event.source,
                    "source_event_id": event.source_event_id,
                    "idempotency_key": event.idempotency_key,
                    "source_schema_version": event.source_schema_version,
                    "canonical_schema_version": event.canonical_schema_version,
                    "event_type": event.event_type,
                    "event_category": event.event_category,
                    "event_time": event.event_time,
                    "observed_at": event.observed_at,
                    "ingested_at": event.ingested_at,
                    "actor_id": event.actor_id,
                    "principal_id": event.principal_id,
                    "session_id": event.session_id,
                    "action": event.action,
                    "resource_type": event.resource_type,
                    "resource_id": event.resource_id,
                    "outcome": event.outcome,
                    "permission_context": json.dumps(event.permission_context),
                    "payload_hash": event.payload_hash,
                    "raw_evidence_reference": event.raw_evidence_reference,
                    "correlation_metadata": json.dumps(event.correlation_metadata),
                },
            )
        return event

    async def get(
        self, event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> SourceEvent | None:
        """System-scoped lookup by id (no tenant context).

        Tenant-scoped callers MUST use :meth:`get_for_tenant` so RLS applies.
        """
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute("SELECT * FROM source_events WHERE id = %s", (event_id,))
            row = await cur.fetchone()
        if row is None:
            return None
        return _source_event_from_row(row)

    async def get_for_tenant(
        self, tenant_id: UUID, event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> SourceEvent | None:
        """Tenant-scoped lookup: returns None for another tenant's event."""
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM source_events WHERE tenant_id = %s AND id = %s",
                (tenant_id, event_id),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return _source_event_from_row(row)

    async def get_by_idempotency(
        self, tenant_id: UUID, idempotency_key: str, *, conn: AsyncConnection | None = None
    ) -> SourceEvent | None:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM source_events WHERE tenant_id = %s AND idempotency_key = %s",
                (tenant_id, idempotency_key),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return _source_event_from_row(row)


def _source_event_from_row(row: dict[str, Any]) -> SourceEvent:
    return SourceEvent(
        event_id=row["id"],
        tenant_id=row["tenant_id"],
        source=row["source"],
        source_event_id=row["source_event_id"],
        idempotency_key=row["idempotency_key"],
        source_schema_version=row["source_schema_version"],
        canonical_schema_version=row["canonical_schema_version"],
        event_type=row["event_type"],
        event_category=row["event_category"],
        event_time=row["event_time"],
        observed_at=row["observed_at"],
        ingested_at=row["ingested_at"],
        actor_id=row["actor_id"],
        principal_id=row["principal_id"],
        session_id=row["session_id"],
        action=row["action"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        outcome=row["outcome"],
        permission_context=row["permission_context"] or {},
        payload_hash=row["payload_hash"],
        raw_evidence_reference=row["raw_evidence_reference"],
        correlation_metadata=row["correlation_metadata"] or {},
    )


class PsycopgFindingRepository(_BaseRepository):
    async def upsert(self, finding: Finding, *, conn: AsyncConnection | None = None) -> Finding:
        tenant_id = finding.tenant_id
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                INSERT INTO findings (
                    id, tenant_id, finding_type, severity, status, title,
                    description, detected_at, rule_version, risk_score, outcome
                ) VALUES (
                    %(id)s, %(tenant_id)s, %(finding_type)s, %(severity)s,
                    %(status)s, %(title)s, %(description)s, %(detected_at)s,
                    %(rule_version)s, %(risk_score)s, %(outcome)s
                )
                ON CONFLICT (tenant_id, finding_type, title) DO NOTHING
                RETURNING id
                """,
                {
                    "id": finding.id,
                    "tenant_id": finding.tenant_id,
                    "finding_type": finding.finding_type,
                    "severity": str(finding.severity),
                    "status": finding.status,
                    "title": finding.title,
                    "description": finding.description,
                    "detected_at": finding.detected_at,
                    "rule_version": finding.rule_version,
                    "risk_score": finding.risk_score,
                    "outcome": finding.outcome,
                },
            )
            row = await cur.fetchone()
            if row is not None:
                return finding
            # Conflict: fetch the existing finding id.
            await cur.execute(
                """
                SELECT id FROM findings
                WHERE tenant_id = %s AND finding_type = %s AND title = %s
                """,
                (finding.tenant_id, finding.finding_type, finding.title),
            )
            row = await cur.fetchone()
            if row is None:
                return finding
            return finding.model_copy(update={"id": row["id"]})

    async def get(
        self,
        tenant_id: UUID,
        finding_id: UUID,
        *,
        conn: AsyncConnection | None = None,
    ) -> Finding | None:
        """Fetch a single finding, scoped to its tenant (cross-tenant returns None)."""
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM findings WHERE tenant_id = %s AND id = %s",
                (tenant_id, finding_id),
            )
            row = await cur.fetchone()
        return _finding_from_row(row) if row is not None else None

    async def list_for_tenant(
        self, tenant_id: UUID, *, conn: AsyncConnection | None = None
    ) -> list[Finding]:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM findings WHERE tenant_id = %s ORDER BY detected_at, id",
                (tenant_id,),
            )
            rows = await cur.fetchall()
        return [_finding_from_row(r) for r in rows]

    async def count_for_tenant(
        self, tenant_id: UUID, *, conn: AsyncConnection | None = None
    ) -> int:
        async with self._session_for(tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute("SELECT count(*) FROM findings WHERE tenant_id = %s", (tenant_id,))
            row = await cur.fetchone()
        return int(row[0]) if row else 0


class PsycopgProcessingRecordRepository(_BaseRepository):
    async def claim(
        self,
        *,
        tenant_id: UUID,
        source: str,
        event_id: UUID,
        processing_version: str,
        conn: AsyncConnection | None = None,
    ) -> tuple[str, UUID | None]:
        """Claim a processing slot.

        Returns (status, record_id) where status is one of:
        - 'NEW'      : this caller created the record; proceed with processing.
        - 'COMPLETED': already processed; do not re-process.
        - 'PROCESSING': another worker is processing; caller should retry later.
        - 'FAILED'   : previous attempt failed; caller may retry (record reset to PROCESSING).
        """
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                INSERT INTO processing_records (
                    id, tenant_id, source, event_id, processing_version, status
                ) VALUES (%s, %s, %s, %s, %s, 'PROCESSING')
                ON CONFLICT (tenant_id, source, event_id, processing_version) DO NOTHING
                RETURNING id
                """,
                (uuid4(), tenant_id, source, event_id, processing_version),
            )
            row = await cur.fetchone()
            if row is not None:
                return "NEW", row["id"]
            await cur.execute(
                """
                SELECT id, status FROM processing_records
                WHERE tenant_id = %s AND source = %s AND event_id = %s
                  AND processing_version = %s
                """,
                (tenant_id, source, event_id, processing_version),
            )
            row = await cur.fetchone()
            if row is None:
                return "PROCESSING", None
            rid = row["id"]
            status = row["status"]
            if status == "COMPLETED":
                return "COMPLETED", rid
            if status == "PROCESSING":
                return "PROCESSING", rid
            if status == "FAILED":
                await cur.execute(
                    """
                    UPDATE processing_records
                    SET status = 'PROCESSING', started_at = now(), last_error = NULL
                    WHERE id = %s
                    """,
                    (rid,),
                )
                return "FAILED", rid
        return "PROCESSING", None

    async def complete(
        self,
        record_id: UUID,
        finding_ids: list[UUID],
        *,
        tenant_id: UUID,
        conn: AsyncConnection | None = None,
    ) -> None:
        async with self._session_for(tenant_id, conn) as c:  # noqa: SIM117
            await c.execute(
                """
                UPDATE processing_records
                SET status = 'COMPLETED', completed_at = %s, finding_ids = %s
                WHERE id = %s
                """,
                (_utcnow(), finding_ids, record_id),
            )

    async def fail(
        self,
        record_id: UUID,
        error: str,
        *,
        tenant_id: UUID,
        conn: AsyncConnection | None = None,
    ) -> None:
        async with self._session_for(tenant_id, conn) as c:  # noqa: SIM117
            await c.execute(
                """
                UPDATE processing_records
                SET status = 'FAILED', last_error = %s
                WHERE id = %s
                """,
                (error[:2000], record_id),
            )


def _finding_from_row(row: dict[str, Any]) -> Finding:
    from itsm_agent.domain.models import Finding, Severity

    return Finding(
        id=row["id"],
        tenant_id=row["tenant_id"],
        finding_type=row["finding_type"],
        severity=Severity(row["severity"]),
        status=row["status"],
        title=row["title"],
        description=row["description"],
        detected_at=row["detected_at"],
        rule_version=row["rule_version"],
        risk_score=row["risk_score"],
        outcome=row["outcome"],
    )


class PsycopgSourceCheckpointRepository(_BaseRepository):
    async def get(
        self, tenant_id: UUID, source: str, *, conn: AsyncConnection | None = None
    ) -> SourceCheckpoint | None:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM source_checkpoints WHERE tenant_id = %s AND source = %s",
                (tenant_id, source),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return SourceCheckpoint(
            tenant_id=row["tenant_id"],
            source=row["source"],
            checkpoint_token=row["checkpoint_token"],
            last_event_time=row["last_event_time"],
            updated_at=row["updated_at"],
        )

    async def upsert(
        self,
        tenant_id: UUID,
        source: str,
        checkpoint_token: str,
        last_event_time: datetime | None = None,
        *,
        conn: AsyncConnection | None = None,
    ) -> None:
        async with self._session_for(tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO source_checkpoints (
                    tenant_id, source, checkpoint_token, last_event_time, updated_at
                ) VALUES (%s, %s, %s, %s, now())
                ON CONFLICT (tenant_id, source) DO UPDATE SET
                    checkpoint_token = EXCLUDED.checkpoint_token,
                    last_event_time = EXCLUDED.last_event_time,
                    updated_at = now()
                """,
                (tenant_id, source, checkpoint_token, last_event_time),
            )


class PsycopgIdentityMappingRepository(_BaseRepository):
    async def upsert(
        self, mapping: IdentityMapping, *, conn: AsyncConnection | None = None
    ) -> IdentityMapping:
        async with self._session_for(mapping.tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO identity_mappings (
                    id, tenant_id, source_system, source_identifier, internal_identity_id,
                    confidence, provenance, valid_from, valid_to
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, source_system, source_identifier, valid_from) DO UPDATE SET
                    internal_identity_id = EXCLUDED.internal_identity_id,
                    confidence = EXCLUDED.confidence,
                    provenance = EXCLUDED.provenance,
                    valid_to = EXCLUDED.valid_to
                """,
                (
                    mapping.id,
                    mapping.tenant_id,
                    mapping.source_system,
                    mapping.source_identifier,
                    mapping.internal_identity_id,
                    mapping.confidence,
                    mapping.provenance,
                    mapping.valid_from,
                    mapping.valid_to,
                ),
            )
        return mapping

    async def get(
        self,
        tenant_id: UUID,
        source_system: str,
        source_identifier: str,
        *,
        at: datetime | None = None,
        conn: AsyncConnection | None = None,
    ) -> list[IdentityMapping]:
        when = at if at is not None else datetime.now(tz=UTC)
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT * FROM identity_mappings
                WHERE tenant_id = %s AND source_system = %s AND source_identifier = %s
                  AND valid_from <= %s AND (valid_to IS NULL OR valid_to >= %s)
                ORDER BY valid_from DESC
                """,
                (tenant_id, source_system, source_identifier, when, when),
            )
            rows = await cur.fetchall()
        return [
            IdentityMapping(
                id=r["id"],
                tenant_id=r["tenant_id"],
                source_system=r["source_system"],
                source_identifier=r["source_identifier"],
                internal_identity_id=r["internal_identity_id"],
                confidence=r["confidence"],
                provenance=r["provenance"],
                valid_from=r["valid_from"],
                valid_to=r["valid_to"],
            )
            for r in rows
        ]

    async def list_by_internal(
        self, tenant_id: UUID, internal_identity_id: UUID, *, conn: AsyncConnection | None = None
    ) -> list[IdentityMapping]:
        async with self._session_for(tenant_id, conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM identity_mappings "
                "WHERE tenant_id = %s AND internal_identity_id = %s",
                (tenant_id, internal_identity_id),
            )
            rows = await cur.fetchall()
        return [
            IdentityMapping(
                id=r["id"],
                tenant_id=r["tenant_id"],
                source_system=r["source_system"],
                source_identifier=r["source_identifier"],
                internal_identity_id=r["internal_identity_id"],
                confidence=r["confidence"],
                provenance=r["provenance"],
                valid_from=r["valid_from"],
                valid_to=r["valid_to"],
            )
            for r in rows
        ]


class PsycopgTenantRepository(_BaseRepository):
    """Tenant registry used to provision RLS context and to enumerate tenants."""

    async def ensure(
        self, tenant_id: UUID, *, name: str | None = None, conn: AsyncConnection | None = None
    ) -> None:
        """Idempotently register a tenant (safe to call on every ingestion)."""
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
                (tenant_id, name),
            )

    async def list_tenant_ids(self, *, conn: AsyncConnection | None = None) -> list[UUID]:
        """All tenant ids, oldest-key ordering; used to drive the scoped relay."""
        async with self._session(conn) as c, c.cursor() as cur:
            await cur.execute("SELECT id FROM tenants ORDER BY id")
            rows = await cur.fetchall()
        return [row[0] for row in rows]


class PsycopgRetentionRepository(_BaseRepository):
    """Tenant-scoped retention, legal hold and erasure bookkeeping.

    Never mutates append-only evidence: erasure of raw payloads is recorded as
    a tombstone preserving the integrity hash. Only derived projections are
    deleted.
    """

    async def record_request(
        self, request: ErasureRequest, *, conn: AsyncConnection | None = None
    ) -> ErasureRequest:
        async with self._tenant_session(request.tenant_id, conn) as c:
            await c.execute(
                """
                INSERT INTO erasure_requests (
                    id, tenant_id, requested_by, reason, data_classes, status, requested_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    request.id,
                    request.tenant_id,
                    request.requested_by,
                    request.reason,
                    [str(dc) for dc in request.data_classes],
                    request.status,
                    request.requested_at,
                ),
            )
        return request

    async def complete_request(
        self,
        tenant_id: UUID,
        request_id: UUID,
        *,
        status: str,
        conn: AsyncConnection | None = None,
    ) -> None:
        if status not in {"COMPLETED", "BLOCKED", "FAILED"}:
            raise ValueError("status must be COMPLETED, BLOCKED or FAILED")
        async with self._tenant_session(tenant_id, conn) as c:
            await c.execute(
                """
                UPDATE erasure_requests
                   SET status = %s,
                       completed_at = %s,
                       lease_until = NULL,
                       updated_at = %s
                 WHERE id = %s AND tenant_id = %s
                """,
                (status, _utcnow(), _utcnow(), request_id, tenant_id),
            )

    async def claim_due_requests(
        self,
        tenant_id: UUID,
        *,
        limit: int = 10,
        lease_seconds: float = 60.0,
        conn: AsyncConnection | None = None,
    ) -> list[ErasureRequest]:
        """Atomically claim due requests with a lease (FOR UPDATE SKIP LOCKED).

        A crashed scheduler leaves a PROCESSING row whose lease expires; the
        next run reclaims it. ``attempt_count`` is incremented on every claim,
        so a poison request eventually becomes FAILED instead of looping
        forever.
        """
        lease_until = _utcnow() + timedelta(seconds=lease_seconds)
        async with (
            self._tenant_session(tenant_id, conn) as c,
            c.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                """
                UPDATE erasure_requests
                   SET status = 'PROCESSING',
                       attempt_count = attempt_count + 1,
                       lease_until = %s,
                       updated_at = now()
                 WHERE id IN (
                     SELECT id FROM erasure_requests
                      WHERE tenant_id = %s
                        AND status IN ('REQUESTED', 'PROCESSING')
                        AND next_attempt_at <= now()
                        AND (lease_until IS NULL OR lease_until < now())
                      ORDER BY next_attempt_at, requested_at, id
                      LIMIT %s
                      FOR UPDATE SKIP LOCKED
                 )
                 RETURNING *
                """,
                (lease_until, tenant_id, limit),
            )
            rows = await cur.fetchall()
        return [_erasure_request_from_row(row) for row in rows]

    async def retry_or_fail_request(
        self,
        tenant_id: UUID,
        request_id: UUID,
        *,
        error: str,
        max_attempts: int,
        backoff_seconds: float,
        conn: AsyncConnection | None = None,
    ) -> str:
        """Release a failed claim with backoff, or mark it FAILED at the cap.

        Returns the resulting status so the caller can emit the matching audit
        event. Retry exhaustion is an escalation signal, never a silent
        resolution.
        """
        next_attempt = _utcnow() + timedelta(seconds=backoff_seconds)
        async with self._tenant_session(tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                UPDATE erasure_requests
                   SET status = CASE
                           WHEN attempt_count >= %s THEN 'FAILED'
                           ELSE 'REQUESTED'
                       END,
                       last_error = %s,
                       lease_until = NULL,
                       next_attempt_at = %s,
                       updated_at = now()
                 WHERE id = %s AND tenant_id = %s
                RETURNING status
                """,
                (max_attempts, error[:2000], next_attempt, request_id, tenant_id),
            )
            row = await cur.fetchone()
        if row is None:
            raise LookupError(f"erasure request not found: {request_id}")
        return str(row[0])

    async def get_request(
        self, tenant_id: UUID, request_id: UUID, *, conn: AsyncConnection | None = None
    ) -> ErasureRequest | None:
        async with (
            self._tenant_session(tenant_id, conn) as c,
            c.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                "SELECT * FROM erasure_requests WHERE id = %s AND tenant_id = %s",
                (request_id, tenant_id),
            )
            row = await cur.fetchone()
        return _erasure_request_from_row(row) if row else None

    async def tombstone_raw_evidence(
        self,
        tenant_id: UUID,
        *,
        older_than: datetime,
        erase_request_id: UUID,
        detail: str = "raw payload erased under retention policy",
        conn: AsyncConnection | None = None,
    ) -> int:
        """Record tombstones for raw evidence older than the cutoff.

        Idempotent per (request, record): a second run inserts nothing.
        ``source_events`` itself is never touched (append-only trigger).
        """
        async with self._tenant_session(tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO erasure_tombstones (
                    id, tenant_id, data_class, record_id, integrity_hash, detail,
                    erase_request_id, erased_at
                )
                SELECT gen_random_uuid(), se.tenant_id, %s, se.id, se.payload_hash, %s, %s, now()
                  FROM source_events se
                 WHERE se.tenant_id = %s
                   AND se.observed_at < %s
                   AND se.raw_evidence_reference IS NOT NULL
                   AND NOT EXISTS (
                        SELECT 1 FROM erasure_tombstones t
                         WHERE t.erase_request_id = %s
                           AND t.data_class = %s
                           AND t.record_id = se.id
                   )
                """,
                (
                    DataClass.RAW_EVIDENCE.value,
                    detail,
                    erase_request_id,
                    tenant_id,
                    older_than,
                    erase_request_id,
                    DataClass.RAW_EVIDENCE.value,
                ),
            )
            inserted = cur.rowcount
        return int(inserted)

    async def delete_derived_facts(
        self,
        tenant_id: UUID,
        *,
        older_than: datetime,
        conn: AsyncConnection | None = None,
    ) -> int:
        """Delete rebuildable derived projections older than the cutoff."""
        async with self._tenant_session(tenant_id, conn) as c, c.cursor() as cur:
            await cur.execute(
                "DELETE FROM access_facts WHERE tenant_id = %s AND observed_at < %s",
                (tenant_id, older_than),
            )
            deleted = cur.rowcount
        return int(deleted)

    async def add_tombstone(
        self,
        *,
        tenant_id: UUID,
        data_class: DataClass,
        record_id: UUID | None,
        integrity_hash: str,
        erase_request_id: UUID,
        detail: str | None = None,
        conn: AsyncConnection | None = None,
    ) -> UUID:
        tombstone_id = uuid4()
        async with self._tenant_session(tenant_id, conn) as c:
            await c.execute(
                """
                INSERT INTO erasure_tombstones (
                    id, tenant_id, data_class, record_id, integrity_hash, detail,
                    erase_request_id, erased_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    tombstone_id,
                    tenant_id,
                    data_class.value,
                    record_id,
                    integrity_hash,
                    detail,
                    erase_request_id,
                    _utcnow(),
                ),
            )
        return tombstone_id

    async def list_tombstones(
        self,
        tenant_id: UUID,
        *,
        erase_request_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> list[ErasureTombstone]:
        query = """
            SELECT id, tenant_id, data_class, record_id, integrity_hash, detail,
                   erase_request_id, erased_at
              FROM erasure_tombstones
             WHERE tenant_id = %s
        """
        params: list[object] = [tenant_id]
        if erase_request_id is not None:
            query += " AND erase_request_id = %s"
            params.append(erase_request_id)
        query += " ORDER BY erased_at, id"
        async with (
            self._tenant_session(tenant_id, conn) as c,
            c.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(query, params)
            rows = await cur.fetchall()
        return [
            ErasureTombstone(
                id=row["id"],
                tenant_id=row["tenant_id"],
                data_class=DataClass(row["data_class"]),
                record_id=row["record_id"],
                integrity_hash=row["integrity_hash"],
                detail=row["detail"],
                erase_request_id=row["erase_request_id"],
                erased_at=row["erased_at"],
            )
            for row in rows
        ]

    async def active_holds(
        self, tenant_id: UUID, *, conn: AsyncConnection | None = None
    ) -> list[LegalHold]:
        async with (
            self._tenant_session(tenant_id, conn) as c,
            c.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                """
                SELECT id, tenant_id, data_class, reason, placed_by, placed_at, released_at
                  FROM legal_holds
                 WHERE tenant_id = %s AND released_at IS NULL
                 ORDER BY placed_at
                """,
                (tenant_id,),
            )
            rows = await cur.fetchall()
        return [
            LegalHold(
                id=row["id"],
                tenant_id=row["tenant_id"],
                data_class=DataClass(row["data_class"]) if row["data_class"] else None,
                reason=row["reason"],
                placed_by=row["placed_by"],
                placed_at=row["placed_at"],
                released_at=row["released_at"],
            )
            for row in rows
        ]

    async def effective_policies(
        self, tenant_id: UUID, *, conn: AsyncConnection | None = None
    ) -> tuple[RetentionPolicy, ...]:
        async with (
            self._tenant_session(tenant_id, conn) as c,
            c.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                """
                SELECT tenant_id, data_class, retention_days, on_expiry
                  FROM retention_policies
                 WHERE tenant_id IS NULL OR tenant_id = %s
                 ORDER BY tenant_id NULLS LAST, data_class
                """,
                (tenant_id,),
            )
            rows = await cur.fetchall()
        if not rows:
            return DEFAULT_POLICIES
        return tuple(
            RetentionPolicy(
                tenant_id=row["tenant_id"],
                data_class=DataClass(row["data_class"]),
                retention_days=row["retention_days"],
                on_expiry=ExpiryAction(row["on_expiry"]),
            )
            for row in rows
        )


class RepositoryBundle:
    """All repositories sharing one pool.

    Passing ``tenant_id`` binds every repository to a transaction-local RLS
    context. ``for_tenant`` returns a bound bundle without mutating the
    original, so independent workers cannot share mutable tenant state.
    """

    def __init__(
        self,
        pool: AsyncConnectionPool[AsyncConnection],
        tenant_id: UUID | None = None,
    ) -> None:
        self._pool = pool
        self.tenant_id = tenant_id
        self.incidents = PsycopgIncidentRepository(pool, tenant_id)
        self.inbox = PsycopgInboxRepository(pool, tenant_id)
        self.outbox = PsycopgOutboxRepository(pool, tenant_id)
        self.action_intents = PsycopgActionIntentRepository(pool, tenant_id)
        self.approvals = PsycopgApprovalRepository(pool, tenant_id)
        self.audit = PsycopgAuditRepository(pool, tenant_id)
        self.workflow_state = PsycopgWorkflowStateRepository(pool, tenant_id)
        self.terminal_state = PsycopgTerminalStateRepository(pool, tenant_id)
        self.source_events = PsycopgSourceEventRepository(pool, tenant_id)
        self.source_checkpoints = PsycopgSourceCheckpointRepository(pool, tenant_id)
        self.identity_mappings = PsycopgIdentityMappingRepository(pool, tenant_id)
        self.review_decisions = PsycopgReviewDecisionRepository(pool, tenant_id)
        self.evidence_references = PsycopgEvidenceReferenceRepository(pool, tenant_id)
        self.findings = PsycopgFindingRepository(pool, tenant_id)
        self.processing_records = PsycopgProcessingRecordRepository(pool, tenant_id)
        self.tenants = PsycopgTenantRepository(pool)
        self.retention = PsycopgRetentionRepository(pool, tenant_id)

    def for_tenant(self, tenant_id: UUID) -> RepositoryBundle:
        return RepositoryBundle(self._pool, tenant_id)

    def transaction(self, tenant_id: UUID) -> AbstractAsyncContextManager[AsyncConnection]:
        """Open a transaction-local tenant context for multi-repository work."""
        return tenant_transaction(self._pool, tenant_id)
