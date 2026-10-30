"""Psycopg 3 async repository implementations (Phase 3).

Contract notes:
- All methods are async and typed; domain models cross the boundary (no raw dicts).
- ``conn=`` allows a caller to compose several writes into ONE transaction —
  required for the fail-closed audit contract and transactional outbox.
- Without ``conn``, each method runs in its own pooled transaction.
- ``DuplicateIdempotencyKeyError`` / ``ApprovalNotPendingError`` fail closed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from itsm_agent.ports.repositories import (
    ActionIntent,
    ApprovalNotPendingError,
    ApprovalRequest,
    AuditEvent,
    InboxEvent,
    InboxReceipt,
    Incident,
    OutboxEvent,
    TerminalStateConflictError,
    WorkflowState,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _BaseRepository:
    def __init__(self, pool: AsyncConnectionPool[AsyncConnection]) -> None:
        self._pool = pool

    @asynccontextmanager
    async def _session(self, conn: AsyncConnection | None) -> AsyncIterator[AsyncConnection]:
        if conn is not None:
            yield conn
        else:
            async with self._pool.connection() as pooled, pooled.transaction():
                yield pooled


class PsycopgIncidentRepository(_BaseRepository):
    async def create(self, incident: Incident, *, conn: AsyncConnection | None = None) -> Incident:
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    INSERT INTO incidents (
                        id, source_system, source_incident_id, external_event_id,
                        title, description, service_name, severity, status,
                        created_at, updated_at, correlation_id, current_workflow_id,
                        resolution_summary, audit_reference
                    ) VALUES (
                        %(id)s, %(source_system)s, %(source_incident_id)s,
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
        conn: AsyncConnection | None = None,
    ) -> InboxReceipt:
        """Dedup gate: INSERT ... ON CONFLICT DO NOTHING on the unique
        (source_system, external_event_id) constraint. Concurrent duplicates
        race on the constraint, so exactly one caller sees NEW."""
        async with self._session(conn) as c, c.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO event_inbox (id, source_system, external_event_id, payload_hash, status)
                VALUES (%s, %s, %s, %s, 'RECEIVED')
                ON CONFLICT (source_system, external_event_id) DO NOTHING
                """,
                (uuid4(), source_system, external_event_id, payload_hash),
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
                INSERT INTO outbox (id, event_type, aggregate_id, payload, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    event.id,
                    event.event_type,
                    event.aggregate_id,
                    Jsonb(event.payload),
                    event.created_at,
                ),
            )
        return event

    async def claim_pending(
        self, limit: int = 10, *, lease_seconds: float = 60.0, conn: AsyncConnection | None = None
    ) -> list[OutboxEvent]:
        """Claim pending rows with FOR UPDATE SKIP LOCKED (multi-relay safe).
        Claim bumps attempts and pushes next_attempt_at forward as a lease so
        a crashed relay's rows become claimable again after the lease expires."""
        lease_until = _utcnow() + timedelta(seconds=lease_seconds)
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                    UPDATE outbox SET attempts = attempts + 1, next_attempt_at = %(lease)s
                    WHERE id IN (
                        SELECT id FROM outbox
                        WHERE status = 'pending' AND next_attempt_at <= now()
                        ORDER BY created_at, id
                        LIMIT %(limit)s
                        FOR UPDATE SKIP LOCKED
                    )
                    RETURNING *
                    """,
                {"lease": lease_until, "limit": limit},
            )
            rows = await cur.fetchall()
        return [OutboxEvent.model_validate(r) for r in rows]

    async def mark_published(
        self, outbox_event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> None:
        """Call ONLY after broker acknowledgement (ADR-0002)."""
        async with self._session(conn) as c:  # noqa: SIM117
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
        conn: AsyncConnection | None = None,
    ) -> None:
        next_at = _utcnow() + timedelta(seconds=backoff_seconds)
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                UPDATE outbox
                SET last_error = %s, next_attempt_at = %s,
                    status = CASE WHEN attempts >= %s THEN 'failed' ELSE 'pending' END
                WHERE id = %s
                """,
                (error[:2000], next_at, max_attempts, outbox_event_id),
            )

    async def count_pending(self, *, conn: AsyncConnection | None = None) -> int:
        async with self._session(conn) as c, c.cursor() as cur:
            await cur.execute("SELECT count(*) FROM outbox WHERE status = 'pending'")
            row = await cur.fetchone()
        return int(row[0]) if row else 0


class PsycopgActionIntentRepository(_BaseRepository):
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
                        id, incident_id, workflow_id, action_type, resource_id,
                        idempotency_key, proposal_hash, status, attempt_number,
                        intent_recorded_at, adapter_name
                    ) VALUES (
                        %(id)s, %(incident_id)s, %(workflow_id)s, %(action_type)s,
                        %(resource_id)s, %(idempotency_key)s, %(proposal_hash)s,
                        %(status)s, %(attempt_number)s, %(intent_recorded_at)s,
                        %(adapter_name)s
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
    async def create(
        self, approval: ApprovalRequest, *, conn: AsyncConnection | None = None
    ) -> ApprovalRequest:
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO approvals (
                    id, incident_id, workflow_id, proposal_hash, action_type,
                    resource_id, parameters_hash, status, requested_at, expires_at,
                    replay_nonce_hash
                ) VALUES (
                    %(id)s, %(incident_id)s, %(workflow_id)s, %(proposal_hash)s,
                    %(action_type)s, %(resource_id)s, %(parameters_hash)s, %(status)s,
                    %(requested_at)s, %(expires_at)s, %(replay_nonce_hash)s
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
    async def append(self, event: AuditEvent, *, conn: AsyncConnection | None = None) -> AuditEvent:
        """Append-only (DB trigger rejects UPDATE/DELETE).

        Fail-closed contract: pass ``conn`` to write the audit record in the
        SAME transaction as the side effect it witnesses. If this insert
        fails, the shared transaction rolls back and the side effect never
        commits. Callers that cannot share a transaction must append the
        audit record BEFORE the side effect and abort on failure.
        """
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO audit_events (
                    id, occurred_at, correlation_id, incident_id, workflow_id,
                    actor_type, actor_id, event_type, entity_type, entity_id,
                    payload_redacted, previous_hash, event_hash
                ) VALUES (
                    %(id)s, %(occurred_at)s, %(correlation_id)s, %(incident_id)s,
                    %(workflow_id)s, %(actor_type)s, %(actor_id)s, %(event_type)s,
                    %(entity_type)s, %(entity_id)s, %(payload_redacted)s,
                    %(previous_hash)s, %(event_hash)s
                )
                """,
                {
                    **event.model_dump(),
                    "payload_redacted": Jsonb(event.payload_redacted),
                },
            )
        return event


class PsycopgWorkflowStateRepository(_BaseRepository):
    async def create(
        self, state: WorkflowState, *, conn: AsyncConnection | None = None
    ) -> WorkflowState:
        async with self._session(conn) as c:  # noqa: SIM117
            await c.execute(
                """
                INSERT INTO workflow_state (
                    id, incident_id, workflow_version, status, current_node,
                    checkpoint_ref, attempt_count, started_at, updated_at,
                    correlation_id
                ) VALUES (
                    %(id)s, %(incident_id)s, %(workflow_version)s, %(status)s,
                    %(current_node)s, %(checkpoint_ref)s, %(attempt_count)s,
                    %(started_at)s, %(updated_at)s, %(correlation_id)s
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


class RepositoryBundle:
    """All repositories sharing one pool."""

    def __init__(self, pool: AsyncConnectionPool[AsyncConnection]) -> None:
        self.incidents = PsycopgIncidentRepository(pool)
        self.inbox = PsycopgInboxRepository(pool)
        self.outbox = PsycopgOutboxRepository(pool)
        self.action_intents = PsycopgActionIntentRepository(pool)
        self.approvals = PsycopgApprovalRepository(pool)
        self.audit = PsycopgAuditRepository(pool)
        self.workflow_state = PsycopgWorkflowStateRepository(pool)
        self.terminal_state = PsycopgTerminalStateRepository(pool)
