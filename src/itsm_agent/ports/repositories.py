"""Repository ports (Phase 3, pinned for this build).

These protocols are the persistence boundary contract. Other agents depend
on the method signatures defined here — changes require an ADR.

Domain types: repositories return typed domain models from
``itsm_agent.domain.models`` (PRD §5.1/§6 field names). That module is being
created by a parallel agent; until it lands, typed fallback models defined
below are used. The import is defensive so this package works either way.

Fail-closed audit contract (PRD invariant 9 / FR-10):
``AuditRepository.append`` MUST be callable with the same database
transaction as the side effect it witnesses (pass ``conn=``). If the audit
write fails, the surrounding transaction rolls back and no side effect
proceeds. Callers that cannot share a transaction must write the audit
record BEFORE the side effect and treat audit failure as an abort.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from psycopg import AsyncConnection

# ---------------------------------------------------------------------------
# Domain model resolution. The domain module (parallel agent) landed with
# suffixed record names; they are aliased here to the port-level names used
# across this build. OutboxEvent is defined locally: the domain
# OutboxEventRecord lacks the queue fields (status/attempts/next_attempt_at)
# pinned by the Phase 3 deliverable — drift noted for the domain owner.
# ---------------------------------------------------------------------------
from itsm_agent.domain.events import SourceEvent
from itsm_agent.domain.models import (  # noqa: E402
    ActionAttemptRecord as ActionIntent,
)
from itsm_agent.domain.models import (
    ApprovalRequestRecord as ApprovalRequest,
)
from itsm_agent.domain.models import (
    AuditEventRecord as AuditEvent,
)
from itsm_agent.domain.models import (
    InboxEventRecord as InboxEvent,
)
from itsm_agent.domain.models import (
    Incident,
)
from itsm_agent.domain.models import (
    WorkflowRun as WorkflowState,
)


class OutboxEvent(BaseModel):
    """Outbox row model (queue fields per Phase 3 deliverable / ADR-0002)."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    event_type: str
    aggregate_id: UUID
    tenant_id: UUID | None = None
    payload: dict[str, object]
    created_at: datetime
    published_at: datetime | None = None
    attempts: int = 0
    last_error: str | None = None
    status: str = "pending"
    next_attempt_at: datetime | None = None


class InboxReceipt(StrEnum):
    """Result of an inbox dedup check."""

    NEW = "NEW"
    DUPLICATE = "DUPLICATE"


class DuplicateIdempotencyKeyError(RuntimeError):
    """An action intent with this idempotency key already exists.

    This is the durable guard against duplicate side effects: the caller
    must treat the existing intent as authoritative and not re-execute.
    """


class ApprovalNotPendingError(RuntimeError):
    """A decision was attempted on an approval that is not PENDING.

    Enforces single-use approvals (FR-06): only the first authenticated
    decision on a PENDING request is accepted; replays fail closed.
    """


@runtime_checkable
class IncidentRepository(Protocol):
    async def create(
        self, incident: Incident, *, conn: AsyncConnection | None = None
    ) -> Incident: ...
    async def get(
        self, incident_id: UUID, *, conn: AsyncConnection | None = None
    ) -> Incident | None: ...
    async def find_by_source(
        self, source_system: str, source_incident_id: str, *, conn: AsyncConnection | None = None
    ) -> Incident | None: ...
    async def find_by_external_event(
        self, source_system: str, external_event_id: str, *, conn: AsyncConnection | None = None
    ) -> Incident | None: ...
    async def update_status(
        self,
        incident_id: UUID,
        status: str,
        *,
        resolution_summary: str | None = None,
        audit_reference: str | None = None,
        current_workflow_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> Incident: ...


@runtime_checkable
class InboxRepository(Protocol):
    async def try_record(
        self,
        *,
        source_system: str,
        external_event_id: str,
        payload_hash: str,
        conn: AsyncConnection | None = None,
    ) -> InboxReceipt: ...
    async def get(
        self, source_system: str, external_event_id: str, *, conn: AsyncConnection | None = None
    ) -> InboxEvent | None: ...
    async def mark_processed(
        self, inbox_event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> None: ...
    async def mark_failed(
        self, inbox_event_id: UUID, error: str, *, conn: AsyncConnection | None = None
    ) -> None: ...


@runtime_checkable
class OutboxRepository(Protocol):
    async def append(
        self,
        *,
        event_type: str,
        aggregate_id: UUID,
        payload: dict[str, object],
        conn: AsyncConnection | None = None,
    ) -> OutboxEvent: ...
    async def claim_pending(
        self, limit: int = 10, *, lease_seconds: float = 60.0, conn: AsyncConnection | None = None
    ) -> list[OutboxEvent]: ...
    async def mark_published(
        self, outbox_event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> None: ...
    async def mark_failed(
        self,
        outbox_event_id: UUID,
        error: str,
        *,
        backoff_seconds: float = 5.0,
        max_attempts: int = 10,
        conn: AsyncConnection | None = None,
    ) -> None: ...
    async def count_pending(self, *, conn: AsyncConnection | None = None) -> int: ...


@runtime_checkable
class ActionIntentRepository(Protocol):
    async def record(
        self, intent: ActionIntent, *, conn: AsyncConnection | None = None
    ) -> ActionIntent:
        """Persist intent BEFORE any side effect. Raises
        DuplicateIdempotencyKeyError if the key exists (fail closed)."""

    async def get_by_idempotency_key(
        self, idempotency_key: str, *, conn: AsyncConnection | None = None
    ) -> ActionIntent | None: ...
    async def mark_result(
        self,
        idempotency_key: str,
        *,
        status: str,
        result_code: str | None = None,
        result_summary: str | None = None,
        result_evidence_id: UUID | None = None,
        conn: AsyncConnection | None = None,
    ) -> ActionIntent: ...


@runtime_checkable
class ApprovalRepository(Protocol):
    async def create(
        self, approval: ApprovalRequest, *, conn: AsyncConnection | None = None
    ) -> ApprovalRequest: ...
    async def get(
        self, approval_id: UUID, *, conn: AsyncConnection | None = None
    ) -> ApprovalRequest | None: ...
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
        """Single-use: only valid from status PENDING, else raises
        ApprovalNotPendingError (replay/expiry fail closed)."""


@runtime_checkable
class AuditRepository(Protocol):
    async def append(self, event: AuditEvent, *, conn: AsyncConnection | None = None) -> AuditEvent:
        """Append-only. Fail-closed contract: pass ``conn`` to join the
        transaction of the side effect being witnessed; if this write fails,
        that transaction must roll back so no side effect proceeds."""


@runtime_checkable
class WorkflowStateRepository(Protocol):
    async def create(
        self, state: WorkflowState, *, conn: AsyncConnection | None = None
    ) -> WorkflowState: ...
    async def get(
        self, workflow_id: UUID, *, conn: AsyncConnection | None = None
    ) -> WorkflowState | None: ...
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
    ) -> WorkflowState: ...


class TerminalStateConflictError(RuntimeError):
    """A terminal workflow/incident transition was rejected.

    Raised when the workflow run is already finished or the incident already
    holds a terminal status. Duplicate, concurrent, or stale deliveries are
    rejected instead of silently overwriting committed business state.
    """


@runtime_checkable
class TerminalStateRepository(Protocol):
    """Atomic terminal transition for a workflow run and its incident.

    A single transaction owns both writes and row-locks both aggregates so a
    failure at any point leaves neither side committed. This is the only
    supported way to move a workflow into a terminal status.
    """

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
    ) -> None: ...


__all__ = [
    "OutboxEvent",
    "InboxReceipt",
    "DuplicateIdempotencyKeyError",
    "ApprovalNotPendingError",
    "TerminalStateConflictError",
    "TerminalStateRepository",
    "IncidentRepository",
    "InboxRepository",
    "OutboxRepository",
    "ActionIntentRepository",
    "ApprovalRepository",
    "AuditRepository",
    "WorkflowStateRepository",
    "ActionIntent",
    "ApprovalRequest",
    "AuditEvent",
    "InboxEvent",
    "Incident",
    "WorkflowState",
]


class SourceCheckpoint(BaseModel):
    """Mutable ingestion checkpoint (per tenant/source)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    source: str
    checkpoint_token: str
    last_event_time: datetime | None = None
    updated_at: datetime


@runtime_checkable
class SourceEventRepository(Protocol):
    async def insert(
        self, event: SourceEvent, *, conn: AsyncConnection | None = None
    ) -> SourceEvent: ...
    async def get(
        self, event_id: UUID, *, conn: AsyncConnection | None = None
    ) -> SourceEvent | None: ...
    async def get_by_idempotency(
        self, tenant_id: UUID, idempotency_key: str, *, conn: AsyncConnection | None = None
    ) -> SourceEvent | None: ...


@runtime_checkable
class SourceCheckpointRepository(Protocol):
    async def get(
        self, tenant_id: UUID, source: str, *, conn: AsyncConnection | None = None
    ) -> SourceCheckpoint | None: ...
    async def upsert(
        self,
        tenant_id: UUID,
        source: str,
        checkpoint_token: str,
        last_event_time: datetime | None = None,
        *,
        conn: AsyncConnection | None = None,
    ) -> None: ...
