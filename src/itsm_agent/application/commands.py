"""Injected dependencies for the LangGraph workflow (PRD §3.2, ADR-0001).

Nodes depend on Protocols and callables only; concrete adapters are wired
in the composition root. Unit tests supply in-memory fakes — no DB, no
NATS, no HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from itsm_agent.domain.events import (
    ApprovalDecision,
    ApprovalRequestContract,
    AuditEvent,
    DiagnosticObservation,
    IncidentCreated,
    ReconciliationResult,
    ToolResult,
    VerificationResult,
)
from itsm_agent.domain.policies import PolicySnapshot
from itsm_agent.ports.model import ModelPort


@runtime_checkable
class DiagnosticsPort(Protocol):
    """Bounded, read-only diagnostic evidence collection."""

    async def collect(
        self, incident: IncidentCreated, max_calls: int
    ) -> list[DiagnosticObservation]: ...


@runtime_checkable
class ExecutorPort(Protocol):
    """Allowlisted adapter execution. Rejects unknown action types."""

    async def execute(self, proposal: object, idempotency_key: str) -> ToolResult: ...


@runtime_checkable
class VerifierPort(Protocol):
    """Independent postcondition verification via a read-only path."""

    async def verify(self, incident_id: UUID, action_attempt_id: UUID) -> VerificationResult: ...


@runtime_checkable
class ReconcilerPort(Protocol):
    """Authoritative target-state reconciliation for uncertain actions.

    Must not return ``APPLIED`` or ``NOT_APPLIED`` without fresh evidence.
    """

    async def reconcile(
        self,
        proposal: object,
        *,
        idempotency_key: str,
        action_attempt_id: UUID,
    ) -> ReconciliationResult: ...


@runtime_checkable
class IntentStorePort(Protocol):
    """Durable action-intent store (rule 10: intent before side effect)."""

    async def record_intent(
        self,
        *,
        incident_id: UUID,
        workflow_id: UUID,
        action_type: str,
        resource_id: str,
        idempotency_key: str,
        proposal_hash: str,
        adapter_name: str,
        attempt_number: int,
        recorded_at: datetime,
    ) -> tuple[str, int]:
        """Persist intent. Returns (durable status, attempt_number).

        Replaying the same idempotency key returns the existing row without
        overwriting it, so a crashed attempt resumes from durable state.
        """

    async def mark_outcome(
        self,
        *,
        idempotency_key: str,
        status: str,
        result_code: str | None = None,
        result_summary: str | None = None,
    ) -> None: ...


@runtime_checkable
class ApprovalPort(Protocol):
    """Durable approval requests bound to exact proposal hashes."""

    async def create_request(
        self,
        incident_id: UUID,
        workflow_id: UUID,
        proposal_hash: str,
        action_type: str,
        resource_id: str,
        parameters_hash: str,
        requested_at: datetime,
        expires_at: datetime,
    ) -> ApprovalRequestContract: ...

    async def get_decision(self, approval_id: UUID) -> ApprovalDecision | None: ...


@runtime_checkable
class AuditPort(Protocol):
    """Append-only audit sink."""

    async def append(self, event: AuditEvent) -> None: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True)
class ExecutionLimits:
    """Bounded execution budgets (PRD §3.4). Enforced in code, tested."""

    max_model_attempts: int = 3
    max_tool_calls: int = 8
    max_action_attempts: int = 1
    #: Bounded reconciliation passes before an uncertain outcome escalates.
    max_reconciliation_attempts: int = 2
    deadline_seconds: float = 120.0
    approval_lifetime_seconds: float = 900.0


@dataclass(frozen=True)
class WorkflowDeps:
    """Everything a workflow node needs, injected. No global state."""

    model: ModelPort
    diagnostics: DiagnosticsPort
    executor: ExecutorPort
    verifier: VerifierPort
    reconciler: ReconcilerPort
    intents: IntentStorePort
    approvals: ApprovalPort
    audit: AuditPort
    clock: Clock
    limits: ExecutionLimits
    policy_snapshot: PolicySnapshot
