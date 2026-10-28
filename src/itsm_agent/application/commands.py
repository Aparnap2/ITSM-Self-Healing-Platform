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
    deadline_seconds: float = 120.0
    approval_lifetime_seconds: float = 900.0


@dataclass(frozen=True)
class WorkflowDeps:
    """Everything a workflow node needs, injected. No global state."""

    model: ModelPort
    diagnostics: DiagnosticsPort
    executor: ExecutorPort
    verifier: VerifierPort
    approvals: ApprovalPort
    audit: AuditPort
    clock: Clock
    limits: ExecutionLimits
    policy_snapshot: PolicySnapshot
