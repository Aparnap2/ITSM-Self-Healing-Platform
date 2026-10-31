"""Domain enums and core entities (PRD §5.1, §5.2).

Pure domain: stdlib + pydantic only. No I/O, no LangGraph, no vendor SDKs.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class IncidentStatus(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    REJECTED = "REJECTED"


class WorkflowStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"
    CANCELLED = "CANCELLED"


class ActionType(StrEnum):
    RESTART_SERVICE = "RESTART_SERVICE"
    CLEAR_SIMULATED_CACHE = "CLEAR_SIMULATED_CACHE"
    GRANT_TEST_RESOURCE_ACCESS = "GRANT_TEST_RESOURCE_ACCESS"


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    STAGING = "staging"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyDecisionType(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


#: PRD §5.2 names this enum ``PolicyOutcome``; it is the same type.
PolicyOutcome = PolicyDecisionType


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"


class ActionStatus(StrEnum):
    INTENT_RECORDED = "INTENT_RECORDED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RECONCILED = "RECONCILED"
    CANCELLED = "CANCELLED"


class EvidenceKind(StrEnum):
    HEALTH_CHECK = "HEALTH_CHECK"
    LOG_EXCERPT = "LOG_EXCERPT"
    SERVICE_METADATA = "SERVICE_METADATA"
    ACTION_RESULT = "ACTION_RESULT"
    POSTCONDITION_CHECK = "POSTCONDITION_CHECK"


class EvidenceTrust(StrEnum):
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    SIMULATOR_OBSERVATION = "SIMULATOR_OBSERVATION"
    POLICY_ENGINE = "POLICY_ENGINE"
    INDEPENDENT_VERIFIER = "INDEPENDENT_VERIFIER"


class InboxStatus(StrEnum):
    RECEIVED = "RECEIVED"
    PROCESSING = "PROCESSING"
    PROCESSED = "PROCESSED"
    REJECTED = "REJECTED"
    DEAD_LETTERED = "DEAD_LETTERED"


class StrictModel(BaseModel):
    """Base for all domain contracts: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Incident(StrictModel):
    """Core incident entity (PRD §5.1)."""

    id: UUID
    source_system: str
    source_incident_id: str
    external_event_id: str | None = None
    title: str
    description: str
    service_name: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime
    updated_at: datetime
    correlation_id: UUID
    current_workflow_id: UUID | None = None
    resolution_summary: str | None = None
    audit_reference: str | None = None


class WorkflowRun(StrictModel):
    id: UUID
    incident_id: UUID
    workflow_version: str
    status: WorkflowStatus = WorkflowStatus.PENDING
    current_node: str = "start"
    checkpoint_ref: str | None = None
    attempt_count: int = 0
    started_at: datetime
    updated_at: datetime
    finished_at: datetime | None = None
    correlation_id: UUID
    last_error_code: str | None = None


class Evidence(StrictModel):
    id: UUID
    incident_id: UUID
    workflow_id: UUID
    kind: EvidenceKind
    source: str
    observed_at: datetime
    content_hash: str
    sanitized_summary: str
    external_ref: str | None = None
    trust_level: EvidenceTrust


class PolicyDecisionRecord(StrictModel):
    id: UUID
    incident_id: UUID
    workflow_id: UUID
    principal_id: str
    resource_id: str
    action_type: ActionType
    decision: PolicyOutcome
    reason_codes: list[str] = Field(min_length=1)
    policy_version: str
    evaluated_at: datetime
    proposal_hash: str


class ApprovalRequestRecord(StrictModel):
    id: UUID
    incident_id: UUID
    workflow_id: UUID
    proposal_hash: str
    action_type: ActionType
    resource_id: str
    parameters_hash: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    approver_id: str | None = None
    decision_reason: str | None = None
    replay_nonce_hash: str | None = None


class ActionAttemptRecord(StrictModel):
    id: UUID
    incident_id: UUID
    workflow_id: UUID
    action_type: ActionType
    resource_id: str
    idempotency_key: str
    proposal_hash: str
    status: ActionStatus = ActionStatus.INTENT_RECORDED
    attempt_number: int = 1
    intent_recorded_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    adapter_name: str
    result_code: str | None = None
    result_summary: str | None = None
    result_evidence_id: UUID | None = None


class VerificationRecord(StrictModel):
    id: UUID
    incident_id: UUID
    action_attempt_id: UUID
    predicate: str
    passed: bool
    observed_state: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    evidence_id: UUID
    verified_at: datetime
    verifier_version: str


class AuditEventRecord(StrictModel):
    id: UUID
    occurred_at: datetime
    correlation_id: UUID
    incident_id: UUID | None = None
    workflow_id: UUID | None = None
    actor_type: str
    actor_id: str
    event_type: str
    entity_type: str | None = None
    entity_id: UUID | None = None
    payload_redacted: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    previous_hash: str | None = None
    event_hash: str | None = None


class InboxEventRecord(StrictModel):
    id: UUID
    tenant_id: UUID | None = None
    source_system: str
    external_event_id: str
    payload_hash: str
    received_at: datetime
    status: InboxStatus = InboxStatus.RECEIVED
    attempt_count: int = 0
    last_error: str | None = None


class OutboxEventRecord(StrictModel):
    id: UUID
    tenant_id: UUID | None = None
    event_type: str
    aggregate_id: UUID
    payload: dict[str, object]
    created_at: datetime
    published_at: datetime | None = None
    publish_attempts: int = 0
    last_error: str | None = None


class IdentityMapping(StrictModel):
    """Source-to-internal identity mapping with provenance and validity."""

    id: UUID
    tenant_id: UUID
    source_system: str
    source_identifier: str
    internal_identity_id: UUID
    confidence: Literal["HIGH", "MEDIUM", "LOW", "UNRESOLVED"] = "MEDIUM"
    provenance: str
    valid_from: datetime
    valid_to: datetime | None = None


class AccessFact(StrictModel):
    """Rebuildable normalized access fact derived from source events."""

    id: UUID
    tenant_id: UUID
    source_event_id: UUID
    principal_id: str | None = None
    resource_id: str | None = None
    action: str
    permission_context: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    granted_at: datetime | None = None
    observed_at: datetime
    fact_hash: str


class ApprovalEvidence(StrictModel):
    """Approval evidence considered by deterministic detection (Task 12.8).

    Flexible input contract: fields accept the common naming variants used by
    approval stores (approver/approver_id, action/action_type, resource/target,
    valid_from/issued_at/requested_at, valid_to/expires_at, status/decision).
    Unknown fields are ignored so callers can pass richer records.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    approver_id: str | None = None
    approver: str | None = None
    action: str | None = None
    action_type: str | None = None
    event_type: str | None = None
    resource_id: str | None = None
    resource: str | None = None
    target: str | None = None
    target_id: str | None = None
    scope: dict[str, object] = Field(default_factory=dict)
    parameters: dict[str, object] = Field(default_factory=dict)
    context: dict[str, object] = Field(default_factory=dict)
    status: str = "APPROVED"
    decision: str | None = None
    outcome: str | None = None
    actor_id: str | None = None
    subject: str | None = None
    principal_id: str | None = None
    valid_from: datetime | None = None
    valid_from_at: datetime | None = None
    issued_at: datetime | None = None
    requested_at: datetime | None = None
    created_at: datetime | None = None
    decided_at: datetime | None = None
    valid_to: datetime | None = None
    valid_until: datetime | None = None
    expires_at: datetime | None = None
    expiry: datetime | None = None
    source: str = "approval-system"
    provenance: str = "approval record"

    def resolved_approver(self) -> str | None:
        return self.approver_id or self.approver

    def resolved_action(self) -> str | None:
        return self.action or self.action_type or self.event_type

    def resolved_resource(self) -> str | None:
        return self.resource_id or self.resource or self.target or self.target_id

    def resolved_actor(self) -> str | None:
        return self.actor_id or self.subject or self.principal_id

    def resolved_status(self) -> str:
        raw = (self.status or self.decision or self.outcome or "APPROVED").upper()
        return raw

    def resolved_valid_from(self) -> datetime | None:
        return (
            self.valid_from
            or self.valid_from_at
            or self.issued_at
            or self.requested_at
            or self.created_at
            or self.decided_at
        )

    def resolved_valid_to(self) -> datetime | None:
        return self.valid_to or self.valid_until or self.expires_at or self.expiry


class Finding(StrictModel):
    """Deterministic detection result with evidence linkage."""

    id: UUID
    tenant_id: UUID
    finding_type: str
    severity: Severity
    status: str = "OPEN"
    title: str
    description: str
    detected_at: datetime
    rule_version: str
    risk_score: int = 0
    outcome: str  # VIOLATION | SUSPICIOUS | COVERAGE_GAP | INCONCLUSIVE


class EvidenceReference(StrictModel):
    """Link between a finding and its supporting evidence."""

    id: UUID
    finding_id: UUID
    source_event_id: UUID | None = None
    access_fact_id: UUID | None = None
    content_hash: str
    excerpt: str | None = None
    trust_level: str
    collected_at: datetime


class CoverageStatus(StrictModel):
    """Source coverage monitoring state."""

    id: UUID
    tenant_id: UUID
    source: str
    last_event_time: datetime | None = None
    expected_cadence_seconds: int | None = None
    status: str = "UNKNOWN"
