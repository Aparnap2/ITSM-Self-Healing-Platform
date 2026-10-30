"""Pydantic trust-boundary contracts (PRD §6).

Every contract uses ``extra="forbid"`` and is validated at trust
boundaries: external events, LLM output, approvals, tool inputs.
Pure domain: stdlib + pydantic only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=240)]
SafeIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


def ensure_utc(value: datetime) -> datetime:
    """Normalize a timestamp to timezone-aware UTC at the boundary."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# 6.1 Incident event
# ---------------------------------------------------------------------------


class IncidentCreated(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    source_system: SafeIdentifier
    source_incident_id: SafeIdentifier
    external_event_id: SafeIdentifier
    occurred_at: datetime
    received_at: datetime | None = None
    correlation_id: UUID
    title: ShortText
    description: Annotated[str, StringConstraints(max_length=8000)]
    service_name: SafeIdentifier
    severity: Literal["P1", "P2", "P3", "P4"]
    environment: Literal["local", "test", "staging"]


# ---------------------------------------------------------------------------
# 6.3 Diagnostic evidence
# ---------------------------------------------------------------------------


class DiagnosticObservation(StrictModel):
    evidence_id: UUID
    source: SafeIdentifier
    kind: Literal["HEALTH_CHECK", "LOG_EXCERPT", "SERVICE_METADATA"]
    observed_at: datetime
    content_hash: Sha256Hex
    sanitized_summary: Annotated[str, StringConstraints(max_length=2000)]
    structured_facts: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=30
    )
    trust_level: Literal["UNTRUSTED_EXTERNAL", "SIMULATOR_OBSERVATION"]


# ---------------------------------------------------------------------------
# 6.4 Action proposals (discriminated union)
# ---------------------------------------------------------------------------


class RestartServiceParameters(StrictModel):
    action_type: Literal["RESTART_SERVICE"]
    service_name: SafeIdentifier
    environment: Literal["local", "test", "staging"]
    reason: Annotated[str, StringConstraints(max_length=500)]
    evidence_ids: list[UUID] = Field(min_length=1, max_length=10)


class ClearCacheParameters(StrictModel):
    action_type: Literal["CLEAR_SIMULATED_CACHE"]
    service_name: SafeIdentifier
    environment: Literal["local", "test", "staging"]
    reason: Annotated[str, StringConstraints(max_length=500)]
    evidence_ids: list[UUID] = Field(min_length=1, max_length=10)


class GrantTestAccessParameters(StrictModel):
    action_type: Literal["GRANT_TEST_RESOURCE_ACCESS"]
    principal_id: SafeIdentifier
    resource_id: SafeIdentifier
    environment: Literal["local", "test"]
    ticket_reference: SafeIdentifier


ActionProposal = Annotated[
    RestartServiceParameters | ClearCacheParameters | GrantTestAccessParameters,
    Field(discriminator="action_type"),
]

ACTION_PROPOSAL_ADAPTER: TypeAdapter[ActionProposal] = TypeAdapter(ActionProposal)  # type: ignore[arg-type]


def parse_action_proposal(raw: object) -> ActionProposal:
    """Validate untrusted input into a typed action proposal (fail closed)."""
    return ACTION_PROPOSAL_ADAPTER.validate_python(raw)


# ---------------------------------------------------------------------------
# 6.5 Policy decision
# ---------------------------------------------------------------------------


class PolicyDecisionResult(StrictModel):
    decision_id: UUID
    outcome: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    action_type: SafeIdentifier
    resource_id: SafeIdentifier
    principal_id: SafeIdentifier
    policy_version: SafeIdentifier
    reason_codes: list[SafeIdentifier] = Field(min_length=1, max_length=20)
    proposal_hash: Sha256Hex
    evaluated_at: datetime


# ---------------------------------------------------------------------------
# 6.6 Approval
# ---------------------------------------------------------------------------


class ApprovalRequestContract(StrictModel):
    approval_id: UUID
    incident_id: UUID
    workflow_id: UUID
    proposal_hash: Sha256Hex
    action_type: SafeIdentifier
    resource_id: SafeIdentifier
    parameters_hash: Sha256Hex
    requested_at: datetime
    expires_at: datetime
    status: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "INVALIDATED"]


class ApprovalDecision(StrictModel):
    approval_id: UUID
    decision: Literal["APPROVE", "REJECT"]
    approver_id: SafeIdentifier
    decided_at: datetime
    nonce: Annotated[str, StringConstraints(min_length=16, max_length=256)]
    reason: Annotated[str, StringConstraints(max_length=1000)]


# ---------------------------------------------------------------------------
# 6.7 Tool result and verification
# ---------------------------------------------------------------------------


class ToolResult(StrictModel):
    action_attempt_id: UUID
    idempotency_key: SafeIdentifier
    status: Literal["SUCCEEDED", "FAILED", "OUTCOME_UNKNOWN"]
    result_code: SafeIdentifier
    summary: Annotated[str, StringConstraints(max_length=1500)]
    observed_at: datetime
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=20)
    #: Only a ``FAILED`` result the adapter can prove did not execute may be
    #: retried (PRD §6.5 action contract). Never set for OUTCOME_UNKNOWN.
    retryable: bool = False


class ReconciliationResult(StrictModel):
    """Outcome of querying authoritative target state after an uncertain action.

    ``APPLIED``     — the intended postcondition is present; do not re-execute.
    ``NOT_APPLIED`` — evidence proves the mutation did not occur; a policy-
                      checked retry may be considered.
    ``INCONCLUSIVE``— evidence is unavailable, stale, or contradictory; never
                      authorizes a retry or a resolution.
    """

    reconciliation_id: UUID
    action_attempt_id: UUID
    idempotency_key: SafeIdentifier
    outcome: Literal["APPLIED", "NOT_APPLIED", "INCONCLUSIVE"]
    result_code: SafeIdentifier
    observed_state: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=50
    )
    evidence_hash: Sha256Hex
    observed_at: datetime
    reconciler_version: SafeIdentifier


class VerificationResult(StrictModel):
    verification_id: UUID
    incident_id: UUID
    action_attempt_id: UUID
    predicate: SafeIdentifier
    passed: bool
    observed_state: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=50
    )
    evidence_id: UUID
    verified_at: datetime
    verifier_version: SafeIdentifier


# ---------------------------------------------------------------------------
# 6.8 Audit event
# ---------------------------------------------------------------------------


class AuditEvent(StrictModel):
    event_id: UUID
    occurred_at: datetime
    correlation_id: UUID
    incident_id: UUID | None = None
    workflow_id: UUID | None = None
    actor_type: Literal["SYSTEM", "WORKER", "POLICY", "APPROVER", "ADAPTER", "VERIFIER"]
    actor_id: SafeIdentifier
    event_type: SafeIdentifier
    entity_type: SafeIdentifier | None = None
    entity_id: UUID | None = None
    payload_redacted: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=50
    )


# ---------------------------------------------------------------------------
# 6.9 Canonical event envelope
# ---------------------------------------------------------------------------


class EventEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    event_type: SafeIdentifier
    occurred_at: datetime
    producer: SafeIdentifier
    correlation_id: UUID
    causation_id: UUID | None = None
    payload: dict[str, object]
