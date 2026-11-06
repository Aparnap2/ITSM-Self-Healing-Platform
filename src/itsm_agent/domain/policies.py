"""Deterministic, deny-by-default policy engine (PRD §8, ADR-0005).

Pure function of (proposal, context, policy snapshot) -> PolicyDecisionResult.
No LLM, no network, no database, no mutable global state. Unknown
action/target/principal/environment fails closed with an explicit reason
code. A model's confidence can never convert a denial into an allow.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from itsm_agent.domain.events import (
    ActionProposal,
    ClearCacheParameters,
    GrantTestAccessParameters,
    PolicyDecisionResult,
    RestartServiceParameters,
    SafeIdentifier,
    StrictModel,
)
from itsm_agent.domain.models import ActionType, Environment, PolicyDecisionType

# ---------------------------------------------------------------------------
# Reason codes (stable, machine-readable, audited)
# ---------------------------------------------------------------------------


class ReasonCode:
    ALLOW_RESTART_LOCAL_TEST = "ALLOW_RESTART_LOCAL_TEST"
    ALLOW_CLEAR_CACHE_LOCAL_TEST = "ALLOW_CLEAR_CACHE_LOCAL_TEST"
    ALLOW_APPROVAL_SATISFIED = "ALLOW_APPROVAL_SATISFIED"
    APPROVAL_REQUIRED_STAGING_RESTART = "APPROVAL_REQUIRED_STAGING_RESTART"
    APPROVAL_REQUIRED_TEST_ACCESS = "APPROVAL_REQUIRED_TEST_ACCESS"
    DENY_UNKNOWN_ACTION_TYPE = "DENY_UNKNOWN_ACTION_TYPE"
    DENY_UNKNOWN_ENVIRONMENT = "DENY_UNKNOWN_ENVIRONMENT"
    DENY_UNKNOWN_PRINCIPAL = "DENY_UNKNOWN_PRINCIPAL"
    DENY_UNKNOWN_TARGET = "DENY_UNKNOWN_TARGET"
    DENY_PRODUCTION_TARGET = "DENY_PRODUCTION_TARGET"
    DENY_ENVIRONMENT_NOT_IN_POLICY = "DENY_ENVIRONMENT_NOT_IN_POLICY"
    DENY_PRINCIPAL_NOT_ALLOWLISTED = "DENY_PRINCIPAL_NOT_ALLOWLISTED"
    DENY_RESOURCE_NOT_ALLOWLISTED = "DENY_RESOURCE_NOT_ALLOWLISTED"
    DENY_INSUFFICIENT_EVIDENCE = "DENY_INSUFFICIENT_EVIDENCE"
    DENY_RETRY_BUDGET_EXHAUSTED = "DENY_RETRY_BUDGET_EXHAUSTED"
    DENY_POLICY_STATE_UNAVAILABLE = "DENY_POLICY_STATE_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Canonical hashing (stable key-sorted JSON, sha256)
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    """Serialize to stable canonical JSON: sorted keys, compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_hash(value: Any) -> str:
    """sha256 hex digest of the canonical JSON encoding of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def proposal_hash(proposal: ActionProposal, policy_version: str) -> str:
    """Canonical identity of an action proposal bound to a policy version.

    Includes action type, full parameters, and policy version so that any
    change to target, parameters, or policy invalidates prior approvals.
    """
    payload: dict[str, Any] = {
        "action_type": proposal.action_type,
        "parameters": proposal.model_dump(mode="json", exclude={"action_type"}),
        "policy_version": policy_version,
    }
    return canonical_hash(payload)


def parameters_hash(proposal: ActionProposal) -> str:
    return canonical_hash(proposal.model_dump(mode="json", exclude={"action_type"}))


# ---------------------------------------------------------------------------
# Policy snapshot: versioned data, not scattered if/else
# ---------------------------------------------------------------------------


class PolicyContext(StrictModel):
    """Fresh preconditions supplied by the caller at evaluation time.

    The engine performs no I/O; callers are responsible for supplying
    current state (ADR-0005). ``model_confidence`` is recorded for audit
    only and never influences the outcome.
    """

    principal_id: SafeIdentifier
    environment: Environment
    target_registered: bool = False
    evidence_indicates_unhealthy: bool = False
    retry_budget_available: bool = True
    approval_satisfied: bool = False
    model_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class PolicyRule(StrictModel):
    """One row of the policy matrix (PRD §8.1)."""

    action_type: ActionType
    environments: frozenset[Environment]
    outcome: PolicyDecisionType
    reason_code: str


class PolicySnapshot(StrictModel):
    """Frozen, versioned policy matrix. Data, not code paths."""

    version: SafeIdentifier
    known_principals: frozenset[str]
    registered_services: frozenset[str]
    test_access_principals: frozenset[str]
    test_access_resources: frozenset[str]
    rules: tuple[PolicyRule, ...]

    model_config = {"frozen": True, "extra": "forbid"}

    def rule_for(self, action_type: ActionType, environment: Environment) -> PolicyRule | None:
        for rule in self.rules:
            if rule.action_type is action_type and environment in rule.environments:
                return rule
        return None


def default_policy_snapshot() -> PolicySnapshot:
    """The PRD §8.1 initial matrix as data."""
    return PolicySnapshot(
        version="2026.10.28",
        known_principals=frozenset({"workflow-worker", "oncall-engineer", "test-user"}),
        registered_services=frozenset({"checkout-api", "payments-api", "search-api"}),
        test_access_principals=frozenset({"test-user"}),
        test_access_resources=frozenset({"test-bucket", "test-database"}),
        rules=(
            PolicyRule(
                action_type=ActionType.RESTART_SERVICE,
                environments=frozenset({Environment.LOCAL, Environment.TEST}),
                outcome=PolicyDecisionType.ALLOW,
                reason_code=ReasonCode.ALLOW_RESTART_LOCAL_TEST,
            ),
            PolicyRule(
                action_type=ActionType.RESTART_SERVICE,
                environments=frozenset({Environment.STAGING}),
                outcome=PolicyDecisionType.REQUIRE_APPROVAL,
                reason_code=ReasonCode.APPROVAL_REQUIRED_STAGING_RESTART,
            ),
            PolicyRule(
                action_type=ActionType.CLEAR_SIMULATED_CACHE,
                environments=frozenset({Environment.LOCAL, Environment.TEST}),
                outcome=PolicyDecisionType.ALLOW,
                reason_code=ReasonCode.ALLOW_CLEAR_CACHE_LOCAL_TEST,
            ),
            PolicyRule(
                action_type=ActionType.GRANT_TEST_RESOURCE_ACCESS,
                environments=frozenset({Environment.LOCAL, Environment.TEST}),
                outcome=PolicyDecisionType.REQUIRE_APPROVAL,
                reason_code=ReasonCode.APPROVAL_REQUIRED_TEST_ACCESS,
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _deny(
    proposal: ActionProposal,
    context: PolicyContext,
    snapshot: PolicySnapshot,
    reason: str,
    now: datetime,
) -> PolicyDecisionResult:
    return PolicyDecisionResult(
        decision_id=uuid4(),
        outcome="DENY",
        action_type=proposal.action_type,
        resource_id=_resource_id(proposal),
        principal_id=context.principal_id,
        policy_version=snapshot.version,
        reason_codes=[reason],
        proposal_hash=proposal_hash(proposal, snapshot.version),
        evaluated_at=now,
    )


def _resource_id(proposal: ActionProposal) -> str:
    if isinstance(proposal, GrantTestAccessParameters):
        return proposal.resource_id
    if isinstance(proposal, RestartServiceParameters | ClearCacheParameters):
        return proposal.service_name
    raise TypeError(f"Unhandled proposal type: {type(proposal)!r}")


def evaluate(
    proposal: ActionProposal,
    context: PolicyContext,
    snapshot: PolicySnapshot | None,
    *,
    now: datetime | None = None,
    decision_id: UUID | None = None,
) -> PolicyDecisionResult:
    """Evaluate a proposal deterministically. Deny-by-default.

    Order of checks (each fails closed):
      1. policy state available
      2. unknown action type
      3. unknown / production environment
      4. unknown principal
      5. matrix rule for (action, environment)
      6. target registration
      7. action-specific preconditions (evidence, retry budget, allowlists)
    """
    evaluated_at = now if now is not None else datetime.now(tz=UTC)

    if snapshot is None:
        # Fail closed: unavailable policy state can never authorize.
        return PolicyDecisionResult(
            decision_id=decision_id or uuid4(),
            outcome="DENY",
            action_type=getattr(proposal, "action_type", "UNKNOWN"),
            resource_id=_resource_id(proposal),
            principal_id=context.principal_id,
            policy_version="unavailable",
            reason_codes=[ReasonCode.DENY_POLICY_STATE_UNAVAILABLE],
            proposal_hash=canonical_hash({"unavailable": True}),
            evaluated_at=evaluated_at,
        )

    try:
        action = ActionType(proposal.action_type)
    except ValueError:
        return _deny(proposal, context, snapshot, ReasonCode.DENY_UNKNOWN_ACTION_TYPE, evaluated_at)

    try:
        environment = Environment(context.environment)
    except ValueError:
        return _deny(proposal, context, snapshot, ReasonCode.DENY_UNKNOWN_ENVIRONMENT, evaluated_at)

    if context.principal_id not in snapshot.known_principals:
        return _deny(proposal, context, snapshot, ReasonCode.DENY_UNKNOWN_PRINCIPAL, evaluated_at)

    rule = snapshot.rule_for(action, environment)
    if rule is None:
        # No matrix row for this (action, environment) pair: fail closed.
        return _deny(
            proposal, context, snapshot, ReasonCode.DENY_ENVIRONMENT_NOT_IN_POLICY, evaluated_at
        )

    # Target registration precondition (shared by all actions).
    if (
        action in (ActionType.RESTART_SERVICE, ActionType.CLEAR_SIMULATED_CACHE)
        and not context.target_registered
    ):
        return _deny(proposal, context, snapshot, ReasonCode.DENY_UNKNOWN_TARGET, evaluated_at)

    if rule.outcome is PolicyDecisionType.ALLOW:
        # Preconditions for allow rows (PRD §8.1 conditions column).
        if action is ActionType.RESTART_SERVICE:
            if not context.evidence_indicates_unhealthy:
                return _deny(
                    proposal, context, snapshot, ReasonCode.DENY_INSUFFICIENT_EVIDENCE, evaluated_at
                )
            if not context.retry_budget_available:
                return _deny(
                    proposal,
                    context,
                    snapshot,
                    ReasonCode.DENY_RETRY_BUDGET_EXHAUSTED,
                    evaluated_at,
                )
        return PolicyDecisionResult(
            decision_id=decision_id or uuid4(),
            outcome="ALLOW",
            action_type=proposal.action_type,
            resource_id=_resource_id(proposal),
            principal_id=context.principal_id,
            policy_version=snapshot.version,
            reason_codes=[rule.reason_code],
            proposal_hash=proposal_hash(proposal, snapshot.version),
            evaluated_at=evaluated_at,
        )

    if rule.outcome is PolicyDecisionType.REQUIRE_APPROVAL:
        if action is ActionType.GRANT_TEST_RESOURCE_ACCESS:
            assert isinstance(proposal, GrantTestAccessParameters)  # noqa: S101 — narrowing
            if proposal.principal_id not in snapshot.test_access_principals:
                return _deny(
                    proposal,
                    context,
                    snapshot,
                    ReasonCode.DENY_PRINCIPAL_NOT_ALLOWLISTED,
                    evaluated_at,
                )
            if proposal.resource_id not in snapshot.test_access_resources:
                return _deny(
                    proposal,
                    context,
                    snapshot,
                    ReasonCode.DENY_RESOURCE_NOT_ALLOWLISTED,
                    evaluated_at,
                )
        if context.approval_satisfied:
            # A valid approval satisfies the approval requirement; it can
            # never convert a DENY into an ALLOW (deny rows never reach here).
            return PolicyDecisionResult(
                decision_id=decision_id or uuid4(),
                outcome="ALLOW",
                action_type=proposal.action_type,
                resource_id=_resource_id(proposal),
                principal_id=context.principal_id,
                policy_version=snapshot.version,
                reason_codes=[ReasonCode.ALLOW_APPROVAL_SATISFIED],
                proposal_hash=proposal_hash(proposal, snapshot.version),
                evaluated_at=evaluated_at,
            )
        return PolicyDecisionResult(
            decision_id=decision_id or uuid4(),
            outcome="REQUIRE_APPROVAL",
            action_type=proposal.action_type,
            resource_id=_resource_id(proposal),
            principal_id=context.principal_id,
            policy_version=snapshot.version,
            reason_codes=[rule.reason_code],
            proposal_hash=proposal_hash(proposal, snapshot.version),
            evaluated_at=evaluated_at,
        )

    # DENY rows and any unknown outcome value fail closed.
    return _deny(proposal, context, snapshot, rule.reason_code, evaluated_at)
