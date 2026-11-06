"""Reconciliation for uncertain infrastructure actions (rule 11).

Reconciliation answers one question only: *did the intended mutation
already take effect?* It never mutates, never resolves an incident, and
never returns ``APPLIED``/``NOT_APPLIED`` without fresh evidence.

Evidence precedence:
1. the target's own operation record for the idempotency key
   (authoritative: distinguishes "not applied" from "no record"),
2. freshly observed service state (can prove APPLIED, never NOT_APPLIED).

Anything else — read failure, unknown operation, stale/inconsistent
state — is ``INCONCLUSIVE`` and therefore cannot authorize a retry.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID, uuid4

from itsm_agent.domain.events import (
    ActionProposal,
    GrantTestAccessParameters,
    ReconciliationResult,
)
from itsm_agent.simulators.infrastructure.simulator import (
    InfrastructureSimulator,
    TransientReadError,
    UnknownServiceError,
    state_fingerprint,
)

RECONCILER_VERSION = "infra-reconciler-v1"


class InfrastructureReconciler:
    """Authoritative-state reconciler over the simulator state store."""

    def __init__(self, simulator: InfrastructureSimulator) -> None:
        self._simulator = simulator

    def reconcile(
        self,
        proposal: ActionProposal,
        *,
        idempotency_key: str,
        action_attempt_id: UUID,
    ) -> ReconciliationResult:
        if isinstance(proposal, GrantTestAccessParameters):
            return self._result(
                action_attempt_id=action_attempt_id,
                idempotency_key=idempotency_key,
                outcome="INCONCLUSIVE",
                result_code="RECONCILE_UNSUPPORTED_ACTION",
                observed={},
                evidence="unsupported-action",
            )
        service_name = proposal.service_name
        environment = proposal.environment
        try:
            status = self._simulator.operation_status(
                service_name=service_name,
                environment=environment,
                idempotency_key=idempotency_key,
            )
            state = self._simulator.read_state(service_name=service_name, environment=environment)
        except TransientReadError:
            return self._result(
                action_attempt_id=action_attempt_id,
                idempotency_key=idempotency_key,
                outcome="INCONCLUSIVE",
                result_code="RECONCILE_READ_UNAVAILABLE",
                observed={},
                evidence="read-error",
            )
        except UnknownServiceError:
            # Fail closed: an unknown target can never authorize a retry.
            return self._result(
                action_attempt_id=action_attempt_id,
                idempotency_key=idempotency_key,
                outcome="INCONCLUSIVE",
                result_code="RECONCILE_TARGET_UNKNOWN",
                observed={},
                evidence="unknown-target",
            )

        observed: dict[str, str | int | float | bool | None] = {
            "status": state.status,
            "restart_count": state.restart_count,
            "operation_status": status,
        }
        evidence = state_fingerprint(state)

        if status == "APPLIED":
            # The mutation is durable. Whether it *worked* is a separate
            # question answered by independent postcondition verification.
            return self._result(
                action_attempt_id=action_attempt_id,
                idempotency_key=idempotency_key,
                outcome="APPLIED",
                result_code="RECONCILE_OPERATION_APPLIED",
                observed=observed,
                evidence=evidence,
            )
        if status == "NOT_APPLIED":
            return self._result(
                action_attempt_id=action_attempt_id,
                idempotency_key=idempotency_key,
                outcome="NOT_APPLIED",
                result_code="RECONCILE_OPERATION_NOT_APPLIED",
                observed=observed,
                evidence=evidence,
            )
        if state.status == "HEALTHY":
            # No operation record but the postcondition holds: do not retry.
            return self._result(
                action_attempt_id=action_attempt_id,
                idempotency_key=idempotency_key,
                outcome="APPLIED",
                result_code="RECONCILE_STATE_HEALTHY",
                observed=observed,
                evidence=evidence,
            )
        return self._result(
            action_attempt_id=action_attempt_id,
            idempotency_key=idempotency_key,
            outcome="INCONCLUSIVE",
            result_code="RECONCILE_NO_OPERATION_RECORD",
            observed=observed,
            evidence=evidence,
        )

    @staticmethod
    def _result(
        *,
        action_attempt_id: UUID,
        idempotency_key: str,
        outcome: str,
        result_code: str,
        observed: dict[str, str | int | float | bool | None],
        evidence: str,
    ) -> ReconciliationResult:
        return ReconciliationResult(
            reconciliation_id=uuid4(),
            action_attempt_id=action_attempt_id,
            idempotency_key=idempotency_key,
            outcome=outcome,
            result_code=result_code,
            observed_state=observed,
            evidence_hash=hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
            observed_at=datetime.now(tz=UTC),
            reconciler_version=RECONCILER_VERSION,
        )


__all__ = ["InfrastructureReconciler", "RECONCILER_VERSION"]
