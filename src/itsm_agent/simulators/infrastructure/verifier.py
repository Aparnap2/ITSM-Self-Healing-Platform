"""Independent verifier for simulated infrastructure state.

The verifier reads state through ``InfrastructureSimulator.read_state``
— a read-only path distinct from the action response path. It never
accepts an ``ActionResult`` as input: proof of recovery comes only from
freshly observed state evaluated against an explicit predicate.

Predicates (allowlisted, deterministic):
- ``service_healthy`` — status == HEALTHY
- ``restart_count_increased`` — restart_count > baseline
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from itsm_agent.ports.infrastructure import VerifiedState, observed_state_dict
from itsm_agent.simulators.infrastructure.simulator import (
    InfrastructureSimulator,
    UnknownServiceError,
    state_fingerprint,
)

VERIFIER_VERSION = "independent-verifier-v1"

PredicateName = Literal["service_healthy", "restart_count_increased"]

_PREDICATES: tuple[str, ...] = ("service_healthy", "restart_count_increased")


class VerificationObservation(BaseModel):
    """Typed output of one independent verification pass."""

    model_config = ConfigDict(extra="forbid")

    predicate: str
    passed: bool
    observed_state: dict[str, str | int | float | bool | None]
    evidence_hash: str
    verifier_version: str


class IndependentVerifier:
    """Read-only verifier over the simulator state store."""

    def __init__(self, simulator: InfrastructureSimulator) -> None:
        self._simulator = simulator

    def verify(
        self,
        *,
        service_name: str,
        environment: str,
        predicate: PredicateName,
        baseline_restart_count: int = 0,
    ) -> VerificationObservation:
        """Observe state fresh and evaluate the allowlisted predicate.

        Raises ``UnknownServiceError`` for unknown targets (fail closed).
        """
        if predicate not in _PREDICATES:
            raise UnknownServiceError(f"Unknown verification predicate: {predicate}")
        state: VerifiedState = self._simulator.read_state(
            service_name=service_name, environment=environment
        )
        if predicate == "service_healthy":
            passed = state.status == "HEALTHY"
        else:  # restart_count_increased
            passed = state.restart_count > baseline_restart_count
        return VerificationObservation(
            predicate=predicate,
            passed=passed,
            observed_state=observed_state_dict(state),
            evidence_hash=state_fingerprint(state),
            verifier_version=VERIFIER_VERSION,
        )


__all__ = [
    "IndependentVerifier",
    "VerificationObservation",
    "VERIFIER_VERSION",
]
