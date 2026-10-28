"""Deterministic infrastructure service-state simulator.

Seeded, in-memory service states with a ``restart_service`` action
supporting three fault-injection modes:

- ``transient_fail`` — first N attempts fail, then succeed
- ``timeout_then_success`` — reports an ambiguous/timeout outcome once,
  then succeeds (drives the reconcile-before-retry rule)
- ``always_fail`` — every attempt fails (drives escalation)

The simulator is the *state store*; the action path and the verifier
path both read from it, but through distinct interfaces (see
``SimulatorActionService`` vs ``SimulatorStateReader``), so the
independent verifier never trusts the action response.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from itsm_agent.ports.infrastructure import ActionResult, VerifiedState

FAULT_MODES = ("transient_fail", "timeout_then_success", "always_fail")


class UnknownServiceError(Exception):
    """Requested service is not in the simulator's known set (fail closed)."""


class UnknownFaultModeError(Exception):
    """Requested fault mode is not allowlisted."""


@dataclass
class _ServiceState:
    name: str
    environment: str
    status: str = "DOWN"
    uptime_seconds: int = 0
    restart_count: int = 0
    last_action_result_code: str | None = None
    attempt_counter: int = 0
    idempotency_keys: dict[str, str] = field(default_factory=dict)


def _deterministic_now(seed_state: dict[str, int], key: str) -> datetime:
    """Deterministic timestamp derived from a per-key counter.

    Keeps tests reproducible without a frozen-clock dependency.
    """
    tick = seed_state.get(key, 0)
    seed_state[key] = tick + 1
    return datetime(2026, 1, 1, 0, 0, tick, tzinfo=UTC)


class InfrastructureSimulator:
    """Seeded deterministic service-state store + action semantics."""

    def __init__(self, *, seed: int = 42) -> None:
        self._seed = seed
        self._services: dict[tuple[str, str], _ServiceState] = {}
        self._clock: dict[str, int] = {}

    def seed_service(
        self,
        *,
        service_name: str,
        environment: str,
        status: str = "DOWN",
        uptime_seconds: int = 0,
        restart_count: int = 0,
    ) -> None:
        """Register a known service with an initial health state."""
        if status not in {"HEALTHY", "DEGRADED", "DOWN", "UNKNOWN"}:
            raise UnknownServiceError(f"Invalid seeded status: {status}")
        self._services[(service_name, environment)] = _ServiceState(
            name=service_name,
            environment=environment,
            status=status,
            uptime_seconds=uptime_seconds,
            restart_count=restart_count,
        )

    def known_services(self) -> tuple[str, ...]:
        return tuple(sorted({name for name, _ in self._services}))

    def restart_service(
        self,
        *,
        service_name: str,
        environment: str,
        idempotency_key: str,
        fault_mode: str = "transient_fail",
        transient_failures: int = 0,
    ) -> ActionResult:
        """Apply the restart action with deterministic fault injection.

        Idempotent: replaying the same idempotency key returns the
        recorded result without re-executing the fault sequence.
        """
        state = self._lookup(service_name, environment)
        if fault_mode not in FAULT_MODES:
            raise UnknownFaultModeError(f"Unknown fault mode: {fault_mode}")

        recorded = state.idempotency_keys.get(idempotency_key)
        if recorded is not None:
            return ActionResult(
                action_type="RESTART_SERVICE",
                service_name=service_name,
                status="SUCCEEDED" if recorded == "RESTART_OK" else "FAILED",
                result_code=recorded,
                summary=f"Idempotent replay of {idempotency_key}",
                observed_at=_deterministic_now(self._clock, f"replay-{idempotency_key}"),
            )

        state.attempt_counter += 1
        attempt = state.attempt_counter

        if fault_mode == "always_fail":
            result_code = "RESTART_FAILED"
            state.last_action_result_code = result_code
            state.idempotency_keys[idempotency_key] = result_code
            return ActionResult(
                action_type="RESTART_SERVICE",
                service_name=service_name,
                status="FAILED",
                result_code=result_code,
                summary=f"Restart attempt {attempt} failed (always_fail)",
                observed_at=_deterministic_now(self._clock, f"fail-{attempt}"),
            )

        if fault_mode == "timeout_then_success" and attempt == 1:
            # Ambiguous outcome: the caller must reconcile before retrying.
            result_code = "OUTCOME_UNKNOWN_TIMEOUT"
            state.last_action_result_code = result_code
            state.idempotency_keys[idempotency_key] = result_code
            return ActionResult(
                action_type="RESTART_SERVICE",
                service_name=service_name,
                status="OUTCOME_UNKNOWN",
                result_code=result_code,
                summary="Restart timed out; actual state must be reconciled",
                observed_at=_deterministic_now(self._clock, f"timeout-{attempt}"),
            )

        if fault_mode == "transient_fail" and attempt <= transient_failures:
            result_code = "RESTART_TRANSIENT_FAILURE"
            state.last_action_result_code = result_code
            state.idempotency_keys[idempotency_key] = result_code
            return ActionResult(
                action_type="RESTART_SERVICE",
                service_name=service_name,
                status="FAILED",
                result_code=result_code,
                summary=f"Restart attempt {attempt} hit transient failure",
                observed_at=_deterministic_now(self._clock, f"transient-{attempt}"),
            )

        # Success path: service becomes healthy.
        state.status = "HEALTHY"
        state.uptime_seconds = 0
        state.restart_count += 1
        state.last_action_result_code = "RESTART_OK"
        state.idempotency_keys[idempotency_key] = "RESTART_OK"
        return ActionResult(
            action_type="RESTART_SERVICE",
            service_name=service_name,
            status="SUCCEEDED",
            result_code="RESTART_OK",
            summary=f"Restart attempt {attempt} succeeded",
            observed_at=_deterministic_now(self._clock, f"ok-{attempt}"),
        )

    def read_state(self, *, service_name: str, environment: str) -> VerifiedState:
        """Read-only state view (the verifier's data source)."""
        state = self._lookup(service_name, environment)
        return VerifiedState(
            service_name=state.name,
            environment=state.environment,
            status=state.status,
            uptime_seconds=state.uptime_seconds,
            restart_count=state.restart_count,
            last_action_result_code=state.last_action_result_code,
            observed_at=_deterministic_now(self._clock, f"read-{service_name}"),
        )

    def _lookup(self, service_name: str, environment: str) -> _ServiceState:
        state = self._services.get((service_name, environment))
        if state is None:
            raise UnknownServiceError(f"Unknown service/target: {service_name}/{environment}")
        return state


def state_fingerprint(state: VerifiedState) -> str:
    """Canonical hash of observed state for evidence records."""
    canonical = (
        f"{state.service_name}|{state.environment}|{state.status}|"
        f"{state.uptime_seconds}|{state.restart_count}|"
        f"{state.last_action_result_code}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "FAULT_MODES",
    "InfrastructureSimulator",
    "UnknownFaultModeError",
    "UnknownServiceError",
    "state_fingerprint",
]
