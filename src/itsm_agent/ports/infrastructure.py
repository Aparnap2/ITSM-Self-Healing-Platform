"""Typed ports for simulated infrastructure state.

Two distinct capabilities, deliberately separated:

- ``InfrastructureActionPort`` — the *action* path (restart_service with
  fault injection). Its success response is never proof of recovery.
- ``InfrastructureStateReader`` — the *independent verifier* path: a
  read-only state reader that must be a different code path from the
  action response (PRD §6.7, AGENTS.md invariant 12).
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from itsm_agent.ports._fallback_types import SafeIdentifier, UTCDateTime


class ServiceHealth(BaseModel):
    """Observed health of a simulated service."""

    model_config = ConfigDict(extra="forbid")

    service_name: SafeIdentifier
    environment: Literal["local", "test", "staging"]
    status: Literal["HEALTHY", "DEGRADED", "DOWN", "UNKNOWN"]
    uptime_seconds: int = Field(ge=0)
    restart_count: int = Field(ge=0)
    observed_at: UTCDateTime


class ActionResult(BaseModel):
    """Typed result of an infrastructure action (untrusted until verified)."""

    model_config = ConfigDict(extra="forbid")

    action_type: SafeIdentifier
    service_name: SafeIdentifier
    status: Literal["SUCCEEDED", "FAILED", "OUTCOME_UNKNOWN"]
    result_code: SafeIdentifier
    summary: str = Field(max_length=1500)
    observed_at: UTCDateTime


class VerifiedState(BaseModel):
    """State read through the independent, read-only verifier path."""

    model_config = ConfigDict(extra="forbid")

    service_name: SafeIdentifier
    environment: Literal["local", "test", "staging"]
    status: Literal["HEALTHY", "DEGRADED", "DOWN", "UNKNOWN"]
    uptime_seconds: int = Field(ge=0)
    restart_count: int = Field(ge=0)
    last_action_result_code: SafeIdentifier | None = None
    observed_at: UTCDateTime


@runtime_checkable
class InfrastructureActionPort(Protocol):
    """Action path: allowlisted mutations against the simulator."""

    async def restart_service(
        self,
        *,
        service_name: SafeIdentifier,
        environment: Literal["local", "test", "staging"],
        idempotency_key: str,
    ) -> ActionResult: ...


@runtime_checkable
class InfrastructureStateReader(Protocol):
    """Independent read-only state path used by the verifier."""

    async def read_service_state(
        self,
        *,
        service_name: SafeIdentifier,
        environment: Literal["local", "test", "staging"],
    ) -> VerifiedState: ...

    async def list_known_services(self) -> tuple[SafeIdentifier, ...]: ...


def observed_state_dict(state: VerifiedState) -> dict[str, str | int | float | bool | None]:
    """Flatten a VerifiedState into a VerificationResult.observed_state payload."""
    raw: dict[str, Any] = state.model_dump(mode="json")
    return {k: v for k, v in raw.items() if isinstance(v, (str, int, float, bool)) or v is None}


__all__ = [
    "ActionResult",
    "InfrastructureActionPort",
    "InfrastructureStateReader",
    "ServiceHealth",
    "VerifiedState",
    "observed_state_dict",
]
