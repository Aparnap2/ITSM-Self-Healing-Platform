"""Mockoon-backed infrastructure adapter.

Two deliberately distinct code paths (PRD §6.7, AGENTS.md invariant 12):

- **Action path** (``InfrastructureActionPort``): POST
  ``/actions/restart_service`` — the response of a mutation is untrusted
  data; ``SUCCEEDED`` here is never proof of recovery.
- **Verifier path** (``InfrastructureStateReader``): GET
  ``/state/{service}`` — a read-only state reader used by the
  independent verifier. It shares no response handling with the action
  path and validates into a different model (``VerifiedState``).

Allowlisted endpoints only; every response validated with Pydantic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import ValidationError

from itsm_agent.adapters.http import (
    AdapterUnavailableError,
    AllowlistedHttpClient,
    UnexpectedResponseError,
)
from itsm_agent.ports._fallback_types import SafeIdentifier
from itsm_agent.ports.infrastructure import ActionResult, VerifiedState

_ACTION_PATHS = ("/actions/restart_service",)
_STATE_PATHS = ("/state/{service}", "/services")


class MockoonInfrastructureActionAdapter:
    """Action path: allowlisted mutations against the simulator."""

    def __init__(self, *, base_url: str, timeout_seconds: float, max_retries: int) -> None:
        self._http = AllowlistedHttpClient(
            base_url=base_url,
            allowed_paths=_ACTION_PATHS,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def restart_service(
        self,
        *,
        service_name: SafeIdentifier,
        environment: Literal["local", "test", "staging"],
        idempotency_key: str,
    ) -> ActionResult:
        body = {
            "action_type": "RESTART_SERVICE",
            "service_name": service_name,
            "environment": environment,
            "idempotency_key": idempotency_key,
        }
        try:
            payload = await self._http.request_json(
                "POST", "/actions/restart_service", json_body=body
            )
        except AdapterUnavailableError:
            # Unreachable/timeout after bounded retries => outcome unknown.
            return ActionResult(
                action_type="RESTART_SERVICE",
                service_name=service_name,
                status="OUTCOME_UNKNOWN",
                result_code="TRANSPORT_UNAVAILABLE",
                summary="Action endpoint unreachable after bounded retries",
                observed_at=datetime.now(UTC),
            )
        try:
            return ActionResult.model_validate(payload)
        except ValidationError as exc:
            raise UnexpectedResponseError(f"Invalid action result: {exc}") from exc


class MockoonInfrastructureStateReader:
    """Independent read-only verifier path — distinct from the action path."""

    def __init__(self, *, base_url: str, timeout_seconds: float, max_retries: int) -> None:
        self._http = AllowlistedHttpClient(
            base_url=base_url,
            allowed_paths=_STATE_PATHS,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def read_service_state(
        self,
        *,
        service_name: SafeIdentifier,
        environment: Literal["local", "test", "staging"],
    ) -> VerifiedState:
        try:
            payload = await self._http.request_json(
                "GET",
                f"/state/{service_name}",
                params={"environment": environment},
            )
        except AdapterUnavailableError as exc:
            raise UnexpectedResponseError(
                f"Verifier state read unavailable: {type(exc).__name__}"
            ) from exc
        try:
            state = VerifiedState.model_validate(payload)
        except ValidationError as exc:
            raise UnexpectedResponseError(f"Invalid verified state: {exc}") from exc
        if state.service_name != service_name or state.environment != environment:
            raise UnexpectedResponseError("Verifier state response does not match requested target")
        return state

    async def list_known_services(self) -> tuple[SafeIdentifier, ...]:
        try:
            payload = await self._http.request_json("GET", "/services")
        except AdapterUnavailableError as exc:
            raise UnexpectedResponseError(
                f"Verifier service list unavailable: {type(exc).__name__}"
            ) from exc
        services = payload.get("services")
        if not isinstance(services, list):
            raise UnexpectedResponseError("Invalid services listing")
        return tuple(str(s) for s in services)


__all__ = [
    "MockoonInfrastructureActionAdapter",
    "MockoonInfrastructureStateReader",
]
