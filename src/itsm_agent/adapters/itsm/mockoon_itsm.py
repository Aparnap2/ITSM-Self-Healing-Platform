"""Mockoon-backed ITSM adapter implementing ``ItsMPort``.

Allowlisted endpoints (relative to the configured Mockoon ITSM base URL):
- POST /tickets            — create ticket
- GET  /tickets/{id}       — read ticket snapshot
- PATCH /tickets/{id}      — apply outbound update

Every response is validated into a typed model; failures raise
``UnexpectedResponseError`` (fail closed).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints, ValidationError

from itsm_agent.adapters.http import (
    AdapterUnavailableError,
    AllowlistedHttpClient,
    UnexpectedResponseError,
)
from itsm_agent.ports.itsm import (
    TicketRef,
    TicketSnapshot,
    TicketUpdate,
    TicketUpdateResult,
)

_ALLOWED_PATHS = ("/tickets", "/tickets/{id}")


class MockoonItsMAdapter:
    """Typed adapter for the Mockoon ITSM API."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float,
        max_retries: int,
        system_name: str = "mockoon-itsm",
    ) -> None:
        self._system = system_name
        self._http = AllowlistedHttpClient(
            base_url=base_url,
            allowed_paths=_ALLOWED_PATHS,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def create_ticket(
        self,
        *,
        title: Annotated[str, StringConstraints(max_length=240)],
        description: Annotated[str, StringConstraints(max_length=8000)],
        severity: str,
        service_name: str,
        correlation_id: str,
    ) -> TicketRef:
        body = {
            "title": title,
            "description": description,
            "severity": severity,
            "service_name": service_name,
            "correlation_id": correlation_id,
        }
        payload = await self._post("/tickets", body)
        try:
            ticket_id = str(payload["ticket_id"])
            return TicketRef(
                system=self._system,
                ticket_id=ticket_id,
                url=payload.get("url"),
            )
        except (KeyError, TypeError, ValidationError) as exc:
            raise UnexpectedResponseError(f"Invalid ticket creation response: {exc}") from exc

    async def get_ticket(self, ticket_id: str) -> TicketSnapshot:
        payload = await self._get(f"/tickets/{ticket_id}")
        try:
            return TicketSnapshot.model_validate(payload)
        except ValidationError as exc:
            raise UnexpectedResponseError(f"Invalid ticket snapshot: {exc}") from exc

    async def update_ticket(self, update: TicketUpdate) -> TicketUpdateResult:
        body: dict[str, str] = {}
        if update.status is not None:
            body["status"] = update.status
        if update.comment is not None:
            body["comment"] = update.comment
        payload = await self._patch(f"/tickets/{update.ticket_id}", body)
        try:
            return TicketUpdateResult.model_validate(
                {
                    "ticket_id": update.ticket_id,
                    "accepted": bool(payload.get("accepted", False)),
                    "result_code": str(payload.get("result_code", "UNKNOWN")),
                    "summary": str(payload.get("summary", ""))[:500],
                }
            )
        except ValidationError as exc:
            raise UnexpectedResponseError(f"Invalid update result: {exc}") from exc

    async def _post(self, path: str, body: dict[str, str]) -> dict[str, object]:
        try:
            return await self._http.request_json("POST", path, json_body=body)
        except AdapterUnavailableError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise UnexpectedResponseError(str(exc)) from exc

    async def _get(self, path: str) -> dict[str, object]:
        try:
            return await self._http.request_json("GET", path)
        except AdapterUnavailableError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise UnexpectedResponseError(str(exc)) from exc

    async def _patch(self, path: str, body: dict[str, str]) -> dict[str, object]:
        try:
            return await self._http.request_json("PATCH", path, json_body=body)
        except AdapterUnavailableError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise UnexpectedResponseError(str(exc)) from exc


__all__ = ["MockoonItsMAdapter"]
