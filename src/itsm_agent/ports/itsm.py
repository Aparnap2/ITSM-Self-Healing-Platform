"""Typed port for ITSM systems (Mockoon-simulated today, Jira later).

Implementations must return typed models, never raw dicts. All responses
are untrusted until validated at the adapter boundary.
"""

from __future__ import annotations

from typing import Annotated, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, StringConstraints

from itsm_agent.ports._fallback_types import SafeIdentifier, ShortText, UTCDateTime


class TicketRef(BaseModel):
    """Reference to a ticket in the external ITSM system."""

    model_config = ConfigDict(extra="forbid")

    system: SafeIdentifier
    ticket_id: SafeIdentifier
    url: str | None = None


class TicketSnapshot(BaseModel):
    """Read-only view of an external ticket."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: SafeIdentifier
    status: SafeIdentifier
    title: ShortText
    description: Annotated[str, StringConstraints(max_length=8000)]
    updated_at: UTCDateTime


class TicketUpdate(BaseModel):
    """Outbound update to apply to a ticket."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: SafeIdentifier
    status: SafeIdentifier | None = None
    comment: Annotated[str, StringConstraints(max_length=4000)] | None = None


class TicketUpdateResult(BaseModel):
    """Typed result of an outbound ticket update."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: SafeIdentifier
    accepted: bool
    result_code: SafeIdentifier
    summary: Annotated[str, StringConstraints(max_length=500)]


@runtime_checkable
class ItsMPort(Protocol):
    """Outbound ITSM operations (create/update/read tickets)."""

    async def create_ticket(
        self,
        *,
        title: ShortText,
        description: Annotated[str, StringConstraints(max_length=8000)],
        severity: SafeIdentifier,
        service_name: SafeIdentifier,
        correlation_id: str,
    ) -> TicketRef: ...

    async def get_ticket(self, ticket_id: SafeIdentifier) -> TicketSnapshot: ...

    async def update_ticket(self, update: TicketUpdate) -> TicketUpdateResult: ...


__all__ = [
    "ItsMPort",
    "TicketRef",
    "TicketSnapshot",
    "TicketUpdate",
    "TicketUpdateResult",
]
