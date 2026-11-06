"""Typed port for identity verification (Mockoon-simulated).

Used to authenticate principals independently of any claimed identity in
ticket text or model output.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from itsm_agent.ports._fallback_types import SafeIdentifier, UTCDateTime


class PrincipalIdentity(BaseModel):
    """Verified identity of a principal (e.g. an approver)."""

    model_config = ConfigDict(extra="forbid")

    principal_id: SafeIdentifier
    display_name: SafeIdentifier
    active: bool
    roles: tuple[SafeIdentifier, ...] = ()
    verified_at: UTCDateTime


class IdentityVerificationResult(BaseModel):
    """Typed result of an identity lookup/verification call."""

    model_config = ConfigDict(extra="forbid")

    principal_id: SafeIdentifier
    outcome: Literal["VERIFIED", "UNKNOWN_PRINCIPAL", "INACTIVE", "ERROR"]
    identity: PrincipalIdentity | None = None
    detail: str | None = None


@runtime_checkable
class IdentityPort(Protocol):
    """Read-only identity verification against the identity provider."""

    async def verify_principal(
        self, principal_id: SafeIdentifier
    ) -> IdentityVerificationResult: ...


__all__ = [
    "IdentityPort",
    "IdentityVerificationResult",
    "PrincipalIdentity",
]
