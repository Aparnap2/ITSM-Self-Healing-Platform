"""Mockoon-backed identity adapter implementing ``IdentityPort``.

Allowlisted endpoint: GET /principals/{principal_id}
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import ValidationError

from itsm_agent.adapters.http import (
    AdapterUnavailableError,
    AllowlistedHttpClient,
    UnexpectedResponseError,
)
from itsm_agent.ports._fallback_types import SafeIdentifier
from itsm_agent.ports.identity import IdentityVerificationResult, PrincipalIdentity

_ALLOWED_PATHS = ("/principals/{id}",)


class MockoonIdentityAdapter:
    """Typed adapter for the Mockoon identity API."""

    def __init__(self, *, base_url: str, timeout_seconds: float, max_retries: int) -> None:
        self._http = AllowlistedHttpClient(
            base_url=base_url,
            allowed_paths=_ALLOWED_PATHS,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def verify_principal(self, principal_id: SafeIdentifier) -> IdentityVerificationResult:
        try:
            payload = await self._http.request_json("GET", f"/principals/{principal_id}")
        except AdapterUnavailableError as exc:
            return IdentityVerificationResult(
                principal_id=principal_id,
                outcome="ERROR",
                detail=f"identity provider unavailable: {type(exc).__name__}",
            )

        if payload.get("found") is False:
            return IdentityVerificationResult(
                principal_id=principal_id, outcome="UNKNOWN_PRINCIPAL"
            )
        try:
            identity = PrincipalIdentity.model_validate(
                {
                    "principal_id": payload["principal_id"],
                    "display_name": payload["display_name"],
                    "active": bool(payload.get("active", False)),
                    "roles": tuple(payload.get("roles", ())),
                    "verified_at": payload.get("verified_at") or datetime.now(UTC).isoformat(),
                }
            )
        except (KeyError, TypeError, ValidationError) as exc:
            raise UnexpectedResponseError(f"Invalid identity response: {exc}") from exc
        outcome = "VERIFIED" if identity.active else "INACTIVE"
        return IdentityVerificationResult(
            principal_id=principal_id, outcome=outcome, identity=identity
        )


__all__ = ["MockoonIdentityAdapter"]
