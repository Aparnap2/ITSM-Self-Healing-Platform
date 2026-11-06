"""Reviewer authentication: trusted principal resolution (security slice).

The API must never trust client-supplied identity. Every reviewer request
carries a bearer credential that is verified here, producing a ``Principal``
with the tenant memberships, roles and authentication metadata the caller is
allowed to act on.

Design constraints:
- Provider-specific logic sits behind the ``Authenticator`` protocol so a
  real IdP (OIDC/JWT, mTLS, ...) can replace the HMAC implementation without
  touching the routes.
- No new third-party dependency is introduced: the token is a compact
  ``v1.<base64url(payload)>.<base64url(hmac-sha256)>`` envelope signed with a
  server-held secret. This is deliberately minimal and replaceable, not a
  home-grown password system.
- Verification fails closed: missing header, wrong scheme, malformed token,
  bad signature, wrong issuer, or expired token all raise an
  ``AuthenticationError``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

TOKEN_VERSION = "v1"  # nosec B105 - wire-format version, not a credential
DEFAULT_ISSUER = "itsm-audit"
DEFAULT_TOKEN_TTL_SECONDS = 900
MAX_TOKEN_LENGTH = 4096


class Role(StrEnum):
    """Reviewer roles. Permissions are derived in ``itsm_agent.api.rbac``."""

    AUDITOR = "auditor"
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class AuthenticationError(Exception):
    """Any credential that cannot be resolved to a trusted principal."""


class InvalidCredentialsError(AuthenticationError):
    """Missing, malformed, or badly signed credential."""


class ExpiredCredentialsError(AuthenticationError):
    """Well-formed credential that is no longer valid."""


class Principal(BaseModel):
    """Authenticated caller. Fields are never populated from the request body."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    principal_id: str = Field(min_length=1, max_length=128)
    tenant_ids: tuple[UUID, ...] = Field(min_length=1)
    roles: tuple[Role, ...] = Field(min_length=1)
    auth_method: str = Field(default="bearer_hmac", min_length=1, max_length=64)
    issuer: str = Field(default=DEFAULT_ISSUER, min_length=1, max_length=128)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return value

    def may_access_tenant(self, tenant_id: UUID) -> bool:
        return tenant_id in self.tenant_ids


class Authenticator(Protocol):
    """Boundary between the API and any identity provider."""

    async def authenticate(self, authorization: str | None) -> Principal: ...


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive
        raise InvalidCredentialsError("malformed token encoding") from exc


def _sign(secret: str, payload: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256)
    return _b64url_encode(digest.digest())


def mint_token(
    secret: str,
    *,
    principal_id: str,
    tenant_ids: Iterable[UUID | str],
    roles: Iterable[Role | str],
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    issuer: str = DEFAULT_ISSUER,
    issued_at: datetime | None = None,
    auth_method: str = "bearer_hmac",
) -> str:
    """Mint a signed reviewer token (used by tests and operational scripts)."""
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    now = issued_at or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("issued_at must be timezone-aware")
    claims: dict[str, Any] = {
        "v": 1,
        "sub": principal_id,
        "tenants": [str(t) for t in tenant_ids],
        "roles": [str(r) for r in roles],
        "iss": issuer,
        "method": auth_method,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return f"{TOKEN_VERSION}.{payload}.{_sign(secret, payload)}"


class TokenAuthenticator:
    """HMAC bearer-token authenticator (minimal, replaceable implementation)."""

    def __init__(
        self,
        *,
        secret: str,
        issuer: str = DEFAULT_ISSUER,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(secret) < 16:
            raise ValueError("token secret must be at least 16 characters")
        self._secret = secret
        self._issuer = issuer
        self._clock = clock or (lambda: datetime.now(UTC))

    async def authenticate(self, authorization: str | None) -> Principal:
        if not authorization:
            raise InvalidCredentialsError("missing bearer credential")
        if len(authorization) > MAX_TOKEN_LENGTH:
            raise InvalidCredentialsError("credential too large")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise InvalidCredentialsError("expected Bearer credential")

        parts = token.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_VERSION:
            raise InvalidCredentialsError("malformed token")
        _, payload, signature = parts
        if not payload.isascii() or not signature.isascii():
            raise InvalidCredentialsError("malformed token encoding")
        expected = _sign(self._secret, payload)
        if not hmac.compare_digest(expected, signature):
            raise InvalidCredentialsError("invalid token signature")

        try:
            claims = json.loads(_b64url_decode(payload))
        except (ValueError, AuthenticationError) as exc:
            raise InvalidCredentialsError("malformed token payload") from exc
        if not isinstance(claims, dict):
            raise InvalidCredentialsError("malformed token payload")
        if claims.get("iss") != self._issuer:
            raise InvalidCredentialsError("untrusted token issuer")

        expires_at = _claim_time(claims.get("exp"))
        if expires_at <= self._clock():
            raise ExpiredCredentialsError("credential expired")

        principal_id = claims.get("sub")
        tenants = claims.get("tenants")
        roles = claims.get("roles")
        if not isinstance(principal_id, str) or not principal_id:
            raise InvalidCredentialsError("token missing subject")
        if not isinstance(tenants, list) or not tenants:
            raise InvalidCredentialsError("token missing tenant membership")
        if not isinstance(roles, list) or not roles:
            raise InvalidCredentialsError("token missing roles")

        try:
            return Principal(
                principal_id=principal_id,
                tenant_ids=tuple(UUID(str(t)) for t in tenants),
                roles=tuple(Role(str(r)) for r in roles),
                auth_method=str(claims.get("method", "bearer_hmac")),
                issuer=self._issuer,
                expires_at=expires_at,
            )
        except (ValueError, TypeError) as exc:
            raise InvalidCredentialsError("token claims failed validation") from exc


def _claim_time(raw: object) -> datetime:
    if not isinstance(raw, int | float):
        raise InvalidCredentialsError("token missing expiry")
    try:
        value = datetime.fromtimestamp(float(raw), tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise InvalidCredentialsError("invalid token expiry") from exc
    return value


BearerHeader = Annotated[str | None, "Authorization header"]

__all__ = [
    "DEFAULT_ISSUER",
    "DEFAULT_TOKEN_TTL_SECONDS",
    "MAX_TOKEN_LENGTH",
    "TOKEN_VERSION",
    "AuthenticationError",
    "Authenticator",
    "ExpiredCredentialsError",
    "InvalidCredentialsError",
    "Principal",
    "Role",
    "TokenAuthenticator",
    "mint_token",
]
