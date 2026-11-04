"""OIDC/JWT reviewer authentication (security hardening slice).

This is a deliberately small OIDC *relying party* implementation behind the
existing ``Authenticator`` protocol. It validates a signed JWT and then, and
this is the important part, resolves the caller's **current** tenant
memberships and roles from a trusted server-side directory. Roles or tenants
carried inside the token are never treated as authorization data.

Why a directory lookup instead of trusting token claims:

- a signed token can remain valid for an hour after a reviewer is disabled or
  moved out of a tenant;
- role changes must take effect without waiting for token expiry;
- a compromised issuer cannot grant a reviewer access to a tenant it does not
  administer.

Fail-closed rules: unknown/missing algorithm, missing key id, unavailable
JWKS, signature failure, wrong issuer, wrong audience, expired/not-yet-valid
token, over-age token, missing subject, unknown/disabled reviewer, empty
tenant or role set, or an unknown role all reject the request.

What this module does NOT do: it is not an authorization server, it does not
issue tokens, and it does not implement mTLS. Workload mTLS is a separate
service-to-service mechanism.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel, ConfigDict, Field

from itsm_agent.api.auth import (
    AuthenticationError,
    InvalidCredentialsError,
    Principal,
    Role,
)

__all__ = [
    "ALLOWED_ALGORITHMS",
    "AuthorizationDirectory",
    "HttpJwksProvider",
    "JwksProvider",
    "OIDCAuthenticator",
    "PsycopgReviewerDirectory",
    "ReviewerAuthorization",
    "StaticAuthorizationDirectory",
    "StaticJwksProvider",
]

#: Signature algorithms accepted by this relying party. Symmetric algorithms
#: (HS*) and ``none`` are deliberately absent: accepting them would let a
#: token signed with a shared secret impersonate a public-key issuer.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256", "RS384", "RS512", "ES256")


class ReviewerAuthorization(BaseModel):
    """Current server-side authorization state for one reviewer."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    active: bool
    tenant_ids: tuple[UUID, ...] = Field(default_factory=tuple)
    roles: tuple[str, ...] = Field(default_factory=tuple)
    authorization_version: str = Field(min_length=1, max_length=128)
    updated_at: datetime | None = None


class AuthorizationDirectory(Protocol):
    """Trusted server-side source of reviewer tenant/role state."""

    async def resolve(self, *, issuer: str, subject: str) -> ReviewerAuthorization | None: ...


class StaticAuthorizationDirectory:
    """Deterministic directory for tests and local single-process setups."""

    def __init__(self, entries: Mapping[tuple[str, str], ReviewerAuthorization]) -> None:
        self._entries = dict(entries)

    async def resolve(self, *, issuer: str, subject: str) -> ReviewerAuthorization | None:
        return self._entries.get((issuer, subject))


class PsycopgReviewerDirectory:
    """Postgres directory read through the runtime role's tenant context."""

    def __init__(self, pool: AsyncConnectionPool[AsyncConnection]) -> None:
        self._pool = pool

    async def resolve(self, *, issuer: str, subject: str) -> ReviewerAuthorization | None:
        async with (
            self._pool.connection() as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                """
                SELECT tenant_ids, roles, active, authorization_version, updated_at
                  FROM reviewer_authorizations
                 WHERE issuer = %s AND subject = %s
                """,
                (issuer, subject),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return ReviewerAuthorization(
            active=row["active"],
            tenant_ids=tuple(row["tenant_ids"]),
            roles=tuple(row["roles"]),
            authorization_version=row["authorization_version"],
            updated_at=row["updated_at"],
        )


class JwksProvider(Protocol):
    """Source of verification keys keyed by ``kid``."""

    async def keys(self, *, force_refresh: bool = False) -> Mapping[str, Any]: ...


class StaticJwksProvider:
    """JWKS provider with no network access (tests, offline acceptance)."""

    def __init__(self, keys: Mapping[str, Any]) -> None:
        self._keys = dict(keys)
        self.calls = 0

    async def keys(self, *, force_refresh: bool = False) -> Mapping[str, Any]:
        self.calls += 1
        return self._keys


class HttpJwksProvider:
    """Caching JWKS fetcher with key-rotation refresh.

    A cache miss for an unknown ``kid`` forces one refresh (rotation). Any
    fetch failure fails closed: stale keys are not used to authenticate a new
    token. The response is bounded in size before parsing.
    """

    MAX_BYTES = 1_048_576

    def __init__(
        self,
        *,
        url: str,
        client: httpx.AsyncClient,
        cache_seconds: float = 300.0,
        clock: Any | None = None,
    ) -> None:
        self._url = url
        self._client = client
        self._cache_seconds = cache_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cache: dict[str, Any] | None = None
        self._fetched_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def keys(self, *, force_refresh: bool = False) -> Mapping[str, Any]:
        async with self._lock:
            if not force_refresh and self._is_fresh():
                assert self._cache is not None
                return self._cache
            try:
                response = await self._client.get(self._url)
                response.raise_for_status()
                if len(response.content) > self.MAX_BYTES:
                    raise InvalidCredentialsError("JWKS response too large")
                document = response.json()
                keys = _parse_jwks(document)
            except InvalidCredentialsError:
                raise
            except Exception as exc:  # noqa: BLE001 - fail closed on any fetch/parse error
                raise InvalidCredentialsError("JWKS unavailable or malformed") from exc
            self._cache = keys
            self._fetched_at = self._clock()
            return keys

    def _is_fresh(self) -> bool:
        if self._cache is None or self._fetched_at is None:
            return False
        age = (self._clock() - self._fetched_at).total_seconds()
        return age < self._cache_seconds


def _parse_jwks(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise InvalidCredentialsError("JWKS document has no keys array")
    parsed: dict[str, Any] = {}
    for jwk in document["keys"]:
        if not isinstance(jwk, dict):
            continue
        if jwk.get("use") not in (None, "sig"):
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        try:
            parsed[kid] = _public_key_from_jwk(jwk)
        except (ValueError, TypeError, KeyError):
            # An unsupported/malformed key is skipped, not fatal: the issuer
            # may publish keys for other algorithms. If the requested kid is
            # only present in unusable form, verification fails closed.
            continue
    if not parsed:
        raise InvalidCredentialsError("JWKS contains no usable signing keys")
    return parsed


def _b64url_decode(value: str) -> bytes:
    padding_needed = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding_needed)
    except (binascii.Error, ValueError) as exc:
        raise InvalidCredentialsError("malformed base64url segment") from exc


def _b64url_uint(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def _public_key_from_jwk(jwk: Mapping[str, Any]) -> Any:
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _b64url_uint(str(jwk["n"]))
        e = _b64url_uint(str(jwk["e"]))
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        crv = jwk.get("crv")
        curves = {"P-256": ec.SECP256R1}
        if crv not in curves:
            raise ValueError(f"unsupported EC curve: {crv}")
        x = _b64url_uint(str(jwk["x"]))
        y = _b64url_uint(str(jwk["y"]))
        return ec.EllipticCurvePublicNumbers(x, y, curves[crv]()).public_key()
    raise ValueError(f"unsupported key type: {kty}")


def _verify_signature(*, alg: str, key: Any, signing_input: bytes, signature: bytes) -> None:
    try:
        if alg.startswith("RS"):
            hash_alg: hashes.HashAlgorithm
            if alg == "RS256":
                hash_alg = hashes.SHA256()
            elif alg == "RS384":
                hash_alg = hashes.SHA384()
            else:
                hash_alg = hashes.SHA512()
            key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
            return
        if alg == "ES256":
            if len(signature) != 64:
                raise InvalidSignature("ES256 signature must be 64 bytes")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der_signature = encode_dss_signature(r, s)
            key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
            return
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise InvalidCredentialsError("invalid token signature") from exc
    raise InvalidCredentialsError("unsupported signing algorithm")


def _numeric_date(claims: Mapping[str, Any], name: str) -> float:
    raw = claims.get(name)
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise InvalidCredentialsError(f"token claim {name} is missing or invalid")
    return float(raw)


def _audience_matches(audience: Any, expected: str) -> bool:
    if isinstance(audience, str):
        return audience == expected
    if isinstance(audience, list):
        return any(isinstance(item, str) and item == expected for item in audience)
    return False


class OIDCAuthenticator:
    """Validate an OIDC JWT, then refresh authorization from the directory."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: JwksProvider,
        directory: AuthorizationDirectory,
        algorithms: tuple[str, ...] = ALLOWED_ALGORITHMS,
        clock: Any | None = None,
        leeway_seconds: float = 30.0,
        max_token_age_seconds: float | None = 3600.0,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        if not audience:
            raise ValueError("audience is required")
        if not algorithms or any(alg not in ALLOWED_ALGORITHMS for alg in algorithms):
            raise ValueError("algorithms must be a non-empty subset of the allowlist")
        if leeway_seconds < 0:
            raise ValueError("leeway_seconds must be non-negative")
        self._issuer = issuer
        self._audience = audience
        self._jwks = jwks
        self._directory = directory
        self._algorithms = tuple(algorithms)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._leeway = leeway_seconds
        self._max_token_age = max_token_age_seconds

    async def authenticate(self, authorization: str | None) -> Principal:
        token = _extract_bearer(authorization)
        header, claims, signing_input, signature = _split_token(token)
        alg = header.get("alg")
        kid = header.get("kid")
        if not isinstance(alg, str) or alg not in self._algorithms:
            raise InvalidCredentialsError("token algorithm is not allowed")
        if not isinstance(kid, str) or not kid:
            raise InvalidCredentialsError("token key id is missing")

        key = await self._resolve_key(kid)
        _verify_signature(alg=alg, key=key, signing_input=signing_input, signature=signature)

        now = self._clock()
        expires_at = self._validate_claims(claims, now=now)
        subject = str(claims["sub"])
        issuer = str(claims["iss"])

        resolved = await self._directory.resolve(issuer=issuer, subject=subject)
        if resolved is None or not resolved.active:
            raise InvalidCredentialsError("reviewer is unknown or disabled")
        if not resolved.tenant_ids or not resolved.roles:
            raise InvalidCredentialsError("reviewer has no active tenant membership or role")
        try:
            roles = tuple(Role(role) for role in resolved.roles)
            tenant_ids = tuple(resolved.tenant_ids)
        except (ValueError, TypeError) as exc:
            raise InvalidCredentialsError("server-side authorization is malformed") from exc

        return Principal(
            principal_id=subject,
            tenant_ids=tenant_ids,
            roles=roles,
            auth_method="oidc",
            issuer=issuer,
            expires_at=expires_at,
        )

    async def _resolve_key(self, kid: str) -> Any:
        keys = await self._jwks.keys()
        key = keys.get(kid)
        if key is not None:
            return key
        # Unknown kid: one forced refresh supports key rotation. No retry loop.
        keys = await self._jwks.keys(force_refresh=True)
        key = keys.get(kid)
        if key is None:
            raise InvalidCredentialsError("token key id is not published")
        return key

    def _validate_claims(self, claims: Mapping[str, Any], *, now: datetime) -> datetime:
        if claims.get("iss") != self._issuer:
            raise InvalidCredentialsError("untrusted token issuer")
        if not _audience_matches(claims.get("aud"), self._audience):
            raise InvalidCredentialsError("token audience mismatch")

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip() or len(subject) > 256:
            raise InvalidCredentialsError("token subject is missing or invalid")

        exp = _numeric_date(claims, "exp")
        nbf = claims.get("nbf")
        iat = claims.get("iat")
        now_ts = now.timestamp()
        if now_ts > exp + self._leeway:
            raise InvalidCredentialsError("token expired")
        if nbf is not None:
            nbf_ts = _numeric_date(claims, "nbf")
            if now_ts + self._leeway < nbf_ts:
                raise InvalidCredentialsError("token is not yet valid")
        if iat is not None:
            iat_ts = _numeric_date(claims, "iat")
            if iat_ts > now_ts + self._leeway:
                raise InvalidCredentialsError("token issued in the future")
            if self._max_token_age is not None and now_ts - iat_ts > self._max_token_age:
                raise InvalidCredentialsError("token is older than the maximum accepted age")
        try:
            return datetime.fromtimestamp(exp, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise InvalidCredentialsError("invalid token expiry") from exc


def _extract_bearer(authorization: str | None) -> str:
    if not authorization:
        raise InvalidCredentialsError("missing bearer credential")
    if len(authorization) > 8192:
        raise InvalidCredentialsError("credential too large")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise InvalidCredentialsError("expected Bearer credential")
    return token


def _split_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidCredentialsError("malformed JWT")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
    except (ValueError, AuthenticationError) as exc:
        raise InvalidCredentialsError("malformed JWT payload") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise InvalidCredentialsError("malformed JWT payload")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(signature_b64)
    return header, claims, signing_input, signature
