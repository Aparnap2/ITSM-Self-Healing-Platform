"""Offline security unit tests for the OIDC relying party (``api/oidc.py``).

Every test here is deterministic and network-free:

- RSA and EC keys are generated in-process with ``cryptography``; no private
  key material is committed to the repository.
- JWTs are assembled by hand (``base64url(header).base64url(claims)`` plus a
  real asymmetric signature) so each fail-closed rule can be probed in
  isolation.
- The clock is a fixed, timezone-aware ``datetime`` so expiry/``nbf``/``iat``
  boundaries are reproducible.

The module under test resolves authorization from a trusted directory. Tokens
are only proof of identity: any tenant or role claim inside a token must be
ignored, and that property is asserted explicitly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from itsm_agent.api.auth import InvalidCredentialsError, Role
from itsm_agent.api.oidc import (
    ALLOWED_ALGORITHMS,
    AuthorizationDirectory,
    JwksProvider,
    OIDCAuthenticator,
    ReviewerAuthorization,
    StaticAuthorizationDirectory,
    StaticJwksProvider,
)

pytestmark = pytest.mark.unit

# Fixed reference instant for every time-based assertion.
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
NOW_TS = int(NOW.timestamp())
EXP_TS = NOW_TS + 300

ISSUER = "https://issuer.example.test"
AUDIENCE = "itsm-agent"
KID = "key-1"
OTHER_KID = "key-2"
TENANT = UUID("11111111-1111-1111-1111-111111111111")
BOGUS_TENANT = UUID("99999999-9999-9999-9999-999999999999")

_MISSING = object()


# ---------------------------------------------------------------------------
# Test keys and deterministic helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def rsa_keys(rsa_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    """Verification keys as ``StaticJwksProvider`` expects them (parsed)."""
    return {KID: rsa_key.public_key()}


def _clock() -> datetime:
    return NOW


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _encode_segments(
    header: Mapping[str, Any],
    claims: Mapping[str, Any],
) -> tuple[str, str, bytes]:
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    claims_segment = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
    return header_segment, claims_segment, signing_input


def _assemble(
    header: Mapping[str, Any],
    claims: Mapping[str, Any],
    signature: bytes,
) -> str:
    header_segment, claims_segment, _ = _encode_segments(header, claims)
    return f"{header_segment}.{claims_segment}.{_b64url(signature)}"


def _rs256_header(*, kid: str = KID) -> dict[str, Any]:
    return {"alg": "RS256", "kid": kid, "typ": "JWT"}


def _sign_rs256(signing_input: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _es256_signature(signing_input: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _rs256_token(
    claims: Mapping[str, Any],
    private_key: rsa.RSAPrivateKey,
    *,
    kid: str = KID,
) -> str:
    header = _rs256_header(kid=kid)
    _, _, signing_input = _encode_segments(header, claims)
    return _assemble(header, claims, _sign_rs256(signing_input, private_key))


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "iat": NOW_TS,
        "exp": EXP_TS,
    }
    claims.update(overrides)
    return claims


def _entry(
    *,
    active: bool = True,
    tenant_ids: tuple[UUID, ...] = (TENANT,),
    roles: tuple[str, ...] = ("reviewer",),
) -> ReviewerAuthorization:
    return ReviewerAuthorization(
        active=active,
        tenant_ids=tenant_ids,
        roles=roles,
        authorization_version="version-1",
    )


def _directory(
    entries: Mapping[str, ReviewerAuthorization],
) -> StaticAuthorizationDirectory:
    return StaticAuthorizationDirectory(
        {(ISSUER, subject): authorization for subject, authorization in entries.items()}
    )


def _authenticator(
    *,
    jwks: JwksProvider,
    directory: AuthorizationDirectory,
    max_token_age_seconds: float | None = 3600.0,
) -> OIDCAuthenticator:
    return OIDCAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=jwks,
        directory=directory,
        clock=_clock,
        max_token_age_seconds=max_token_age_seconds,
    )


def _static_auth(
    rsa_keys: Mapping[str, Any],
    *,
    entries: Mapping[str, ReviewerAuthorization] | None = None,
    max_token_age_seconds: float | None = 3600.0,
) -> OIDCAuthenticator:
    return _authenticator(
        jwks=StaticJwksProvider(rsa_keys),
        directory=_directory(entries if entries is not None else {"alice": _entry()}),
        max_token_age_seconds=max_token_age_seconds,
    )


class _RecordingJwksProvider:
    """JWKS provider that records refresh requests and can serve a rotation."""

    def __init__(
        self,
        initial: Mapping[str, Any],
        *,
        refreshed: Mapping[str, Any] | None = None,
    ) -> None:
        self._current = dict(initial)
        self._refreshed = dict(refreshed) if refreshed is not None else None
        self.calls: list[bool] = []

    async def keys(self, *, force_refresh: bool = False) -> Mapping[str, Any]:
        self.calls.append(force_refresh)
        if force_refresh and self._refreshed is not None:
            self._current = self._refreshed
            self._refreshed = None
        return dict(self._current)


# ---------------------------------------------------------------------------
# 1. Directory, not token claims, is the authorization source of truth
# ---------------------------------------------------------------------------


async def test_valid_token_authorizes_from_directory_not_token_claims(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    claims = _claims(
        # Hostile/forged claims: a valid signature must not turn these into
        # authorization data.
        tenant_ids=[str(BOGUS_TENANT)],
        tenants=[str(BOGUS_TENANT)],
        roles=["admin"],
    )
    token = _rs256_token(claims, rsa_key)
    authority = _static_auth(
        rsa_keys,
        entries={"alice": _entry(roles=("reviewer", "auditor"))},
    )

    principal = await authority.authenticate(f"Bearer {token}")

    assert principal.principal_id == "alice"
    assert principal.tenant_ids == (TENANT,)
    assert principal.roles == (Role.REVIEWER, Role.AUDITOR)
    assert principal.auth_method == "oidc"
    assert principal.issuer == ISSUER
    assert principal.expires_at == datetime.fromtimestamp(EXP_TS, tz=UTC)
    # The directory grant must win over the (bogus) token claim.
    assert not principal.may_access_tenant(BOGUS_TENANT)
    assert Role.ADMIN not in principal.roles


# ---------------------------------------------------------------------------
# 2. Authorization header handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        "bearer",
        "Basic YWJj",
        "Token abc.def.ghi",
        "Bearer\tx.y.z",
        "Beareré",
    ],
)
async def test_missing_or_malformed_authorization_header_is_rejected(
    header: str | None,
    rsa_keys: dict[str, Any],
) -> None:
    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(header)


async def test_oversized_authorization_header_is_rejected(
    rsa_keys: dict[str, Any],
) -> None:
    # 8192 bytes is the extractor's ceiling; stay clearly above it.
    header = "Bearer " + "a" * 9000
    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(header)


# ---------------------------------------------------------------------------
# 3. Structural JWT malformation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    [
        "one-segment",
        "two-segments",
        "four-segments",
        "non-json-header",
        "non-json-payload",
        "header-not-object",
        "non-ascii",
    ],
)
async def test_structurally_malformed_jwt_is_rejected(
    case: str,
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    valid = _rs256_token(_claims(), rsa_key)
    header_segment, payload_segment, signature_segment = valid.split(".")
    tokens = {
        "one-segment": "not-a-jwt",
        "two-segments": "a.b",
        "four-segments": "a.b.c.d",
        "non-json-header": f"{_b64url(b'not-json')}.{payload_segment}.{signature_segment}",
        "non-json-payload": f"{header_segment}.{_b64url(b'not-json')}.{signature_segment}",
        "header-not-object": f"{_b64url(b'[]')}.{payload_segment}.{signature_segment}",
        "non-ascii": "é.é.é",
    }

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {tokens[case]}")


# ---------------------------------------------------------------------------
# 4. Algorithm confusion (alg=none, symmetric HS*, unlisted algorithms)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "alg",
    ["none", "None", "HS256", "HS384", "HS512", "PS256", "ES384", "rs256", ""],
)
async def test_disallowed_algorithm_is_rejected(
    alg: str,
    rsa_keys: dict[str, Any],
) -> None:
    header: dict[str, Any] = {"alg": alg, "kid": KID, "typ": "JWT"}
    claims = _claims()
    _, _, signing_input = _encode_segments(header, claims)
    # For HS* this is a *valid* HMAC-SHA256 signature over the signing input;
    # it must still be rejected because the algorithm is not allowlisted.
    signature = hmac.new(b"attacker-shared-secret", signing_input, hashlib.sha256).digest()
    token = _assemble(header, claims, signature)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_missing_algorithm_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    header: dict[str, Any] = {"kid": KID, "typ": "JWT"}
    _, _, signing_input = _encode_segments(header, _claims())
    token = _assemble(header, _claims(), _sign_rs256(signing_input, rsa_key))

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


# ---------------------------------------------------------------------------
# 5. Key identifier handling and rotation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kid", [None, ""])
async def test_missing_or_blank_key_id_is_rejected(
    kid: str | None,
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    header: dict[str, Any] = {"alg": "RS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    _, _, signing_input = _encode_segments(header, _claims())
    token = _assemble(header, _claims(), _sign_rs256(signing_input, rsa_key))

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_unknown_kid_forces_exactly_one_refresh_then_fails(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    provider = _RecordingJwksProvider({KID: rsa_key.public_key()})
    token = _rs256_token(_claims(), rsa_key, kid="never-published")
    authority = _authenticator(
        jwks=provider,
        directory=_directory({"alice": _entry()}),
    )

    with pytest.raises(InvalidCredentialsError):
        await authority.authenticate(f"Bearer {token}")

    # One cache lookup followed by exactly one forced refresh. No retry loop.
    assert provider.calls == [False, True]


async def test_rotated_key_is_accepted_after_forced_refresh(
    rsa_key: rsa.RSAPrivateKey,
    other_rsa_key: rsa.RSAPrivateKey,
) -> None:
    provider = _RecordingJwksProvider(
        {KID: rsa_key.public_key()},
        refreshed={
            KID: rsa_key.public_key(),
            OTHER_KID: other_rsa_key.public_key(),
        },
    )
    token = _rs256_token(_claims(), other_rsa_key, kid=OTHER_KID)
    authority = _authenticator(
        jwks=provider,
        directory=_directory({"alice": _entry()}),
    )

    principal = await authority.authenticate(f"Bearer {token}")

    assert principal.principal_id == "alice"
    assert provider.calls == [False, True]


# ---------------------------------------------------------------------------
# 6. Signature integrity
# ---------------------------------------------------------------------------


async def test_tampered_payload_with_original_signature_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    header_segment, _, signature_segment = token.split(".")
    _, forged_payload_segment, _ = _encode_segments(_rs256_header(), _claims(sub="mallory"))
    forged = f"{header_segment}.{forged_payload_segment}.{signature_segment}"

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {forged}")


async def test_tampered_signature_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    header_segment, payload_segment, signature_segment = token.split(".")
    signature = bytearray(base64.urlsafe_b64decode(signature_segment + "=="))
    signature[0] ^= 0xFF
    forged = f"{header_segment}.{payload_segment}.{_b64url(bytes(signature))}"

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {forged}")


# ---------------------------------------------------------------------------
# 7. Claim validation: issuer, audience, time windows
# ---------------------------------------------------------------------------


async def test_wrong_issuer_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(iss="https://attacker.example.test"), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_wrong_audience_string_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(aud="some-other-api"), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_audience_array_without_expected_value_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(aud=["other-api", "another-api"]), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_audience_array_containing_expected_value_is_accepted(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(aud=["other-api", AUDIENCE]), rsa_key)

    principal = await _static_auth(rsa_keys).authenticate(f"Bearer {token}")

    assert principal.principal_id == "alice"


async def test_expired_token_beyond_leeway_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    # Default leeway is 30s; 31s past expiry must fail.
    token = _rs256_token(_claims(exp=NOW_TS - 31), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_expired_within_leeway_is_accepted(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(exp=NOW_TS - 20), rsa_key)

    principal = await _static_auth(rsa_keys).authenticate(f"Bearer {token}")

    assert principal.expires_at == datetime.fromtimestamp(NOW_TS - 20, tz=UTC)


async def test_not_yet_valid_token_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    # nbf must not be later than now + leeway (30s).
    token = _rs256_token(_claims(nbf=NOW_TS + 31), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_token_issued_in_the_future_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(iat=NOW_TS + 31), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


async def test_token_older_than_max_age_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(iat=NOW_TS - 3601), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys, max_token_age_seconds=3600.0).authenticate(f"Bearer {token}")


# ---------------------------------------------------------------------------
# 8. Subject claim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("subject", [_MISSING, "", "   ", "a" * 257, 123])
async def test_missing_blank_or_oversized_subject_is_rejected(
    subject: object,
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    claims = _claims()
    if subject is _MISSING:
        del claims["sub"]
    else:
        claims["sub"] = subject
    token = _rs256_token(claims, rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys).authenticate(f"Bearer {token}")


# ---------------------------------------------------------------------------
# 9. Directory authorization state
# ---------------------------------------------------------------------------


async def test_unknown_reviewer_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    authority = _static_auth(rsa_keys, entries={})

    with pytest.raises(InvalidCredentialsError):
        await authority.authenticate(f"Bearer {token}")


async def test_disabled_reviewer_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    authority = _static_auth(rsa_keys, entries={"alice": _entry(active=False)})

    with pytest.raises(InvalidCredentialsError):
        await authority.authenticate(f"Bearer {token}")


async def test_reviewer_without_tenant_membership_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    authority = _static_auth(rsa_keys, entries={"alice": _entry(tenant_ids=())})

    with pytest.raises(InvalidCredentialsError):
        await authority.authenticate(f"Bearer {token}")


async def test_reviewer_without_roles_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    authority = _static_auth(rsa_keys, entries={"alice": _entry(roles=())})

    with pytest.raises(InvalidCredentialsError):
        await authority.authenticate(f"Bearer {token}")


async def test_unknown_role_in_directory_is_rejected(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    token = _rs256_token(_claims(), rsa_key)
    authority = _static_auth(rsa_keys, entries={"alice": _entry(roles=("superuser",))})

    with pytest.raises(InvalidCredentialsError):
        await authority.authenticate(f"Bearer {token}")


# ---------------------------------------------------------------------------
# 10. Constructor validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": ""},
        {"audience": ""},
        {"algorithms": ()},
        {"algorithms": ("HS256",)},
        {"algorithms": ("none",)},
        {"algorithms": ("RS256", "HS256")},
        {"leeway_seconds": -1.0},
    ],
)
def test_constructor_rejects_invalid_configuration(
    overrides: dict[str, Any],
    rsa_keys: dict[str, Any],
) -> None:
    kwargs: dict[str, Any] = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks": StaticJwksProvider(rsa_keys),
        "directory": StaticAuthorizationDirectory({}),
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError):
        OIDCAuthenticator(**kwargs)


# ---------------------------------------------------------------------------
# 11. Algorithm allowlist
# ---------------------------------------------------------------------------


def test_allowed_algorithms_exclude_symmetric_and_none() -> None:
    assert ALLOWED_ALGORITHMS
    assert isinstance(ALLOWED_ALGORITHMS, tuple)
    assert set(ALLOWED_ALGORITHMS) == {"RS256", "RS384", "RS512", "ES256"}
    for algorithm in ALLOWED_ALGORITHMS:
        assert algorithm != "none"
        assert not algorithm.upper().startswith("HS")


# ---------------------------------------------------------------------------
# EC accept path (exercises the P-256 JWK branch with a real signature)
# ---------------------------------------------------------------------------


async def test_es256_token_authenticates(ec_key: ec.EllipticCurvePrivateKey) -> None:
    header: dict[str, Any] = {"alg": "ES256", "kid": KID, "typ": "JWT"}
    claims = _claims()
    _, _, signing_input = _encode_segments(header, claims)
    token = _assemble(header, claims, _es256_signature(signing_input, ec_key))
    authority = _authenticator(
        jwks=StaticJwksProvider({KID: ec_key.public_key()}),
        directory=_directory({"alice": _entry()}),
    )

    principal = await authority.authenticate(f"Bearer {token}")

    assert principal.principal_id == "alice"
    assert principal.roles == (Role.REVIEWER,)


# ---------------------------------------------------------------------------
# Regression: token age must not be bypassable by omitting ``iat``
# ---------------------------------------------------------------------------


async def test_token_without_iat_is_rejected_when_max_age_is_enforced(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    """A token with no ``iat`` would otherwise have unbounded age.

    ``max_token_age_seconds`` is a fail-closed control: if the relying party
    cannot prove how old a token is, it must not accept it.
    """
    claims = _claims()
    del claims["iat"]
    token = _rs256_token(claims, rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys, max_token_age_seconds=3600.0).authenticate(f"Bearer {token}")


async def test_token_without_iat_is_accepted_only_when_max_age_is_disabled(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    claims = _claims()
    del claims["iat"]
    token = _rs256_token(claims, rsa_key)

    principal = await _static_auth(rsa_keys, max_token_age_seconds=None).authenticate(
        f"Bearer {token}"
    )

    assert principal.principal_id == "alice"


def test_constructor_rejects_negative_max_token_age(
    rsa_keys: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        _authenticator(
            jwks=StaticJwksProvider(rsa_keys),
            directory=_directory({"alice": _entry()}),
            max_token_age_seconds=-1.0,
        )


# ---------------------------------------------------------------------------
# Regression: an over-long subject must be a 401, never a 500
# ---------------------------------------------------------------------------


async def test_subject_longer_than_principal_limit_is_a_credential_error(
    rsa_key: rsa.RSAPrivateKey,
    rsa_keys: dict[str, Any],
) -> None:
    """``Principal.principal_id`` caps at 128 chars.

    A 200-char ``sub`` previously passed claim validation and then raised an
    uncaught pydantic ``ValidationError`` while building the ``Principal``,
    which surfaces as HTTP 500 instead of a fail-closed 401.
    """
    subject = "s" * 200
    token = _rs256_token(_claims(sub=subject), rsa_key)

    with pytest.raises(InvalidCredentialsError):
        await _static_auth(rsa_keys, entries={subject: _entry()}).authenticate(f"Bearer {token}")
