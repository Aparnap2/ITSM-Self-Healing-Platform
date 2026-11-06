"""Unit tests for the caching HTTP JWKS provider (``api/oidc.py``).

Every HTTP interaction is mocked with ``respx``; no test here touches the
network. RSA and EC keys are generated in-process with ``cryptography``, so no
private key material is committed to the repository. The cache clock is
injected and deterministic.

Security contract asserted here:

- the JWKS URL must be an absolute ``https://`` URL and ``cache_seconds``
  must be positive; both are rejected at construction;
- redirects are never followed, even when the injected client was built with
  ``follow_redirects=True`` (no cross-host key substitution);
- the response size cap is enforced while streaming, so an oversized body is
  aborted early instead of being buffered whole;
- one malformed published key is skipped, and the remaining usable keys are
  still returned;
- fetch/parse failures never serve stale keys beyond their TTL.

The provider has no ``timeout`` or ``leeway`` parameter; the HTTP timeout is
whatever the injected ``httpx.AsyncClient`` carries.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from itsm_agent.api.auth import InvalidCredentialsError
from itsm_agent.api.oidc import HttpJwksProvider, _parse_jwks

pytestmark = pytest.mark.unit

JWKS_URL = "https://issuer.example.test/.well-known/jwks.json"
REDIRECT_URL = "https://keys.attacker.example.test/jwks.json"
KID_RSA = "rsa-key-1"
KID_RSA_OTHER = "rsa-key-2"
KID_EC = "ec-key-1"
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
DEFAULT_CACHE_SECONDS = 300.0


# ---------------------------------------------------------------------------
# Deterministic helpers: clock, keys, JWK documents, mocked transport
# ---------------------------------------------------------------------------


@dataclass
class _Clock:
    """Fixed-step clock injected into ``HttpJwksProvider``."""

    now: datetime = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_int(value: int, *, length: int | None = None) -> str:
    size = length if length is not None else max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(size, "big"))


def _rsa_jwk(
    key: rsa.RSAPrivateKey,
    *,
    kid: str = KID_RSA,
    use: str | None = "sig",
    **overrides: Any,
) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    jwk: dict[str, Any] = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": _b64url_int(numbers.n),
        "e": _b64url_int(numbers.e),
    }
    if use is not None:
        jwk["use"] = use
    jwk.update(overrides)
    return jwk


def _ec_jwk(
    key: ec.EllipticCurvePrivateKey,
    *,
    kid: str = KID_EC,
    crv: str = "P-256",
    **overrides: Any,
) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    jwk: dict[str, Any] = {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "crv": crv,
        "x": _b64url_int(numbers.x, length=32),
        "y": _b64url_int(numbers.y, length=32),
    }
    jwk.update(overrides)
    return jwk


def _jwks_response(*jwks: Mapping[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"keys": list(jwks)})


def _sequence(
    outcomes: list[httpx.Response | Exception],
) -> Callable[[httpx.Request], httpx.Response]:
    """Return a respx side effect that plays ``outcomes`` back in order."""

    pending = list(outcomes)

    def handler(request: httpx.Request) -> httpx.Response:
        outcome = pending.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return handler


@asynccontextmanager
async def _client(
    *,
    timeout: float | httpx.Timeout = 5.0,
    follow_redirects: bool = False,
) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=follow_redirects) as client:
        yield client


def _provider(
    client: httpx.AsyncClient,
    *,
    clock: _Clock,
    url: str = JWKS_URL,
    cache_seconds: float = DEFAULT_CACHE_SECONDS,
) -> HttpJwksProvider:
    return HttpJwksProvider(url=url, client=client, cache_seconds=cache_seconds, clock=clock)


def _rs256_signature(signing_input: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _raw_es256_signature(signing_input: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class _CountingAsyncStream(httpx.AsyncByteStream):
    """Async body stream that records how many chunks were consumed."""

    def __init__(self, chunks: list[bytes], consumed: list[int]) -> None:
        self._chunks = chunks
        self._consumed = consumed

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            self._consumed[0] += 1
            yield chunk


# ---------------------------------------------------------------------------
# 1. Construction: what is and is not validated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not-a-url",
        "://bad",
        "ftp://issuer.example.test/jwks",
        "http://issuer.example.test/jwks.json",
        "https://",
    ],
)
async def test_constructor_rejects_malformed_or_non_https_url(url: str) -> None:
    """A JWKS URL must be absolute https; anything else fails at construction."""
    async with _client() as client:
        with pytest.raises(ValueError, match="https"):
            _provider(client, clock=_Clock(), url=url)


@pytest.mark.parametrize("cache_seconds", [0.0, -1.0])
async def test_constructor_rejects_non_positive_cache_seconds(
    cache_seconds: float,
) -> None:
    """A non-positive TTL would disable caching and hammer the issuer."""
    async with _client() as client:
        with pytest.raises(ValueError, match="cache_seconds"):
            _provider(client, clock=_Clock(), cache_seconds=cache_seconds)


@pytest.mark.parametrize(
    "extra",
    [{"timeout": 1.0}, {"leeway_seconds": -1.0}, {"leeway": -1.0}],
)
async def test_constructor_has_no_timeout_or_leeway_parameters(extra: dict[str, Any]) -> None:
    """The provider exposes no timeout or leeway knob at all.

    The HTTP timeout is the injected client's; there is no cache-freshness
    leeway. Passing either keyword is a ``TypeError``, not a ``ValueError``.
    """
    async with _client() as client:
        kwargs: dict[str, Any] = {"url": JWKS_URL, "client": client, **extra}
        with pytest.raises(TypeError):
            HttpJwksProvider(**kwargs)


async def test_https_url_is_accepted_and_fetched(rsa_key: rsa.RSAPrivateKey) -> None:
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(return_value=_jwks_response(_rsa_jwk(rsa_key)))
            provider = _provider(client, clock=_Clock())

            keys = await provider.keys()

            assert router.calls.call_count == 1

    assert set(keys) == {KID_RSA}


# ---------------------------------------------------------------------------
# 2. Successful fetch: parsed keys really verify signatures
# ---------------------------------------------------------------------------


async def test_fetch_returns_public_keys_keyed_by_kid(
    rsa_key: rsa.RSAPrivateKey,
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            route = router.get(JWKS_URL).mock(
                return_value=_jwks_response(_rsa_jwk(rsa_key), _ec_jwk(ec_key))
            )
            provider = _provider(client, clock=_Clock())

            keys = await provider.keys()

            assert route.called
            assert route.calls.call_count == 1

    assert set(keys) == {KID_RSA, KID_EC}
    assert isinstance(keys[KID_RSA], rsa.RSAPublicKey)
    assert isinstance(keys[KID_EC], ec.EllipticCurvePublicKey)


async def test_fetched_rsa_key_verifies_rs256_signature(rsa_key: rsa.RSAPrivateKey) -> None:
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(return_value=_jwks_response(_rsa_jwk(rsa_key)))
            provider = _provider(client, clock=_Clock())

            keys = await provider.keys()

    public_key = keys[KID_RSA]
    signing_input = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9"
    signature = _rs256_signature(signing_input, rsa_key)

    # The parsed key verifies a genuine PKCS#1 v1.5 SHA-256 signature...
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    # ...and does not verify a different message.
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, b"different-input", padding.PKCS1v15(), hashes.SHA256())


async def test_fetched_ec_p256_key_verifies_es256_signature(
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(return_value=_jwks_response(_ec_jwk(ec_key)))
            provider = _provider(client, clock=_Clock())

            keys = await provider.keys()

    public_key = keys[KID_EC]
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert public_key.curve.name == "secp256r1"

    signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9"
    raw_signature = _raw_es256_signature(signing_input, ec_key)
    der_signature = encode_dss_signature(
        int.from_bytes(raw_signature[:32], "big"),
        int.from_bytes(raw_signature[32:], "big"),
    )

    public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# 3-5. Caching: single flight, forced refresh, expiry, boundary
# ---------------------------------------------------------------------------


async def test_two_calls_within_cache_window_make_exactly_one_request(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    clock = _Clock()
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            route = router.get(JWKS_URL).mock(return_value=_jwks_response(_rsa_jwk(rsa_key)))
            provider = _provider(client, clock=clock)

            first = await provider.keys()
            clock.advance(DEFAULT_CACHE_SECONDS - 1.0)
            second = await provider.keys()

            assert route.calls.call_count == 1
            assert router.calls.call_count == 1

    assert first == second
    assert set(second) == {KID_RSA}


async def test_force_refresh_bypasses_a_fresh_cache(
    rsa_key: rsa.RSAPrivateKey,
    other_rsa_key: rsa.RSAPrivateKey,
) -> None:
    clock = _Clock()
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                side_effect=_sequence(
                    [
                        _jwks_response(_rsa_jwk(rsa_key)),
                        _jwks_response(_rsa_jwk(other_rsa_key, kid=KID_RSA_OTHER)),
                    ]
                )
            )
            provider = _provider(client, clock=clock)

            first = await provider.keys()
            second = await provider.keys(force_refresh=True)

            # The refreshed cache is what subsequent non-forced calls see.
            third = await provider.keys()

            assert router.calls.call_count == 2

    assert set(first) == {KID_RSA}
    assert set(second) == {KID_RSA_OTHER}
    assert set(third) == {KID_RSA_OTHER}


async def test_cache_expiry_beyond_cache_seconds_refetches(rsa_key: rsa.RSAPrivateKey) -> None:
    clock = _Clock()
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                side_effect=_sequence(
                    [
                        _jwks_response(_rsa_jwk(rsa_key)),
                        _jwks_response(_rsa_jwk(rsa_key), _rsa_jwk(rsa_key, kid=KID_RSA_OTHER)),
                    ]
                )
            )
            provider = _provider(client, clock=clock)

            await provider.keys()
            clock.advance(DEFAULT_CACHE_SECONDS + 1.0)
            refreshed = await provider.keys()

            assert router.calls.call_count == 2

    assert set(refreshed) == {KID_RSA, KID_RSA_OTHER}


@pytest.mark.parametrize(
    ("advance_seconds", "expected_requests"),
    # Freshness is ``age < cache_seconds``; the TTL boundary itself is stale.
    [(DEFAULT_CACHE_SECONDS - 0.5, 1), (DEFAULT_CACHE_SECONDS, 2)],
)
async def test_cache_freshness_boundary_is_strictly_less_than_ttl(
    advance_seconds: float,
    expected_requests: int,
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    clock = _Clock()
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                side_effect=_sequence(
                    [_jwks_response(_rsa_jwk(rsa_key)), _jwks_response(_rsa_jwk(rsa_key))]
                )
            )
            provider = _provider(client, clock=clock)

            await provider.keys()
            clock.advance(advance_seconds)
            await provider.keys()

            assert router.calls.call_count == expected_requests


# ---------------------------------------------------------------------------
# 6. Failure handling: no stale keys, recovery on a later success
# ---------------------------------------------------------------------------


def _failure_response(kind: str) -> httpx.Response:
    if kind == "status-500":
        return httpx.Response(500, text="upstream exploded")
    if kind == "non-json":
        return httpx.Response(200, text="<html>not a JWKS</html>")
    if kind == "json-array":
        return httpx.Response(200, json=[])
    if kind == "oversized":
        return httpx.Response(200, content=b"x" * (HttpJwksProvider.MAX_BYTES + 1))
    raise AssertionError(f"unknown failure kind: {kind}")


@pytest.mark.parametrize(
    "failure",
    ["connect-error", "status-500", "non-json", "json-array", "oversized"],
)
async def test_fetch_failure_raises_and_does_not_serve_expired_keys(
    failure: str,
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    clock = _Clock()
    good = _jwks_response(_rsa_jwk(rsa_key))
    broken: httpx.Response | Exception = (
        httpx.ConnectError("upstream unreachable")
        if failure == "connect-error"
        else _failure_response(failure)
    )

    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(side_effect=_sequence([good, broken, good]))
            provider = _provider(client, clock=clock)

            assert set(await provider.keys()) == {KID_RSA}

            # Cache is now expired; the failing fetch must raise, not return
            # the previously cached key set.
            clock.advance(DEFAULT_CACHE_SECONDS + 1.0)
            with pytest.raises(InvalidCredentialsError):
                await provider.keys()

            assert router.calls.call_count == 2

            # A later successful fetch recovers without a restart.
            recovered = await provider.keys()
            assert router.calls.call_count == 3

    assert set(recovered) == {KID_RSA}


async def test_http_500_is_wrapped_as_invalid_credentials(rsa_key: rsa.RSAPrivateKey) -> None:
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(return_value=httpx.Response(503, text="nope"))
            provider = _provider(client, clock=_Clock())

            with pytest.raises(InvalidCredentialsError) as excinfo:
                await provider.keys()

            assert router.calls.call_count == 1

    assert isinstance(excinfo.value.__cause__, httpx.HTTPStatusError)


async def test_failed_forced_refresh_does_not_extend_cache_lifetime(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """A failed forced refresh leaves the previous fetch timestamp untouched.

    Consequence: a failed refresh cannot extend the trust window of cached
    keys. The still-fresh cache remains servable by later non-forced calls
    (that is the TTL working as designed), but its age is not reset, so the
    next call after the original TTL refetches.
    """
    clock = _Clock()
    good = _jwks_response(_rsa_jwk(rsa_key))

    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                side_effect=_sequence([good, httpx.ConnectError("down"), good])
            )
            provider = _provider(client, clock=clock)

            await provider.keys()
            clock.advance(DEFAULT_CACHE_SECONDS - 100.0)

            with pytest.raises(InvalidCredentialsError):
                await provider.keys(force_refresh=True)

            # Cache is still within its original TTL and is served as-is.
            still_cached = await provider.keys()
            assert router.calls.call_count == 2

            # Advancing past the original TTL forces a real refetch.
            clock.advance(101.0)
            await provider.keys()
            assert router.calls.call_count == 3

    assert set(still_cached) == {KID_RSA}


# ---------------------------------------------------------------------------
# 7. Size cap: buffered bytes, not Content-Length; chunked bodies are fully read
# ---------------------------------------------------------------------------


async def test_oversized_buffered_body_is_rejected(rsa_key: rsa.RSAPrivateKey) -> None:
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                return_value=httpx.Response(200, content=b"x" * (HttpJwksProvider.MAX_BYTES + 1))
            )
            provider = _provider(client, clock=_Clock())

            with pytest.raises(InvalidCredentialsError, match="too large"):
                await provider.keys()

            assert router.calls.call_count == 1


async def test_oversized_chunked_body_aborts_during_streaming() -> None:
    """The cap is enforced while reading, not after full buffering.

    Two chunks already exceed ``MAX_BYTES``; the third must never be consumed.
    """
    consumed = [0]
    chunk_size = HttpJwksProvider.MAX_BYTES // 2 + 1

    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                return_value=httpx.Response(
                    200,
                    stream=_CountingAsyncStream([b"x" * chunk_size] * 3, consumed),
                )
            )
            provider = _provider(client, clock=_Clock())

            with pytest.raises(InvalidCredentialsError, match="too large"):
                await provider.keys()

            assert router.calls.call_count == 1

    assert consumed == [2]


async def test_declared_content_length_is_not_trusted_for_the_size_cap(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """A huge ``Content-Length`` header with a small body is accepted.

    The implementation measures ``len(response.content)``, so the header
    neither short-circuits nor inflates the check.
    """
    body = json.dumps({"keys": [_rsa_jwk(rsa_key)]}).encode()
    async with _client() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(JWKS_URL).mock(
                return_value=httpx.Response(
                    200,
                    content=body,
                    headers={"Content-Length": str(HttpJwksProvider.MAX_BYTES * 4)},
                )
            )
            provider = _provider(client, clock=_Clock())

            keys = await provider.keys()

            assert router.calls.call_count == 1

    assert set(keys) == {KID_RSA}


# ---------------------------------------------------------------------------
# 8. ``_parse_jwks`` filtering
# ---------------------------------------------------------------------------


def test_parse_jwks_returns_one_key_per_kid(rsa_key: rsa.RSAPrivateKey) -> None:
    parsed = _parse_jwks({"keys": [_rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_RSA}
    assert isinstance(parsed[KID_RSA], rsa.RSAPublicKey)


@pytest.mark.parametrize("entry", ["not-a-dict", 42, None, ["nested"], True])
def test_parse_jwks_skips_non_dict_entries(entry: Any, rsa_key: rsa.RSAPrivateKey) -> None:
    parsed = _parse_jwks({"keys": [entry, _rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_RSA}


def test_parse_jwks_skips_non_signing_use(rsa_key: rsa.RSAPrivateKey) -> None:
    parsed = _parse_jwks({"keys": [_rsa_jwk(rsa_key, kid="enc", use="enc"), _rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_RSA}


def test_parse_jwks_treats_absent_use_as_signing(rsa_key: rsa.RSAPrivateKey) -> None:
    parsed = _parse_jwks({"keys": [_rsa_jwk(rsa_key, use=None)]})

    assert set(parsed) == {KID_RSA}


@pytest.mark.parametrize("kid", [None, "", 123, ["kid"]])
def test_parse_jwks_skips_missing_or_blank_kid(
    kid: Any,
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    jwk = _rsa_jwk(rsa_key, kid="placeholder")
    if kid is None:
        del jwk["kid"]
    else:
        jwk["kid"] = kid

    parsed = _parse_jwks({"keys": [jwk, _rsa_jwk(rsa_key, kid=KID_RSA_OTHER)]})

    assert set(parsed) == {KID_RSA_OTHER}


def test_parse_jwks_skips_unsupported_key_types(rsa_key: rsa.RSAPrivateKey) -> None:
    oct_jwk = {"kty": "oct", "kid": "hmac-key", "use": "sig", "k": "c2VjcmV0"}

    parsed = _parse_jwks({"keys": [oct_jwk, _rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_RSA}


def test_parse_jwks_skips_unsupported_ec_curves(
    ec_key: ec.EllipticCurvePrivateKey,
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    # Coordinates are P-256 sized; only the declared curve is unsupported.
    p521_jwk = _ec_jwk(ec_key, kid="p521", crv="P-521")

    parsed = _parse_jwks({"keys": [p521_jwk, _ec_jwk(ec_key), _rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_EC, KID_RSA}


def _malformed_jwk(
    case: str,
    rsa_key: rsa.RSAPrivateKey,
    ec_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    if case == "rsa-missing-modulus":
        jwk = _rsa_jwk(rsa_key, kid="broken")
        del jwk["n"]
        return jwk
    if case == "rsa-zero-modulus":
        return _rsa_jwk(rsa_key, kid="broken", n="AA")
    if case == "rsa-zero-exponent":
        return _rsa_jwk(rsa_key, kid="broken", e="AA")
    if case == "ec-missing-y":
        jwk = _ec_jwk(ec_key, kid="broken")
        del jwk["y"]
        return jwk
    if case == "ec-point-not-on-curve":
        return _ec_jwk(
            ec_key,
            kid="broken",
            x=_b64url_int(1, length=32),
            y=_b64url_int(1, length=32),
        )
    raise AssertionError(f"unknown malformed-key case: {case}")


@pytest.mark.parametrize(
    "case",
    [
        "rsa-missing-modulus",
        "rsa-zero-modulus",
        "rsa-zero-exponent",
        "ec-missing-y",
        "ec-point-not-on-curve",
    ],
)
def test_parse_jwks_skips_malformed_keys(
    case: str,
    rsa_key: rsa.RSAPrivateKey,
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    parsed = _parse_jwks({"keys": [_malformed_jwk(case, rsa_key, ec_key), _rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_RSA}


@pytest.mark.parametrize(
    "document",
    [
        {"keys": []},
        {"keys": [{"kty": "oct", "kid": "k", "use": "sig"}]},
        {"keys": [None, 42]},
        {"keys": [{"kty": "EC", "kid": "k", "crv": "P-521", "x": "AA", "y": "AA"}]},
    ],
)
def test_parse_jwks_document_without_usable_keys_raises(document: Any) -> None:
    with pytest.raises(InvalidCredentialsError, match="no usable signing keys"):
        _parse_jwks(document)


@pytest.mark.parametrize(
    "document",
    [
        [],
        "a string",
        None,
        42,
        {},
        {"keys": "not-a-list"},
        {"keys": {"kid": "x"}},
        {"keys": None},
    ],
)
def test_parse_jwks_rejects_document_without_keys_array(document: Any) -> None:
    with pytest.raises(InvalidCredentialsError, match="no keys array"):
        _parse_jwks(document)


def test_parse_jwks_skips_a_malformed_key_and_keeps_usable_keys(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """One broken published key must not deny verification with the others."""
    broken = _rsa_jwk(rsa_key, kid="broken", n="a")

    parsed = _parse_jwks({"keys": [broken, _rsa_jwk(rsa_key)]})

    assert set(parsed) == {KID_RSA}


# ---------------------------------------------------------------------------
# 10. Request target, timeout, credential hygiene, redirect policy
# ---------------------------------------------------------------------------


async def test_request_uses_configured_url_bounded_timeout_and_no_credentials(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["timeout"] = dict(request.extensions["timeout"])
        captured["headers"] = dict(request.headers)
        return _jwks_response(_rsa_jwk(rsa_key))

    async with _client(timeout=2.0) as client:
        with respx.mock(assert_all_called=False) as router:
            route = router.get(JWKS_URL).mock(side_effect=handler)
            provider = _provider(client, clock=_Clock())

            await provider.keys()

            assert route.calls.call_count == 1

    assert captured["url"] == JWKS_URL
    assert captured["method"] == "GET"
    # httpx stamps the effective timeout onto the request extensions.
    assert set(captured["timeout"]) == {"connect", "read", "write", "pool"}
    assert all(value == 2.0 for value in captured["timeout"].values())
    # The provider adds no credential or cookie to the JWKS request.
    assert "authorization" not in captured["headers"]
    assert "cookie" not in captured["headers"]


async def test_cross_host_redirect_is_not_followed_by_a_default_client(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    async with _client() as client:
        assert client.follow_redirects is False
        with respx.mock(assert_all_called=False) as router:
            redirect = router.get(JWKS_URL).mock(
                return_value=httpx.Response(302, headers={"Location": REDIRECT_URL})
            )
            attacker = router.get(REDIRECT_URL).mock(return_value=_jwks_response(_rsa_jwk(rsa_key)))
            provider = _provider(client, clock=_Clock())

            with pytest.raises(InvalidCredentialsError) as excinfo:
                await provider.keys()

            assert redirect.calls.call_count == 1
            assert attacker.calls.call_count == 0

    assert isinstance(excinfo.value.__cause__, httpx.HTTPStatusError)


async def test_provider_does_not_follow_redirects_even_if_the_client_does() -> None:
    """A cross-host redirect must never supply the verification keys.

    The provider pins ``follow_redirects=False`` per request, so an injected
    client configured to follow redirects cannot be used to substitute keys.
    """
    async with _client(follow_redirects=True) as client:
        with respx.mock(assert_all_called=False) as router:
            redirect = router.get(JWKS_URL).mock(
                return_value=httpx.Response(302, headers={"Location": REDIRECT_URL})
            )
            attacker = router.get(REDIRECT_URL).mock(
                return_value=httpx.Response(200, json={"keys": []})
            )
            provider = _provider(client, clock=_Clock())

            with pytest.raises(InvalidCredentialsError):
                await provider.keys()

            assert redirect.calls.call_count == 1
            assert attacker.calls.call_count == 0
