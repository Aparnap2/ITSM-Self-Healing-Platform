"""Contract: the local identity simulator against the real OIDC relying party.

Marker: ``contract``. The point of this test is the authentication
boundary, so it uses the production relying party
(`itsm_agent.api.oidc.OIDCAuthenticator`) and the production JWKS provider
(`HttpJwksProvider`) against the simulator's real TLS endpoint:

* a token the simulator mints is accepted;
* a token signed by another key is rejected;
* a token for another audience, or an expired one, is rejected;
* the roles the principal ends up with come from the application's own
  directory, **not** from the token — the simulator holds no application
  authorization and cannot grant itself anything.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import tempfile
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import pytest

from itsm_agent.api.auth import AuthenticationError
from itsm_agent.api.oidc import (
    HttpJwksProvider,
    OIDCAuthenticator,
    ReviewerAuthorization,
    StaticAuthorizationDirectory,
)
from itsm_agent.simulators.identity.keys import (
    encode_jwt,
    generate_signing_key,
    mint_claims,
)
from itsm_agent.simulators.identity.server import (
    SimulatorConfig,
    assert_loopback,
    create_app,
)

pytestmark = pytest.mark.contract

ISSUER = "https://issuer.simulator.test"
AUDIENCE = "itsm-audience"
SUBJECT_A = "reviewer-a"
SUBJECT_B = "reviewer-b"
TENANT = UUID("11111111-1111-1111-1111-111111111111")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@asynccontextmanager
async def _simulator(
    key: Any,
    subjects: tuple[str, ...] = (SUBJECT_A, SUBJECT_B),
) -> AsyncIterator[tuple[httpx.AsyncClient, str, str]]:
    """Serve the simulator over real TLS and yield (client, base_url, ca_path).

    The relying party refuses a non-https JWKS URL, so the simulator serves
    TLS with a certificate signed by a throwaway CA — and the client pins
    that CA explicitly rather than disabling verification.
    """
    import uvicorn

    from itsm_agent.simulators.identity.keys import generate_tls_material, write_tls_material

    material = generate_tls_material()
    with tempfile.TemporaryDirectory() as directory:
        paths = write_tls_material(material, directory)
        app = create_app(
            SimulatorConfig(
                issuer=ISSUER,
                audience=AUDIENCE,
                key=key,
                subjects=subjects,
            )
        )
        port = _free_port()
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            ssl_certfile=paths["cert"],
            ssl_keyfile=paths["key"],
            server_header=False,
        )
        server = uvicorn.Server(config)
        task = asyncio.create_task(server.serve())
        base_url = f"https://127.0.0.1:{port}"
        try:
            await _wait_for_port(port)
            ca_context = ssl.create_default_context(cafile=paths["ca"])
            async with httpx.AsyncClient(
                base_url=base_url, verify=ca_context, timeout=httpx.Timeout(10.0)
            ) as client:
                yield client, base_url, paths["ca"]
        finally:
            server.should_exit = True
            with contextlib.suppress(asyncio.TimeoutError, TimeoutError):
                await asyncio.wait_for(task, timeout=15)


async def _wait_for_port(port: int, attempts: int = 100) -> None:
    """Wait until the simulator accepts connections."""
    for _ in range(attempts):
        try:
            async with httpx.AsyncClient(verify=False) as probe:  # noqa: S501 - liveness probe
                await probe.get(f"https://127.0.0.1:{port}/healthz", timeout=2.0)
        except Exception:  # noqa: BLE001 - not up yet
            await asyncio.sleep(0.1)
            continue
        return
    raise TimeoutError(f"the simulator did not start on port {port}")


def _directory() -> StaticAuthorizationDirectory:
    """The application's own authorization state, keyed by (issuer, subject)."""
    return StaticAuthorizationDirectory(
        {
            (ISSUER, SUBJECT_A): ReviewerAuthorization(
                active=True,
                tenant_ids=(TENANT,),
                roles=("reviewer",),
                authorization_version="1",
                updated_at=datetime.now(UTC),
            ),
            (ISSUER, SUBJECT_B): ReviewerAuthorization(
                active=True,
                tenant_ids=(TENANT,),
                roles=("reviewer",),
                authorization_version="1",
                updated_at=datetime.now(UTC),
            ),
        }
    )


async def _authenticator(client: httpx.AsyncClient, base_url: str) -> OIDCAuthenticator:
    """Build the production relying party over the simulator's JWKS."""
    jwks = HttpJwksProvider(url=f"{base_url}/jwks", client=client, cache_seconds=60.0)
    return OIDCAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=jwks,
        directory=_directory(),
        max_token_age_seconds=3600.0,
    )


async def test_simulator_token_is_accepted_by_the_relying_party() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        response = await client.post("/token", json={"subject": SUBJECT_A})
        assert response.status_code == 200
        token = response.json()["access_token"]

        principal = await authenticator.authenticate(f"Bearer {token}")

    assert principal.principal_id == SUBJECT_A
    assert principal.tenant_ids == (TENANT,)
    # Roles come from the application's directory, not from the token.
    assert principal.roles == ("reviewer",)


async def test_roles_are_never_taken_from_the_token() -> None:
    """A token that claims extra roles cannot grant itself any."""
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        claims = mint_claims(
            issuer=ISSUER,
            audience=AUDIENCE,
            subject=SUBJECT_A,
        )
        claims["roles"] = ["admin"]
        claims["tenant_ids"] = [str(uuid.uuid4())]
        token = encode_jwt(claims, key)

        principal = await authenticator.authenticate(f"Bearer {token}")

    assert principal.roles == ("reviewer",)
    assert principal.tenant_ids == (TENANT,)


async def test_token_signed_by_another_key_is_rejected() -> None:
    trusted = generate_signing_key()
    attacker = generate_signing_key()
    async with _simulator(trusted) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        claims = mint_claims(issuer=ISSUER, audience=AUDIENCE, subject=SUBJECT_A)
        forged = encode_jwt(claims, attacker)

        with pytest.raises(AuthenticationError):
            await authenticator.authenticate(f"Bearer {forged}")


async def test_token_for_another_audience_is_rejected() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        claims = mint_claims(issuer=ISSUER, audience="another-audience", subject=SUBJECT_A)
        token = encode_jwt(claims, key)

        with pytest.raises(AuthenticationError):
            await authenticator.authenticate(f"Bearer {token}")


async def test_expired_token_is_rejected() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        claims = mint_claims(
            issuer=ISSUER,
            audience=AUDIENCE,
            subject=SUBJECT_A,
            now=datetime.now(UTC) - timedelta(hours=2),
        )
        token = encode_jwt(claims, key)

        with pytest.raises(AuthenticationError):
            await authenticator.authenticate(f"Bearer {token}")


async def test_unknown_subject_is_refused_by_the_directory() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        claims = mint_claims(issuer=ISSUER, audience=AUDIENCE, subject="stranger")
        token = encode_jwt(claims, key)

        with pytest.raises(AuthenticationError):
            await authenticator.authenticate(f"Bearer {token}")


async def test_simulator_refuses_to_mint_for_an_undeclared_subject() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, _base_url, _ca):
        response = await client.post("/token", json={"subject": "stranger"})

    assert response.status_code == 404


async def test_simulator_refuses_to_bind_beyond_loopback() -> None:
    with pytest.raises(ValueError, match="loopback"):
        assert_loopback("0.0.0.0")
    with pytest.raises(ValueError, match="loopback"):
        assert_loopback("10.0.0.5")


async def test_simulator_signs_only_rs256() -> None:
    key = generate_signing_key()
    claims = mint_claims(issuer=ISSUER, audience=AUDIENCE, subject=SUBJECT_A)

    with pytest.raises(ValueError, match="RS256"):
        encode_jwt(claims, key, algorithm="HS256")


async def test_jwks_publishes_only_public_material() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, _base_url, _ca):
        response = await client.get("/jwks")

    assert response.status_code == 200
    published = response.json()["keys"]
    assert len(published) == 1
    assert published[0]["alg"] == "RS256"
    assert published[0]["kid"] == key.kid
    # The private half must never be published.
    assert "d" not in published[0]
    assert "p" not in published[0]


async def test_two_subjects_are_distinct_principals() -> None:
    """Independent verification needs two identities, not one with two hats."""
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        authenticator = await _authenticator(client, base_url)
        token_a = (await client.post("/token", json={"subject": SUBJECT_A})).json()["access_token"]
        token_b = (await client.post("/token", json={"subject": SUBJECT_B})).json()["access_token"]

        principal_a = await authenticator.authenticate(f"Bearer {token_a}")
        principal_b = await authenticator.authenticate(f"Bearer {token_b}")

    assert principal_a.principal_id != principal_b.principal_id
    assert principal_a.principal_id == SUBJECT_A
    assert principal_b.principal_id == SUBJECT_B


async def test_simulator_marks_its_responses() -> None:
    key = generate_signing_key()
    async with _simulator(key) as (client, base_url, _ca):
        response = await client.get("/jwks")

    assert response.headers["X-Simulator"] == "itsm-identity-simulator"


async def test_simulator_generates_usable_tls_material() -> None:
    from itsm_agent.simulators.identity.keys import generate_tls_material

    material = generate_tls_material()
    assert b"BEGIN CERTIFICATE" in material.ca_cert_pem
    assert b"BEGIN CERTIFICATE" in material.server_cert_pem
    assert b"BEGIN PRIVATE KEY" in material.server_key_pem


async def test_jwks_provider_refuses_a_non_https_url() -> None:
    """The transport requirement is unchanged by the simulator."""
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="https"):
            HttpJwksProvider(url="http://simulator.test/jwks", client=client)


async def test_simulator_is_offline_and_uses_no_services() -> None:
    """The simulator needs no database, broker or network."""
    key = generate_signing_key()
    async with _simulator(key) as (client, _base_url, _ca):
        health = await client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["mode"] == "simulator"


def _unused() -> None:  # pragma: no cover - keeps asyncio import meaningful
    asyncio.get_event_loop_policy()


async def test_discovery_document_advertises_the_configured_base_url() -> None:
    """Discovery describes the surface the stack is actually wired to.

    The relying party does not use this document — it is configured with an
    explicit JWKS URL — so the value of discovery is that a readiness probe
    can compare what the simulator advertises with what the platform pins.
    """
    key = generate_signing_key()
    app = create_app(
        SimulatorConfig(
            issuer=ISSUER,
            audience=AUDIENCE,
            key=key,
            subjects=(SUBJECT_A,),
            base_url="https://identity:8443",
        )
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://identity:8443") as client:
        response = await client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    body = response.json()
    assert body["issuer"] == ISSUER
    assert body["jwks_uri"] == "https://identity:8443/jwks"
    assert body["token_endpoint"] == "https://identity:8443/token"
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]
    # The absence of client authentication is advertised, not hidden.
    assert body["token_endpoint_auth_methods_supported"] == ["none"]
    assert body["x-simulator"] is True
    assert response.headers["x-simulator"] == "itsm-identity-simulator"


async def test_container_bind_is_opt_in_and_narrow() -> None:
    """A wildcard bind needs the explicit flag and never admits a real address."""
    with pytest.raises(ValueError, match="loopback"):
        assert_loopback("0.0.0.0")

    assert_loopback("0.0.0.0", allow_container_bind=True)
    assert_loopback("::", allow_container_bind=True)

    with pytest.raises(ValueError, match="loopback"):
        assert_loopback("10.0.0.5", allow_container_bind=True)
    with pytest.raises(ValueError, match="loopback"):
        assert_loopback("identity", allow_container_bind=True)
