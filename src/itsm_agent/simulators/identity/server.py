"""The LOCAL identity simulator's HTTP surface — development/staging only.

Endpoints:

* ``GET  /jwks``  — the published public signing keys (JWKS document).
* ``POST /token``  — mints a token for a **pre-declared** subject.

The simulator holds no application authorization: tokens carry no role or
tenant claim, and the relying party resolves reviewer state from the
application's own directory on every request.

It binds to loopback only and serves TLS with a certificate signed by a
throwaway CA that the client pins explicitly — verification is never
disabled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from itsm_agent.simulators.identity import __simulator_notice__
from itsm_agent.simulators.identity.keys import (
    SigningKey,
    TlsMaterial,
    encode_jwt,
    generate_signing_key,
    generate_tls_material,
    load_tls_material,
    mint_claims,
    write_tls_material,
)

#: Hosts the simulator is allowed to bind to by default. Anything else is
#: refused: a simulator reachable from the network would be a credential
#: oracle.
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: Wildcard binds, permitted ONLY with the explicit container opt-in. Inside
#: an isolated compose network the service must listen on a routable address
#: for its peers; the host's published port stays bound to 127.0.0.1 and the
#: environment guard in ``__main__`` still refuses anything but
#: local/test/staging. This is a bind-address concession for a private
#: container network, never an authentication concession.
ALLOWED_CONTAINER_HOSTS = frozenset({"0.0.0.0", "::"})


class TokenRequest(BaseModel):
    """The token request. Only a pre-declared subject may be minted."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=128)
    ttl_seconds: int = Field(default=900, ge=60, le=3600)


@dataclass(frozen=True)
class SimulatorConfig:
    """Static configuration of one simulator instance."""

    issuer: str
    audience: str
    key: SigningKey
    subjects: tuple[str, ...]
    #: Public base URL the simulator advertises in its discovery document.
    #: ``None`` falls back to the loopback default used by the test suite.
    base_url: str | None = None

    @property
    def resolved_base_url(self) -> str:
        return self.base_url or "https://127.0.0.1:8443"


def create_app(config: SimulatorConfig) -> FastAPI:
    """Build the simulator application."""
    app = FastAPI(
        title="ITS-M local identity simulator",
        description=__simulator_notice__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/jwks")
    async def jwks() -> JSONResponse:
        return JSONResponse(
            {"keys": [config.key.jwk()]},
            headers={"X-Simulator": "itsm-identity-simulator"},
        )

    @app.get("/.well-known/openid-configuration")
    async def discovery() -> JSONResponse:
        """Discovery metadata for operators and readiness probes.

        The relying party does NOT use this document: it is configured with an
        explicit ``ITSM_OIDC_JWKS_URL`` and pins the CA. Discovery is here so a
        readiness probe can assert the simulator's advertised surface matches
        the one the platform is wired to, instead of guessing it.
        """
        base = config.resolved_base_url.rstrip("/")
        return JSONResponse(
            {
                "issuer": config.issuer,
                "jwks_uri": f"{base}/jwks",
                "token_endpoint": f"{base}/token",
                "id_token_signing_alg_values_supported": ["RS256"],
                "subject_types_supported": ["public"],
                # Stated plainly: the token endpoint performs no client
                # authentication. Authorization is the relying party's job and
                # rests on the application directory, never on these claims.
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["simulator"],
                "x-simulator": True,
                "x-simulator-notice": __simulator_notice__,
            },
            headers={"X-Simulator": "itsm-identity-simulator"},
        )

    @app.post("/token")
    async def token(body: TokenRequest, response: Response) -> JSONResponse:
        if body.subject not in config.subjects:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="unknown subject",
            )
        claims = mint_claims(
            issuer=config.issuer,
            audience=config.audience,
            subject=body.subject,
            ttl_seconds=body.ttl_seconds,
        )
        access_token = encode_jwt(claims, config.key)
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": body.ttl_seconds,
            },
            headers={"X-Simulator": "itsm-identity-simulator"},
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "mode": "simulator"}

    return app


def assert_loopback(host: str, *, allow_container_bind: bool = False) -> None:
    """Refuse to serve beyond loopback unless the container opt-in is given.

    The default is unchanged and remains the safe one. ``allow_container_bind``
    admits only the wildcard addresses and only because a compose service must
    be reachable by its peers on the private network.
    """
    if host in ALLOWED_HOSTS:
        return
    if allow_container_bind and host in ALLOWED_CONTAINER_HOSTS:
        return
    raise ValueError(
        "the identity simulator may only bind to loopback "
        f"({sorted(ALLOWED_HOSTS)}) outside a container, not {host!r}"
    )


async def run(
    *,
    issuer: str,
    audience: str,
    subjects: tuple[str, ...],
    host: str = "127.0.0.1",
    port: int = 8443,
    state_dir: str | None = None,
    key: SigningKey | None = None,
    material: TlsMaterial | None = None,
    allow_container_bind: bool = False,
    base_url: str | None = None,
) -> None:
    """Serve the simulator over TLS until cancelled.

    Returns the JWKS URL and the CA path through the ``state_dir`` it was
    given, so a caller can configure the relying party to pin that CA.
    """
    import uvicorn

    assert_loopback(host, allow_container_bind=allow_container_bind)
    signing_key = key or generate_signing_key()
    directory = state_dir or os.path.join(os.path.expanduser("~"), ".itsm-simulator")
    # Same reasoning as the CLI: reuse material a running relying party may
    # already trust rather than invalidating it on every restart.
    hostnames = tuple(dict.fromkeys((host, "localhost", "127.0.0.1")))
    tls = material or load_tls_material(directory, hostnames) or generate_tls_material(hostnames)
    paths = write_tls_material(tls, directory)

    app = create_app(
        SimulatorConfig(
            issuer=issuer,
            audience=audience,
            key=signing_key,
            subjects=subjects,
            base_url=base_url,
        )
    )
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        ssl_certfile=paths["cert"],
        ssl_keyfile=paths["key"],
        server_header=False,
    )
    await uvicorn.Server(config).serve()


def state_paths(state_dir: str) -> dict[str, str]:
    """The file paths a caller needs to configure the relying party."""
    base = Path(state_dir)
    return {
        "ca": str(base / "simulator-ca.pem"),
        "jwks_url": "https://127.0.0.1:8443/jwks",
        "token_url": "https://127.0.0.1:8443/token",
    }


__all__ = [
    "ALLOWED_HOSTS",
    "SimulatorConfig",
    "TokenRequest",
    "assert_loopback",
    "create_app",
    "run",
    "state_paths",
]
