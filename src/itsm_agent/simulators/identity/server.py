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
    mint_claims,
    write_tls_material,
)

#: Hosts the simulator is allowed to bind to. Anything else is refused: a
#: simulator reachable from the network would be a credential oracle.
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


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


def assert_loopback(host: str) -> None:
    """Refuse to serve anything but the loopback interface."""
    if host not in ALLOWED_HOSTS:
        raise ValueError(
            "the identity simulator may only bind to loopback "
            f"({sorted(ALLOWED_HOSTS)}), not {host!r}"
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
) -> None:
    """Serve the simulator over TLS until cancelled.

    Returns the JWKS URL and the CA path through the ``state_dir`` it was
    given, so a caller can configure the relying party to pin that CA.
    """
    import uvicorn

    assert_loopback(host)
    signing_key = key or generate_signing_key()
    tls = material or generate_tls_material()
    directory = state_dir or os.path.join(os.path.expanduser("~"), ".itsm-simulator")
    paths = write_tls_material(tls, directory)

    app = create_app(
        SimulatorConfig(
            issuer=issuer,
            audience=audience,
            key=signing_key,
            subjects=subjects,
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
