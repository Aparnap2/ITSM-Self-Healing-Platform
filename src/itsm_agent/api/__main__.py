"""Packaged ASGI entrypoint: ``python -m itsm_agent.api``.

Owns the process lifecycle that ``create_app`` deliberately does not: the
connection pool is opened before the server starts and closed after it stops.
The app lifespan still runs ``verify_runtime_database``, so a server that
connects with a role able to bypass RLS fails closed at startup.

Reviewer authentication is wired from ``ITSM_AUTH_MODE``: HMAC for local/test,
OIDC (cached JWKS + Postgres reviewer directory) otherwise.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Mapping

import httpx
import uvicorn
from fastapi import FastAPI
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from itsm_agent.adapters.persistence.ingestion_sink import PsycopgIngestionSink
from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import RepositoryBundle
from itsm_agent.api.app import create_app
from itsm_agent.api.auth import Authenticator, TokenAuthenticator
from itsm_agent.api.oidc import (
    HttpJwksProvider,
    OIDCAuthenticator,
    PsycopgReviewerDirectory,
)
from itsm_agent.api.routes.ingestion import IngestionSink
from itsm_agent.config import ConfigError, Settings, load_settings

logger = logging.getLogger("itsm.api")


def database_dsn(env: Mapping[str, str] | None = None) -> str:
    """Resolve the runtime DSN, preferring the ITSM-specific variable."""
    source = os.environ if env is None else env
    dsn = source.get("ITSM_POSTGRES_DSN") or source.get("DATABASE_URL")
    if not dsn:
        raise ConfigError(
            "Missing required environment variable: ITSM_POSTGRES_DSN or DATABASE_URL"
        )
    return dsn


def build_authenticator(
    *,
    settings: Settings,
    pool: AsyncConnectionPool[AsyncConnection],
    client: httpx.AsyncClient | None,
) -> Authenticator:
    """Build the configured reviewer authenticator or fail closed."""
    if settings.auth_mode == "hmac":
        if not settings.auth_hmac_secret:
            raise ConfigError("Missing required environment variable: ITSM_AUTH_HMAC_SECRET")
        return TokenAuthenticator(secret=settings.auth_hmac_secret)

    issuer = settings.oidc_issuer
    audience = settings.oidc_audience
    jwks_url = settings.oidc_jwks_url
    if not issuer or not audience or not jwks_url:
        raise ConfigError(
            "OIDC requires ITSM_OIDC_ISSUER, ITSM_OIDC_AUDIENCE, and ITSM_OIDC_JWKS_URL"
        )
    if client is None:
        raise ConfigError("OIDC requires an HTTP client for the JWKS endpoint")
    return OIDCAuthenticator(
        issuer=issuer,
        audience=audience,
        jwks=HttpJwksProvider(
            url=jwks_url,
            client=client,
            cache_seconds=settings.oidc_jwks_cache_seconds,
        ),
        directory=PsycopgReviewerDirectory(pool),
        algorithms=settings.oidc_algorithms,
        leeway_seconds=settings.oidc_leeway_seconds,
        max_token_age_seconds=settings.oidc_max_token_age_seconds,
    )


def build_app(
    *,
    settings: Settings,
    pool: AsyncConnectionPool[AsyncConnection],
    client: httpx.AsyncClient | None = None,
    sink: IngestionSink | None = None,
) -> FastAPI:
    """Compose the app around a pool the caller owns and will open."""
    repositories = RepositoryBundle(pool)
    return create_app(
        settings=settings,
        sink=PsycopgIngestionSink(pool) if sink is None else sink,
        findings_repo=repositories.findings,
        review_decisions_repo=repositories.review_decisions,
        authenticator=build_authenticator(settings=settings, pool=pool, client=client),
        database_pool=pool,
    )


async def serve(settings: Settings) -> None:
    """Open the pool, serve until shutdown, then close the pool."""
    pool = create_pool(PersistenceConfig(dsn=database_dsn()))
    await pool.open()
    await pool.wait()
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(5.0)) as client:
            app = build_app(settings=settings, pool=pool, client=client)
            config = uvicorn.Config(
                app,
                host=settings.api_host,
                port=settings.api_port,
                log_level=os.environ.get("LOG_LEVEL", "info").lower(),
                access_log=False,
                server_header=False,
                proxy_headers=False,
            )
            await uvicorn.Server(config).serve()
    finally:
        await pool.close()


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        logger.error("startup config error: %s", exc)
        return 2
    try:
        asyncio.run(serve(settings))
    except KeyboardInterrupt:
        return 0
    except Exception:  # noqa: BLE001 - process boundary: log and exit non-zero
        logger.exception("api server crashed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
