"""Unit tests for the packaged ASGI entrypoint.

Marker: ``unit``. These tests assert the composition wiring and fail-closed
startup behaviour without opening a database pool or binding a socket.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import httpx
import pytest
from fastapi import FastAPI

from itsm_agent.adapters.persistence.ingestion_sink import PsycopgIngestionSink
from itsm_agent.api import __main__ as api_main
from itsm_agent.api.auth import TokenAuthenticator
from itsm_agent.api.oidc import OIDCAuthenticator
from itsm_agent.config import ConfigError, Settings

pytestmark = pytest.mark.unit


def _settings() -> Settings:
    return Settings.model_validate(
        {
            "env": "test",
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "webhook_secret": "test-webhook-secret-0123456789abcdef",
            "auth_hmac_secret": "test-hmac-secret-0123456789abcdef",
            "mockoon_itsm_base_url": "http://mockoon-itsm.test",
            "mockoon_identity_base_url": "http://mockoon-identity.test",
            "mockoon_infrastructure_base_url": "http://mockoon-infra.test",
        }
    )


def test_database_dsn_prefers_the_itsm_variable() -> None:
    env: Mapping[str, str] = {
        "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
        "DATABASE_URL": "postgresql://fallback@db/itsm",
    }

    assert api_main.database_dsn(env) == "postgresql://itsm_app@db/itsm"


def test_database_dsn_falls_back_to_database_url() -> None:
    env: Mapping[str, str] = {"DATABASE_URL": "postgresql://fallback@db/itsm"}

    assert api_main.database_dsn(env) == "postgresql://fallback@db/itsm"


def test_database_dsn_fails_closed_when_missing() -> None:
    with pytest.raises(ConfigError, match="DATABASE_URL"):
        api_main.database_dsn({})


def test_build_app_passes_the_pool_to_the_lifespan_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    sentinel_app = cast(FastAPI, object())

    def fake_create_app(**kwargs: Any) -> FastAPI:
        captured.update(kwargs)
        return sentinel_app

    monkeypatch.setattr(api_main, "create_app", fake_create_app)
    pool = cast(Any, object())
    sink = cast(Any, object())

    app = api_main.build_app(settings=_settings(), pool=pool, sink=sink)

    assert app is sentinel_app
    assert captured["database_pool"] is pool
    assert captured["sink"] is sink
    assert captured["findings_repo"] is not None
    assert captured["review_decisions_repo"] is not None


def test_build_app_wires_the_hmac_authenticator(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_create_app(**kwargs: Any) -> FastAPI:
        captured.update(kwargs)
        return cast(FastAPI, object())

    monkeypatch.setattr(api_main, "create_app", fake_create_app)

    api_main.build_app(settings=_settings(), pool=cast(Any, object()))

    assert isinstance(captured["authenticator"], TokenAuthenticator)


def test_build_authenticator_rejects_oidc_without_an_http_client() -> None:
    settings = Settings.model_validate(
        {
            **_settings().model_dump(),
            "auth_mode": "oidc",
            "oidc_issuer": "https://issuer.test",
            "oidc_audience": "itsm-api",
            "oidc_jwks_url": "https://issuer.test/jwks",
        }
    )

    with pytest.raises(ConfigError, match="HTTP client"):
        api_main.build_authenticator(settings=settings, pool=cast(Any, object()), client=None)


async def test_build_authenticator_builds_the_oidc_relying_party() -> None:
    settings = Settings.model_validate(
        {
            **_settings().model_dump(),
            "auth_mode": "oidc",
            "oidc_issuer": "https://issuer.test",
            "oidc_audience": "itsm-api",
            "oidc_jwks_url": "https://issuer.test/jwks",
        }
    )
    async with httpx.AsyncClient() as client:
        authenticator = api_main.build_authenticator(
            settings=settings, pool=cast(Any, object()), client=client
        )

    assert isinstance(authenticator, OIDCAuthenticator)


def test_build_app_defaults_to_the_postgres_ingestion_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create_app(**kwargs: Any) -> FastAPI:
        captured.update(kwargs)
        return cast(FastAPI, object())

    monkeypatch.setattr(api_main, "create_app", fake_create_app)
    pool = cast(Any, object())

    api_main.build_app(settings=_settings(), pool=pool)

    assert isinstance(captured["sink"], PsycopgIngestionSink)


def test_main_returns_two_on_invalid_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> Settings:
        raise ConfigError("Missing required environment variable: ITSM_ENV")

    monkeypatch.setattr(api_main, "load_settings", fail)

    assert api_main.main() == 2


def test_main_returns_one_when_the_server_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(_settings: Settings) -> None:
        raise RuntimeError("bind failed")

    monkeypatch.setattr(api_main, "load_settings", _settings)
    monkeypatch.setattr(api_main, "serve", boom)

    assert api_main.main() == 1


def test_main_returns_zero_after_a_clean_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    async def clean(_settings: Settings) -> None:
        return None

    monkeypatch.setattr(api_main, "load_settings", _settings)
    monkeypatch.setattr(api_main, "serve", clean)

    assert api_main.main() == 0
