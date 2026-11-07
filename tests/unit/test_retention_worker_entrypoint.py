"""Unit tests for the packaged retention-scheduler entrypoint.

Marker: ``unit``. These tests assert configuration validation, scheduler
wiring, and fail-closed exit codes without connecting to PostgreSQL.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any, cast

import pytest

from itsm_agent.config import ConfigError
from itsm_agent.workers import retention as retention_main

pytestmark = pytest.mark.unit


def test_config_prefers_itsm_variables_and_applies_defaults() -> None:
    env: Mapping[str, str] = {
        "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
        "DATABASE_URL": "postgresql://fallback@db/itsm",
    }

    config = retention_main.RetentionConfig.from_env(env)

    assert config.dsn == "postgresql://itsm_app@db/itsm"
    assert config.interval_seconds == 60.0
    assert config.batch_size == 10
    assert config.lease_seconds == 60.0
    assert config.max_attempts == 5
    assert config.backoff_seconds == 30.0


def test_config_falls_back_to_database_url() -> None:
    config = retention_main.RetentionConfig.from_env(
        {"DATABASE_URL": "postgresql://fallback@db/itsm"}
    )

    assert config.dsn == "postgresql://fallback@db/itsm"


def test_config_fails_closed_when_the_dsn_is_missing() -> None:
    with pytest.raises(ConfigError, match="ITSM_POSTGRES_DSN"):
        retention_main.RetentionConfig.from_env({})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ITSM_RETENTION_BATCH_SIZE", "0"),
        ("ITSM_RETENTION_INTERVAL_SECONDS", "0"),
        ("ITSM_RETENTION_LEASE_SECONDS", "-1"),
        ("ITSM_RETENTION_MAX_ATTEMPTS", "0"),
    ],
)
def test_config_rejects_non_positive_bounds(name: str, value: str) -> None:
    env: dict[str, str] = {
        "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
        name: value,
    }

    with pytest.raises(ConfigError):
        retention_main.RetentionConfig.from_env(env)


def test_config_rejects_negative_backoff() -> None:
    with pytest.raises(ConfigError, match="ITSM_RETENTION_BACKOFF_SECONDS"):
        retention_main.RetentionConfig.from_env(
            {
                "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
                "ITSM_RETENTION_BACKOFF_SECONDS": "-1",
            }
        )


def test_build_scheduler_wires_the_tenant_registry_and_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    bundle = SimpleNamespace(tenants="tenant-registry")

    def fake_bundle(_pool: Any) -> SimpleNamespace:
        return bundle

    class Recorder:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(retention_main, "RepositoryBundle", fake_bundle)
    monkeypatch.setattr(retention_main, "RetentionScheduler", Recorder)
    config = retention_main.RetentionConfig(
        dsn="postgresql://itsm_app@db/itsm",
        interval_seconds=0.5,
        batch_size=7,
        lease_seconds=30.0,
        max_attempts=3,
        backoff_seconds=5.0,
    )

    result = retention_main.build_scheduler(pool=cast(Any, object()), config=config)

    assert isinstance(result, Recorder)
    assert captured["repos"] == bundle
    assert captured["batch_size"] == 7
    assert captured["lease_seconds"] == 30.0
    assert captured["max_attempts"] == 3
    assert captured["backoff_seconds"] == 5.0
    assert captured["interval_seconds"] == 0.5


def test_main_returns_two_on_invalid_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> retention_main.RetentionConfig:
        raise ConfigError("Missing required environment variable: ITSM_POSTGRES_DSN")

    monkeypatch.setattr(retention_main.RetentionConfig, "from_env", fail)

    assert retention_main.main() == 2


def test_main_returns_one_when_the_scheduler_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = retention_main.RetentionConfig(dsn="postgresql://itsm_app@db/itsm")

    async def boom(_config: retention_main.RetentionConfig) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(
        retention_main.RetentionConfig, "from_env", classmethod(lambda _cls: config)
    )
    monkeypatch.setattr(retention_main, "serve", boom)

    assert retention_main.main() == 1


def test_main_returns_zero_after_a_clean_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    config = retention_main.RetentionConfig(dsn="postgresql://itsm_app@db/itsm")

    async def clean(_config: retention_main.RetentionConfig) -> None:
        return None

    monkeypatch.setattr(
        retention_main.RetentionConfig, "from_env", classmethod(lambda _cls: config)
    )
    monkeypatch.setattr(retention_main, "serve", clean)

    assert retention_main.main() == 0
