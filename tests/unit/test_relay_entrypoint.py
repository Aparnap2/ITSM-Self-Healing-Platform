"""Unit tests for the packaged outbox-relay entrypoint.

Marker: ``unit``. These tests assert configuration validation and composition
wiring without connecting to PostgreSQL or NATS.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any, cast

import pytest

from itsm_agent.config import ConfigError
from itsm_agent.workers import relay as relay_main

pytestmark = pytest.mark.unit


def test_config_prefers_itsm_variables_and_applies_defaults() -> None:
    env: Mapping[str, str] = {
        "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
        "ITSM_NATS_URL": "nats://nats:4222",
    }

    config = relay_main.RelayConfig.from_env(env)

    assert config.dsn == "postgresql://itsm_app@db/itsm"
    assert config.nats_url == "nats://nats:4222"
    assert config.batch_size == 10
    assert config.poll_interval_seconds == 1.0
    assert config.lease_seconds == 60.0


def test_config_falls_back_to_database_url_and_nats_url() -> None:
    env: Mapping[str, str] = {
        "DATABASE_URL": "postgresql://fallback@db/itsm",
        "NATS_URL": "nats://fallback:4222",
    }

    config = relay_main.RelayConfig.from_env(env)

    assert config.dsn == "postgresql://fallback@db/itsm"
    assert config.nats_url == "nats://fallback:4222"


@pytest.mark.parametrize("missing", ["ITSM_POSTGRES_DSN", "ITSM_NATS_URL"])
def test_config_fails_closed_when_a_dependency_is_missing(missing: str) -> None:
    env: dict[str, str] = {
        "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
        "ITSM_NATS_URL": "nats://nats:4222",
    }
    env.pop(missing)

    with pytest.raises(ConfigError, match=missing):
        relay_main.RelayConfig.from_env(env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ITSM_RELAY_BATCH_SIZE", "0"),
        ("ITSM_RELAY_POLL_SECONDS", "0"),
        ("ITSM_RELAY_LEASE_SECONDS", "-1"),
    ],
)
def test_config_rejects_non_positive_bounds(name: str, value: str) -> None:
    env: dict[str, str] = {
        "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
        "ITSM_NATS_URL": "nats://nats:4222",
        name: value,
    }

    with pytest.raises(ConfigError):
        relay_main.RelayConfig.from_env(env)


def test_build_relay_wires_the_tenant_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    bundle = SimpleNamespace(outbox="outbox-repo", tenants="tenant-registry")

    def fake_bundle(_pool: Any) -> SimpleNamespace:
        return bundle

    class Recorder:
        def __init__(self, outbox: Any, publisher: Any, **kwargs: Any) -> None:
            captured["outbox"] = outbox
            captured["publisher"] = publisher
            captured.update(kwargs)

    monkeypatch.setattr(relay_main, "RepositoryBundle", fake_bundle)
    monkeypatch.setattr(relay_main, "OutboxRelay", Recorder)
    config = relay_main.RelayConfig(
        dsn="postgresql://itsm_app@db/itsm",
        nats_url="nats://nats:4222",
        batch_size=7,
        poll_interval_seconds=0.5,
        lease_seconds=30.0,
    )

    result = relay_main.build_relay(
        pool=cast(Any, object()), publisher=cast(Any, "publisher"), config=config
    )

    assert isinstance(result, Recorder)
    assert captured["outbox"] == "outbox-repo"
    assert captured["publisher"] == "publisher"
    assert captured["tenants"] == "tenant-registry"
    assert captured["batch_size"] == 7
    assert captured["lease_seconds"] == 30.0


def test_main_returns_two_on_invalid_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> relay_main.RelayConfig:
        raise ConfigError("Missing required environment variable: ITSM_NATS_URL")

    monkeypatch.setattr(relay_main.RelayConfig, "from_env", fail)

    assert relay_main.main() == 2


def test_main_returns_one_when_the_relay_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    config = relay_main.RelayConfig(
        dsn="postgresql://itsm_app@db/itsm", nats_url="nats://nats:4222"
    )

    async def boom(_config: relay_main.RelayConfig) -> None:
        raise RuntimeError("nats unavailable")

    monkeypatch.setattr(relay_main.RelayConfig, "from_env", classmethod(lambda _cls: config))
    monkeypatch.setattr(relay_main, "serve", boom)

    assert relay_main.main() == 1


def test_main_returns_zero_after_a_clean_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    config = relay_main.RelayConfig(
        dsn="postgresql://itsm_app@db/itsm", nats_url="nats://nats:4222"
    )

    async def clean(_config: relay_main.RelayConfig) -> None:
        return None

    monkeypatch.setattr(relay_main.RelayConfig, "from_env", classmethod(lambda _cls: config))
    monkeypatch.setattr(relay_main, "serve", clean)

    assert relay_main.main() == 0
