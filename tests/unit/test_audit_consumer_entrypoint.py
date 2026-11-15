"""Unit tests for the packaged audit-consumer entrypoint.

Marker: ``unit``. These tests assert configuration validation, the composition
wiring and the exit-code contract **without connecting to PostgreSQL or
NATS**: the network path is stubbed out.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest

from itsm_agent.config import ConfigError
from itsm_agent.workers import audit_consumer as consumer_main

pytestmark = pytest.mark.unit

BASE_ENV: dict[str, str] = {
    "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
    "ITSM_NATS_URL": "nats://nats:4222",
}


def _env(**overrides: str) -> dict[str, str]:
    env = dict(BASE_ENV)
    env.update(overrides)
    return env


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_config_prefers_itsm_variables_and_applies_defaults() -> None:
    config = consumer_main.AuditConsumerConfig.from_env(_env())

    assert config.dsn == "postgresql://itsm_app@db/itsm"
    assert config.nats_url == "nats://nats:4222"
    assert config.investigation_enabled is False
    assert config.investigation_max_model_calls == 2
    assert config.investigation_max_tool_calls == 5
    assert config.investigation_llm_budget_calls == 3
    assert config.groq_api_key is None


def test_config_falls_back_to_database_url_and_nats_url() -> None:
    env: Mapping[str, str] = {
        "DATABASE_URL": "postgresql://fallback@db/itsm",
        "NATS_URL": "nats://fallback:4222",
    }

    config = consumer_main.AuditConsumerConfig.from_env(env)

    assert config.dsn == "postgresql://fallback@db/itsm"
    assert config.nats_url == "nats://fallback:4222"


def test_config_fails_closed_when_the_dsn_is_missing() -> None:
    env = _env()
    env.pop("ITSM_POSTGRES_DSN")

    with pytest.raises(ConfigError, match="ITSM_POSTGRES_DSN"):
        consumer_main.AuditConsumerConfig.from_env(env)


def test_config_fails_closed_when_the_nats_url_is_missing() -> None:
    env = _env()
    env.pop("ITSM_NATS_URL")

    with pytest.raises(ConfigError, match="ITSM_NATS_URL"):
        consumer_main.AuditConsumerConfig.from_env(env)


def test_enabled_investigation_without_a_model_key_fails_closed() -> None:
    env = _env(ITSM_INVESTIGATION_ENABLED="true")

    with pytest.raises(ConfigError, match="ITSM_GROQ_API_KEY"):
        consumer_main.AuditConsumerConfig.from_env(env)


def test_enabled_investigation_with_a_model_key_is_accepted() -> None:
    env = _env(ITSM_INVESTIGATION_ENABLED="true", ITSM_GROQ_API_KEY="gsk-not-a-real-key")

    config = consumer_main.AuditConsumerConfig.from_env(env)

    assert config.investigation_enabled is True
    assert config.groq_api_key == "gsk-not-a-real-key"


def test_disabled_investigation_does_not_require_a_model_key() -> None:
    env = _env(ITSM_INVESTIGATION_ENABLED="false")

    config = consumer_main.AuditConsumerConfig.from_env(env)

    assert config.investigation_enabled is False
    assert config.groq_api_key is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ITSM_INVESTIGATION_MAX_MODEL_CALLS", "0"),
        ("ITSM_INVESTIGATION_MAX_MODEL_CALLS", "6"),
        ("ITSM_INVESTIGATION_MAX_TOOL_CALLS", "0"),
        ("ITSM_INVESTIGATION_MAX_TOOL_CALLS", "21"),
        ("ITSM_INVESTIGATION_LLM_BUDGET_CALLS", "0"),
        ("ITSM_INVESTIGATION_LLM_BUDGET_CALLS", "11"),
    ],
)
def test_config_rejects_out_of_range_bounds(name: str, value: str) -> None:
    env = _env(**{name: value})

    with pytest.raises(ConfigError):
        consumer_main.AuditConsumerConfig.from_env(env)


def test_config_rejects_a_non_boolean_switch() -> None:
    env = _env(ITSM_INVESTIGATION_ENABLED="maybe")

    with pytest.raises(ConfigError, match="ITSM_INVESTIGATION_ENABLED"):
        consumer_main.AuditConsumerConfig.from_env(env)


def test_config_reads_the_covered_sources() -> None:
    env = _env(ITSM_AUDIT_COVERED_SOURCES="cloudtrail, github")

    config = consumer_main.AuditConsumerConfig.from_env(env)

    assert config.covered_sources == frozenset({"cloudtrail", "github"})


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def test_disabled_stage_builds_no_investigation_service() -> None:
    config = consumer_main.AuditConsumerConfig.from_env(_env())
    repositories = SimpleNamespace(investigation="ledger", pool=object())

    service, model = consumer_main.build_investigation_service(
        repositories=repositories,  # type: ignore[arg-type]
        config=config,
    )

    assert service is None
    assert model is None


def test_enabled_stage_without_a_key_fails_closed() -> None:
    config = consumer_main.AuditConsumerConfig(
        dsn="postgresql://itsm_app@db/itsm",
        nats_url="nats://nats:4222",
        investigation_enabled=True,
        groq_api_key=None,
    )
    repositories = SimpleNamespace(investigation="ledger", pool=object())

    with pytest.raises(ConfigError, match="ITSM_GROQ_API_KEY"):
        consumer_main.build_investigation_service(
            repositories=repositories,  # type: ignore[arg-type]
            config=config,
        )


def test_enabled_stage_builds_an_investigation_service(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeModel:
        def __init__(self, **kwargs: Any) -> None:
            captured["model_kwargs"] = kwargs

    monkeypatch.setattr(consumer_main, "GroqInvestigationModel", FakeModel)
    config = consumer_main.AuditConsumerConfig(
        dsn="postgresql://itsm_app@db/itsm",
        nats_url="nats://nats:4222",
        investigation_enabled=True,
        groq_api_key="gsk-not-a-real-key",
        groq_model="openai/gpt-oss-120b",
    )
    repositories = SimpleNamespace(investigation="ledger", pool=object())

    service, model = consumer_main.build_investigation_service(
        repositories=repositories,  # type: ignore[arg-type]
        config=config,
    )

    assert service is not None
    assert model is not None
    assert service._model is not None  # noqa: SLF001 - composition assertion
    # The evidence resolver is wired, so the model reasons about the
    # canonical source event rather than a bare question.
    assert service._evidence_source is not None  # noqa: SLF001 - composition assertion
    assert captured["model_kwargs"]["model"] == "openai/gpt-oss-120b"
    assert captured["model_kwargs"]["api_key"] == "gsk-not-a-real-key"


# ---------------------------------------------------------------------------
# Exit-code contract: 0 clean / 1 crash / 2 config
# ---------------------------------------------------------------------------


def test_main_returns_two_on_invalid_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> consumer_main.AuditConsumerConfig:
        raise ConfigError("Missing required environment variable: ITSM_NATS_URL")

    monkeypatch.setattr(consumer_main.AuditConsumerConfig, "from_env", fail)

    assert consumer_main.main() == 2


def test_main_returns_two_when_the_dsn_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ITSM_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("ITSM_NATS_URL", "nats://nats:4222")

    assert consumer_main.main() == 2


def test_main_returns_two_when_the_nats_url_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ITSM_POSTGRES_DSN", "postgresql://itsm_app@db/itsm")
    monkeypatch.delenv("ITSM_NATS_URL", raising=False)
    monkeypatch.delenv("NATS_URL", raising=False)

    assert consumer_main.main() == 2


def test_main_returns_two_when_the_enabled_stage_has_no_model_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITSM_POSTGRES_DSN", "postgresql://itsm_app@db/itsm")
    monkeypatch.setenv("ITSM_NATS_URL", "nats://nats:4222")
    monkeypatch.setenv("ITSM_INVESTIGATION_ENABLED", "true")
    monkeypatch.delenv("ITSM_GROQ_API_KEY", raising=False)

    assert consumer_main.main() == 2


def test_main_returns_one_when_the_consumer_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    config = consumer_main.AuditConsumerConfig(
        dsn="postgresql://itsm_app@db/itsm", nats_url="nats://nats:4222"
    )

    async def boom(_config: consumer_main.AuditConsumerConfig) -> None:
        raise RuntimeError("nats unavailable")

    monkeypatch.setattr(
        consumer_main.AuditConsumerConfig, "from_env", classmethod(lambda _cls: config)
    )
    monkeypatch.setattr(consumer_main, "serve", boom)

    assert consumer_main.main() == 1


def test_main_returns_zero_after_a_clean_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    config = consumer_main.AuditConsumerConfig(
        dsn="postgresql://itsm_app@db/itsm", nats_url="nats://nats:4222"
    )

    async def clean(_config: consumer_main.AuditConsumerConfig) -> None:
        return None

    monkeypatch.setattr(
        consumer_main.AuditConsumerConfig, "from_env", classmethod(lambda _cls: config)
    )
    monkeypatch.setattr(consumer_main, "serve", clean)

    assert consumer_main.main() == 0
