"""Typed, environment-driven application configuration.

Fail-fast: every required key must be present at load time; there are no
secret defaults. Secrets (webhook signing secret, Groq API key) are read
from the environment only and are never logged or serialized.

Import rules (docs/architecture.md §5): this module may import only the
standard library and Pydantic.
"""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


class Settings(BaseModel):
    """Immutable, validated settings snapshot."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    env: Literal["local", "test", "staging"]
    api_host: str
    api_port: int = Field(ge=1, le=65535)

    # Ingestion boundary (FR-01)
    webhook_secret: str = Field(min_length=16)
    webhook_signature_header: str = "x-itsm-signature"
    webhook_max_body_bytes: int = Field(default=65536, ge=1, le=1_048_576)
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: float = Field(default=60.0, gt=0)

    # Adapter boundary (Mockoon base URLs; allowlisted endpoints derive
    # from these origins only)
    mockoon_itsm_base_url: str
    mockoon_identity_base_url: str
    mockoon_infrastructure_base_url: str
    adapter_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    adapter_max_retries: int = Field(default=2, ge=0, le=5)

    # LLM boundary (Groq, OpenAI-compatible)
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-120b"
    groq_api_key: str | None = None
    groq_max_tokens: int = Field(default=2000, ge=256, le=8192)
    groq_timeout_seconds: float = Field(default=30.0, gt=0, le=120)

    # Observability
    otel_service_name: str = "itsm-agent"
    otel_exporter_endpoint: str | None = None
    metrics_enabled: bool = True

    # Simulator
    simulator_seed: int = 42

    @property
    def llm_configured(self) -> bool:
        return self.groq_api_key is not None


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be an integer") from exc


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be a float") from exc


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"Environment variable {name} must be a boolean")


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Build Settings from the given mapping (default: os.environ).

    Raises ConfigError on any missing required key or invalid value.
    """
    source = os.environ if env is None else env

    def get(name: str) -> str | None:
        return source.get(name)

    def require(name: str) -> str:
        value = get(name)
        if not value:
            raise ConfigError(f"Missing required environment variable: {name}")
        return value

    raw = {
        "env": require("ITSM_ENV"),
        "api_host": get("ITSM_API_HOST") or "127.0.0.1",
        "api_port": _int("ITSM_API_PORT", 8000),
        "webhook_secret": require("ITSM_WEBHOOK_SECRET"),
        "webhook_signature_header": (
            get("ITSM_WEBHOOK_SIGNATURE_HEADER") or "x-itsm-signature"
        ).lower(),
        "webhook_max_body_bytes": _int("ITSM_WEBHOOK_MAX_BODY_BYTES", 65536),
        "rate_limit_requests": _int("ITSM_RATE_LIMIT_REQUESTS", 60),
        "rate_limit_window_seconds": _float("ITSM_RATE_LIMIT_WINDOW_SECONDS", 60.0),
        "mockoon_itsm_base_url": require("ITSM_MOCKOON_ITSM_BASE_URL"),
        "mockoon_identity_base_url": require("ITSM_MOCKOON_IDENTITY_BASE_URL"),
        "mockoon_infrastructure_base_url": require("ITSM_MOCKOON_INFRASTRUCTURE_BASE_URL"),
        "adapter_timeout_seconds": _float("ITSM_ADAPTER_TIMEOUT_SECONDS", 5.0),
        "adapter_max_retries": _int("ITSM_ADAPTER_MAX_RETRIES", 2),
        "groq_base_url": get("ITSM_GROQ_BASE_URL") or "https://api.groq.com/openai/v1",
        "groq_model": get("ITSM_GROQ_MODEL") or "openai/gpt-oss-120b",
        "groq_api_key": get("ITSM_GROQ_API_KEY"),
        "groq_max_tokens": _int("ITSM_GROQ_MAX_TOKENS", 2000),
        "groq_timeout_seconds": _float("ITSM_GROQ_TIMEOUT_SECONDS", 30.0),
        "otel_service_name": get("ITSM_OTEL_SERVICE_NAME") or "itsm-agent",
        "otel_exporter_endpoint": get("ITSM_OTEL_EXPORTER_ENDPOINT"),
        "metrics_enabled": _bool("ITSM_METRICS_ENABLED", True),
        "simulator_seed": _int("ITSM_SIMULATOR_SEED", 42),
    }

    try:
        return Settings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc


def redact_secret(value: str, keep: int = 4) -> str:
    """Return a non-reversible display form of a secret for logs."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


__all__ = ["ConfigError", "Settings", "load_settings", "redact_secret"]
