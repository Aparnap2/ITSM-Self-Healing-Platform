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

    # Reviewer authentication. HMAC is a development/test-only placeholder;
    # OIDC is the production path. ``load_settings`` refuses HMAC in staging.
    auth_mode: Literal["hmac", "oidc"] = "hmac"
    auth_hmac_secret: str | None = Field(default=None, min_length=16)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_algorithms: tuple[str, ...] = ("RS256", "ES256")
    oidc_jwks_cache_seconds: float = Field(default=300.0, gt=0)
    oidc_leeway_seconds: float = Field(default=30.0, ge=0, le=120)
    oidc_max_token_age_seconds: float | None = Field(default=3600.0, gt=0)

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
        "auth_mode": (get("ITSM_AUTH_MODE") or "hmac").strip().lower(),
        "auth_hmac_secret": get("ITSM_AUTH_HMAC_SECRET"),
        "oidc_issuer": get("ITSM_OIDC_ISSUER"),
        "oidc_audience": get("ITSM_OIDC_AUDIENCE"),
        "oidc_jwks_url": get("ITSM_OIDC_JWKS_URL"),
        "oidc_algorithms": tuple(
            part.strip().upper()
            for part in (get("ITSM_OIDC_ALGORITHMS") or "RS256,ES256").split(",")
            if part.strip()
        ),
        "oidc_jwks_cache_seconds": _float("ITSM_OIDC_JWKS_CACHE_SECONDS", 300.0),
        "oidc_leeway_seconds": _float("ITSM_OIDC_LEEWAY_SECONDS", 30.0),
        "oidc_max_token_age_seconds": _float("ITSM_OIDC_MAX_TOKEN_AGE_SECONDS", 3600.0),
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
        settings = Settings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc

    # Fail closed at configuration time: HMAC is an explicitly development/
    # test-only mechanism, not a production identity provider.
    if settings.auth_mode == "hmac":
        if settings.env == "staging":
            raise ConfigError("ITSM_AUTH_MODE=hmac is not permitted when ITSM_ENV=staging")
        if not settings.auth_hmac_secret:
            raise ConfigError("Missing required environment variable: ITSM_AUTH_HMAC_SECRET")
    else:
        missing = [
            name
            for name, value in (
                ("ITSM_OIDC_ISSUER", settings.oidc_issuer),
                ("ITSM_OIDC_AUDIENCE", settings.oidc_audience),
                ("ITSM_OIDC_JWKS_URL", settings.oidc_jwks_url),
            )
            if not value
        ]
        if missing:
            raise ConfigError("Missing required OIDC configuration: " + ", ".join(missing))
    return settings


def redact_secret(value: str, keep: int = 4) -> str:
    """Return a non-reversible display form of a secret for logs."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


__all__ = ["ConfigError", "Settings", "load_settings", "redact_secret"]
