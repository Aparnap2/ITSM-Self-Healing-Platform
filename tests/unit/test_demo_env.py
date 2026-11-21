"""Unit tests for the local demo environment bootstrap (offline).

Marker: ``unit``. These tests pin the two properties that make the target safe
to re-run: an existing value is never overwritten, and no secret is ever
printed. Everything else is file manipulation in a temporary directory.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "demo_env.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_env_under_test", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def demo_env() -> ModuleType:
    return _load()


def test_ensure_creates_static_keys_ports_and_secrets(demo_env: ModuleType, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    added, problems = demo_env.ensure(env_file, environ={"GROQ_API_KEY": "gsk-test"})

    assert problems == []
    values = demo_env.read_env(env_file)
    for key in demo_env.STATIC_VALUES:
        assert values.get(key), f"{key} missing"
    for key in demo_env.DEMO_PORTS:
        assert values.get(key), f"{key} missing"
    for key in demo_env.SECRET_KEYS:
        assert values.get(key), f"{key} missing"
        assert len(values[key]) >= 32
    assert values["ITSM_GROQ_API_KEY"] == "gsk-test"
    assert "ITSM_POSTGRES_DSN" in values
    # Host URLs are derived from the ports rather than frozen, so they are not
    # in STATIC_VALUES; what must hold is that every key written was reported.
    for key in (
        "ITSM_API_BASE_URL",
        "ITSM_IDENTITY_BASE_URL",
        "ITSM_NATS_URL",
        "ITSM_PROMETHEUS_URL",
    ):
        assert values.get(key), f"{key} missing"
    assert set(added) == set(values)


def test_ensure_is_idempotent_and_never_duplicates_keys(
    demo_env: ModuleType, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    first, _ = demo_env.ensure(env_file, environ={"GROQ_API_KEY": "gsk-test"})
    assert first

    second, problems = demo_env.ensure(env_file, environ={"GROQ_API_KEY": "gsk-test"})
    assert second == []
    assert problems == []

    text = env_file.read_text(encoding="utf-8")
    for key in demo_env.SECRET_KEYS:
        assert text.count(f"{key}=") == 1


def test_existing_values_always_win(demo_env: ModuleType, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "POSTGRES_PASSWORD=human-chosen\nITSM_ENV=local\nITSM_GROQ_API_KEY=gsk-existing\n",
        encoding="utf-8",
    )

    demo_env.ensure(env_file, environ={})
    values = demo_env.read_env(env_file)

    assert values["POSTGRES_PASSWORD"] == "human-chosen"
    assert values["ITSM_ENV"] == "local"  # not silently rewritten to staging
    assert values["ITSM_GROQ_API_KEY"] == "gsk-existing"


def test_missing_groq_key_is_reported_not_silently_disabled(
    demo_env: ModuleType, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    _added, problems = demo_env.ensure(env_file, environ={})

    assert len(problems) == 1
    assert "ITSM_GROQ_API_KEY" in problems[0]
    values = demo_env.read_env(env_file)
    assert not values.get("ITSM_GROQ_API_KEY")
    # The demo must not start with the investigation stage quietly off.
    assert values["ITSM_INVESTIGATION_ENABLED"] == "true"


def test_status_reports_missing_keys_without_printing_values(
    demo_env: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env_file = tmp_path / ".env"
    assert demo_env.status(env_file) == 1
    out = capsys.readouterr().out
    assert "missing:" in out

    demo_env.ensure(env_file, environ={"GROQ_API_KEY": "gsk-secret-value"})
    capsys.readouterr()
    assert demo_env.status(env_file) == 0
    out = capsys.readouterr().out
    assert "gsk-secret-value" not in out
    assert "groq key: set" in out


def test_generated_secrets_are_distinct_per_file(demo_env: ModuleType, tmp_path: Path) -> None:
    first = tmp_path / "one.env"
    second = tmp_path / "two.env"
    demo_env.ensure(first, environ={"GROQ_API_KEY": "gsk-test"})
    demo_env.ensure(second, environ={"GROQ_API_KEY": "gsk-test"})

    a = demo_env.read_env(first)
    b = demo_env.read_env(second)
    for key in demo_env.SECRET_KEYS:
        assert a[key] != b[key]


def test_a_password_from_the_environment_reaches_the_file_and_the_dsn(
    demo_env: ModuleType, tmp_path: Path
) -> None:
    """An env-only password must not yield an empty --admin-dsn.

    `have()` used to see the process environment and skip the key, while the
    DSN was built from the file only. The next command then received an empty
    DSN and `ensure` still reported success.
    """
    env_file = tmp_path / ".env"
    added, problems = demo_env.ensure(
        env_file,
        environ={"GROQ_API_KEY": "gsk-test", "POSTGRES_PASSWORD": "from-environment"},
    )
    assert problems == []
    values = demo_env.read_env(env_file)
    assert values["POSTGRES_PASSWORD"] == "from-environment"
    assert "from-environment" in values["ITSM_POSTGRES_DSN"]
    assert "POSTGRES_PASSWORD" in added
    assert "ITSM_POSTGRES_DSN" in added


def test_overridden_ports_move_the_urls_and_the_dsn(demo_env: ModuleType, tmp_path: Path) -> None:
    """A preserved port must not be contradicted by a derived URL."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "API_HOST_PORT=8011\nPOSTGRES_HOST_PORT=5540\nIDENTITY_HOST_PORT=8445\n",
        encoding="utf-8",
    )
    demo_env.ensure(env_file, environ={"GROQ_API_KEY": "gsk-test"})
    values = demo_env.read_env(env_file)
    assert values["API_HOST_PORT"] == "8011"
    assert values["ITSM_API_BASE_URL"] == "http://127.0.0.1:8011"
    assert values["ITSM_IDENTITY_BASE_URL"] == "https://127.0.0.1:8445"
    assert ":5540/" in values["ITSM_POSTGRES_DSN"]


def test_a_quoted_empty_credential_counts_as_missing(demo_env: ModuleType, tmp_path: Path) -> None:
    """`KEY=''` is empty to a shell, so it must be empty here too."""
    env_file = tmp_path / ".env"
    env_file.write_text("ITSM_GROQ_API_KEY=''\n", encoding="utf-8")
    _, problems = demo_env.ensure(env_file, environ={})
    assert problems, "a quoted empty key must still be reported as missing"
    assert demo_env.read_env(env_file)["ITSM_GROQ_API_KEY"] == ""


def test_preserved_database_identity_is_used_for_the_dsn(
    demo_env: ModuleType, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("POSTGRES_USER=auditor\nPOSTGRES_DB=evidence\n", encoding="utf-8")
    demo_env.ensure(env_file, environ={"GROQ_API_KEY": "gsk-test"})
    dsn = demo_env.read_env(env_file)["ITSM_POSTGRES_DSN"]
    assert "//auditor:" in dsn
    assert dsn.endswith("/evidence")
