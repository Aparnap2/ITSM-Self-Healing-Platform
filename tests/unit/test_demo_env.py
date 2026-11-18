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
    assert set(added) == {
        *demo_env.STATIC_VALUES,
        *demo_env.DEMO_PORTS,
        *demo_env.SECRET_KEYS,
        "ITSM_GROQ_API_KEY",
        "ITSM_POSTGRES_DSN",
    }


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
