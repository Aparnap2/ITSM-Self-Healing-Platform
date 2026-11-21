"""Evidence capture must bind artifacts to *this* invocation.

Marker: ``unit``. The screenshots are taken live; what is testable offline is
that a stale file cannot be reported as a fresh capture, and that the
documented ``--run-id`` actually reaches the index.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "demo_capture.py"


@pytest.fixture(scope="module")
def capture_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_capture_under_test", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a_leftover_screenshot_cannot_be_reported_as_fresh(
    capture_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "10-shot.png"
    target.write_bytes(b"a screenshot from an earlier run")
    # A browser that exits successfully without writing anything: the exact
    # shape of the failure the existence check used to miss.
    monkeypatch.setattr(capture_module, "_chrome", lambda: "/bin/true")

    entry = capture_module._screenshot("http://127.0.0.1:8001", target, "note")

    assert entry["status"] == "FAIL"
    assert not target.exists()


def test_a_screenshot_written_during_this_call_passes(
    capture_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "10-shot.png"
    monkeypatch.setattr(capture_module, "_chrome", lambda: "/bin/true")

    def fake_run(*_args: object, **_kwargs: object) -> object:
        target.write_bytes(b"fresh bytes")
        return type("Result", (), {"stderr": ""})()

    monkeypatch.setattr(capture_module.subprocess, "run", fake_run)

    entry = capture_module._screenshot("http://127.0.0.1:8001", target, "note")

    assert entry["status"] == "PASS"
    assert entry["bytes"] == len(b"fresh bytes")


async def test_the_supplied_run_id_reaches_the_index(
    capture_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def empty(_out: Path) -> list[object]:
        return []

    async def no_migrations(_out: Path) -> dict[str, object]:
        return {}

    monkeypatch.setattr(capture_module, "_raw_captures", empty)
    monkeypatch.setattr(capture_module, "_migrations", no_migrations)
    monkeypatch.setattr(capture_module, "_screenshots", lambda _out, _phase: [])
    monkeypatch.setattr(capture_module, "_chrome", lambda: "/bin/true")
    monkeypatch.setattr(capture_module, "_git_commit", lambda: "deadbeef")

    args = Namespace(phase="b", out_dir=str(tmp_path), run_id="run-123")
    code = await capture_module.main_async(args)

    assert code == 0
    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert index["run_id"] == "run-123"


async def test_an_omitted_run_id_is_recorded_as_absent(
    capture_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def empty(_out: Path) -> list[object]:
        return []

    async def no_migrations(_out: Path) -> dict[str, object]:
        return {}

    monkeypatch.setattr(capture_module, "_raw_captures", empty)
    monkeypatch.setattr(capture_module, "_migrations", no_migrations)
    monkeypatch.setattr(capture_module, "_screenshots", lambda _out, _phase: [])
    monkeypatch.setattr(capture_module, "_chrome", lambda: "/bin/true")
    monkeypatch.setattr(capture_module, "_git_commit", lambda: "deadbeef")

    args = Namespace(phase="a", out_dir=str(tmp_path), run_id="")
    await capture_module.main_async(args)

    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert index["run_id"] is None
