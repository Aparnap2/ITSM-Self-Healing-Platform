"""Unit tests for the staging readiness gate's verdict algebra (offline).

Marker: ``unit``. The probes themselves are live-only; what is testable
offline is the rule that decides the gate, and that rule must fail closed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "demo_readiness.py"


@pytest.fixture(scope="module")
def readiness_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_readiness_under_test", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _report(module: ModuleType, mode: str = "full") -> Any:
    return module.Readiness(commit="deadbeef", started_at="2026-01-01T00:00:00Z", mode=mode)


def test_all_pass_is_pass(readiness_module: ModuleType) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    report.add("b", "PASS", "ok")
    assert report.verdict == "PASS"


def test_any_fail_is_fail(readiness_module: ModuleType) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    report.add("b", "FAIL", "boom")
    assert report.verdict == "FAIL"


def test_not_run_never_reads_as_pass_in_the_full_gate(
    readiness_module: ModuleType,
) -> None:
    """In full mode an unrun check is not evidence of readiness."""
    report = _report(readiness_module, mode="full")
    report.add("a", "PASS", "ok")
    report.add("b", "NOT RUN", "API unreachable")
    assert report.verdict == "FAIL"


def test_smoke_mode_makes_no_qualification_claim(
    readiness_module: ModuleType,
) -> None:
    """A smoke check is not the gate, and says so in its own name."""
    report = _report(readiness_module, mode="fast")
    report.add("a", "PASS", "ok")
    report.add("b", "NOT RUN", "skipped in the fast path")
    assert report.gate == "STAGING_SMOKE"
    assert report.verdict == "PASS"
    assert report.evidence()["gate"] == "STAGING_SMOKE"


def test_full_mode_reports_the_qualification_gate_name(
    readiness_module: ModuleType,
) -> None:
    report = _report(readiness_module, mode="full")
    report.add("a", "PASS", "ok")
    assert report.gate == "STAGING_READY"
    assert report.evidence()["gate"] == "STAGING_READY"


def test_not_applicable_does_not_block_an_otherwise_passing_gate(
    readiness_module: ModuleType,
) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    report.add("b", "NOT APPLICABLE", "feature not enabled in this mode")
    assert report.verdict == "PASS"


def test_evidence_is_bound_to_the_commit_and_states_its_limits(
    readiness_module: ModuleType,
) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    evidence = report.evidence()

    assert evidence["gate"] == "STAGING_READY"
    assert evidence["commit"] == "deadbeef"
    assert evidence["verdict"] == "PASS"
    assert evidence["checks"] == [{"name": "a", "verdict": "PASS", "detail": "ok"}]
    limits = evidence["does_not_prove"]
    assert any("throughput" in item for item in limits)
    assert any("production readiness" in item for item in limits)


def test_http_success_predicate_is_not_any_2xx_parsing_quirk(
    readiness_module: ModuleType,
) -> None:
    assert readiness_module._is_ok(200)
    assert readiness_module._is_ok(204)
    assert not readiness_module._is_ok(301)
    assert not readiness_module._is_ok(401)
    assert not readiness_module._is_ok(500)
