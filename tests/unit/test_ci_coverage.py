"""Unit tests for the CI coverage checker.

Marker: ``unit``. The checker is what proves CI runs every declared suite;
these tests prove the checker itself cannot pass vacuously.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "tools" / "ci_coverage.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("itsm_ci_coverage", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


coverage = _load()


def test_every_declared_marker_is_mapped_to_a_suite_target() -> None:
    declared = coverage._declared_markers()  # noqa: SLF001 - unit assertion
    mapped = set(coverage.SUITE_TARGETS)

    assert declared == mapped, (
        "the declared pytest markers and the CI suite mapping have drifted: "
        f"declared={sorted(declared)} mapped={sorted(mapped)}"
    )


def test_every_suite_target_exists_in_the_makefile() -> None:
    targets = coverage._makefile_targets()  # noqa: SLF001 - unit assertion

    for suite, target in coverage.SUITE_TARGETS.items():
        assert target in targets, f"the Makefile has no target {target!r} for {suite!r}"


def test_every_declared_suite_is_run_by_a_ci_job() -> None:
    jobs = coverage._workflow_suites()  # noqa: SLF001 - unit assertion
    covered = {suite for suites in jobs.values() for suite in suites}

    missing = coverage._declared_markers() - covered  # noqa: SLF001
    assert not missing, f"suites not run by any CI job: {sorted(missing)}"


def test_the_checker_passes_against_the_real_workflow() -> None:
    assert coverage.main() == 0


def test_the_known_gaps_are_stated_explicitly() -> None:
    """A gap that is not written down is a gap that gets claimed."""
    gaps = " ".join(coverage.KNOWN_UNCOVERED)

    assert "throughput" in gaps
    assert "trace" in gaps
    assert "load test" in gaps
