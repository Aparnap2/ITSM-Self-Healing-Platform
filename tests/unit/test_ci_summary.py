"""Tests for the CI summary gate (``tools/ci_summary.py``).

Marker: ``unit``. The script is exercised as a real subprocess so the exit
code — the only thing CI consumes — is asserted, not an in-process return.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "ci_summary.py"

REPORTS = {
    "unit-junit.xml": "unit",
    "contract-junit.xml": "contract",
    "security-junit.xml": "security",
    "integration-junit.xml": "integration",
    "fault-injection-junit.xml": "fault-injection",
    "scenarios-junit.xml": "scenarios",
    "e2e-junit.xml": "e2e",
}


def _junit(path: Path, *, failures: int = 0, skipped: int = 0) -> None:
    cases = []
    for index in range(3):
        failure = "<failure/>" if index < failures else ""
        skip = "<skipped/>" if index < skipped else ""
        cases.append(
            f'<testcase classname="suite.{path.stem}" name="case_{index}">'
            f"{failure}{skip}</testcase>"
        )
    path.write_text(f'<testsuite tests="3">{"".join(cases)}</testsuite>', encoding="utf-8")


def _needs(*, failed: tuple[str, ...] = ()) -> str:
    jobs = {name: {"result": "success"} for name in REPORTS}
    for name in failed:
        jobs[name] = {"result": "failure"}
    jobs["ci-summary"] = {"result": "skipped"}
    return json.dumps(jobs)


def _run(
    reports: Path,
    needs: str | None,
    *,
    summary_file: Path | None = None,
    optional_jobs: str | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable,
        str(SCRIPT),
        "--reports",
        str(reports),
        "--sha",
        "deadbeef",
    ]
    if needs is not None:
        args.extend(["--needs-json", needs])
    # CI sets GITHUB_STEP_SUMMARY, which redirects output to a file. Tests that
    # assert stdout must opt out of that redirection; one test exercises it.
    env = {key: value for key, value in os.environ.items() if key != "GITHUB_STEP_SUMMARY"}
    if summary_file is not None:
        env["GITHUB_STEP_SUMMARY"] = str(summary_file)
    if optional_jobs is not None:
        args.extend(["--optional-jobs", optional_jobs])
    return subprocess.run(args, capture_output=True, text=True, check=False, env=env)


def test_all_reports_and_successful_needs_exit_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        _junit(tmp_path / filename)

    result = _run(tmp_path, _needs())

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Failures + errors: **0**" in result.stdout


def test_missing_report_exits_non_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        if filename != "e2e-junit.xml":
            _junit(tmp_path / filename)

    result = _run(tmp_path, _needs())

    assert result.returncode == 1
    assert "e2e-junit.xml" in result.stdout


def test_failed_required_job_exits_non_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        _junit(tmp_path / filename)

    result = _run(tmp_path, _needs(failed=("build",)))

    assert result.returncode == 1
    assert "build: failure" in result.stdout


def test_skipped_optional_job_exits_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        _junit(tmp_path / filename)
    payload = json.loads(_needs())
    payload["dast"] = {"result": "skipped"}

    result = _run(tmp_path, json.dumps(payload))

    assert result.returncode == 0, result.stdout + result.stderr


def test_failing_report_exits_non_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        _junit(tmp_path / filename, failures=1 if filename == "unit-junit.xml" else 0)

    result = _run(tmp_path, _needs())

    assert result.returncode == 1


def test_unparseable_needs_json_fails_closed(tmp_path: Path) -> None:
    for filename in REPORTS:
        _junit(tmp_path / filename)

    result = _run(tmp_path, "{not json")

    assert result.returncode != 0
    assert "cannot parse --needs-json" in result.stderr


def test_github_step_summary_is_written_and_exit_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        _junit(tmp_path / filename)
    summary = tmp_path / "summary.md"

    result = _run(tmp_path, _needs(), summary_file=summary)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""
    written = summary.read_text(encoding="utf-8")
    assert "# CI Verification Summary" in written
    assert "Failures + errors: **0**" in written
