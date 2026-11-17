"""Tests for the CI summary gate (``tools/ci_summary.py``).

Marker: ``unit``. The script is exercised as a real subprocess so the exit
code — the only thing CI consumes — is asserted, not an in-process return.

The script's contract is deliberately strict: every required job must be
present and successful, every mandatory report must exist, be non-empty,
have collected a non-zero number of tests, have executed (not skipped) all
of them, and carry this run's provenance stamp.
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

SHA = "deadbeef"
RUN_ID = "4242"
RUN_ATTEMPT = "1"
RETENTION_DAYS = "30"

REPORTS = {
    "unit-junit.xml": "unit",
    "contract-junit.xml": "contract",
    "security-junit.xml": "security",
    "integration-junit.xml": "integration",
    "fault-injection-junit.xml": "fault-injection",
    "scenarios-junit.xml": "scenarios",
    "e2e-junit.xml": "e2e",
}

#: The job ids the summary requires, minus the summary job itself (a job
#: cannot appear in its own ``needs`` payload).
JOB_IDS = (
    "lint",
    "typecheck",
    "secret-scan",
    "workflow-security",
    "supply-chain",
    "unit-tests",
    "contract-tests",
    "security-invariants",
    "build",
    "dast",
    "integration-tests",
    "fault-injection-tests",
    "e2e-tests",
    "scenarios",
)


def _write_report(
    reports: Path,
    filename: str,
    *,
    failures: int = 0,
    skipped: int = 0,
    tests: int = 3,
    sha: str = SHA,
    run_id: str = RUN_ID,
    run_attempt: str = RUN_ATTEMPT,
    collected: int | None = None,
    write_collect: bool = True,
    write_meta: bool = True,
) -> None:
    """Write one JUnit report plus its collect record and provenance stamp."""
    cases = []
    for index in range(tests):
        failure = "<failure/>" if index < failures else ""
        skip = "<skipped/>" if index < skipped else ""
        cases.append(
            f'<testcase classname="suite.{Path(filename).stem}" name="case_{index}">'
            f"{failure}{skip}</testcase>"
        )
    (reports / filename).write_text(
        f'<testsuite tests="{tests}">{"".join(cases)}</testsuite>', encoding="utf-8"
    )
    stem = Path(filename).stem
    if write_collect:
        count = tests if collected is None else collected
        (reports / f"{stem}.collect.txt").write_text(f"collected={count}\n", encoding="utf-8")
    if write_meta:
        (reports / f"{stem}.meta").write_text(
            f"sha={sha}\nrun_id={run_id}\nrun_attempt={run_attempt}\njob=unit-tests\n",
            encoding="utf-8",
        )


def _write_all(reports: Path) -> None:
    for filename in REPORTS:
        _write_report(reports, filename)


def _needs(*, failed: tuple[str, ...] = (), skipped: tuple[str, ...] = ()) -> str:
    jobs = {name: {"result": "success"} for name in JOB_IDS}
    for name in failed:
        jobs[name] = {"result": "failure"}
    for name in skipped:
        jobs[name] = {"result": "skipped"}
    return json.dumps(jobs)


def _run(
    reports: Path,
    needs: str | None,
    *,
    summary_file: Path | None = None,
    optional_jobs: str | None = None,
    retention_days: str | None = RETENTION_DAYS,
) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable,
        str(SCRIPT),
        "--reports",
        str(reports),
        "--sha",
        SHA,
        "--run-id",
        RUN_ID,
        "--run-attempt",
        RUN_ATTEMPT,
    ]
    if retention_days is not None:
        args.extend(["--retention-days", retention_days])
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
    _write_all(tmp_path)

    result = _run(tmp_path, _needs())

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Failures + errors: **0**" in result.stdout


def test_missing_report_exits_non_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        if filename != "e2e-junit.xml":
            _write_report(tmp_path, filename)

    result = _run(tmp_path, _needs())

    assert result.returncode == 1
    assert "e2e-junit.xml" in result.stdout


def test_failed_required_job_exits_non_zero(tmp_path: Path) -> None:
    _write_all(tmp_path)

    result = _run(tmp_path, _needs(failed=("build",)))

    assert result.returncode == 1
    assert "build" in result.stdout
    assert "not qualified" in result.stdout


def test_skipped_required_job_exits_non_zero(tmp_path: Path) -> None:
    """DAST is required: a skipped DAST is not qualified by default."""
    _write_all(tmp_path)

    result = _run(tmp_path, _needs(skipped=("dast",)))

    assert result.returncode == 1, result.stdout + result.stderr
    assert "dast" in result.stdout
    assert "not qualified" in result.stdout


def test_owner_marked_optional_job_may_be_skipped(tmp_path: Path) -> None:
    """An owner-marked optional job is the only way to relax the gate."""
    _write_all(tmp_path)

    result = _run(tmp_path, _needs(skipped=("dast",)), optional_jobs="dast")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "owner-marked optional" in result.stdout


def test_missing_required_job_exits_non_zero(tmp_path: Path) -> None:
    """A required job that never ran is a failure, not an absence."""
    _write_all(tmp_path)
    payload = json.loads(_needs())
    del payload["dast"]

    result = _run(tmp_path, json.dumps(payload))

    assert result.returncode == 1, result.stdout + result.stderr
    assert "absent" in result.stdout


def test_unexpected_job_exits_non_zero(tmp_path: Path) -> None:
    """The required set is explicit: an unlisted job fails the summary."""
    _write_all(tmp_path)
    payload = json.loads(_needs())
    payload["surprise-job"] = {"result": "success"}

    result = _run(tmp_path, json.dumps(payload))

    assert result.returncode == 1, result.stdout + result.stderr
    assert "surprise-job" in result.stdout


def test_failing_report_exits_non_zero(tmp_path: Path) -> None:
    for filename in REPORTS:
        _write_report(tmp_path, filename, failures=1 if filename == "unit-junit.xml" else 0)

    result = _run(tmp_path, _needs())

    assert result.returncode == 1


def test_zero_test_report_exits_non_zero(tmp_path: Path) -> None:
    """A report that collected nothing must not pass vacuously."""
    for filename in REPORTS:
        _write_report(
            tmp_path,
            filename,
            tests=0,
            collected=0 if filename == "unit-junit.xml" else None,
        )

    result = _run(tmp_path, _needs())

    assert result.returncode == 1, result.stdout + result.stderr
    assert "ZERO tests" in result.stdout


def test_fully_skipped_report_exits_non_zero(tmp_path: Path) -> None:
    """A suite whose tests were all skipped is a silent skip, not a pass."""
    for filename in REPORTS:
        _write_report(
            tmp_path,
            filename,
            skipped=3 if filename == "unit-junit.xml" else 0,
        )

    result = _run(tmp_path, _needs())

    assert result.returncode == 1, result.stdout + result.stderr
    assert "silent skip" in result.stdout


def test_stale_provenance_stamp_exits_non_zero(tmp_path: Path) -> None:
    """A report from another run must not be presented as this run's evidence."""
    for filename in REPORTS:
        _write_report(
            tmp_path,
            filename,
            sha="cafebabe" if filename == "unit-junit.xml" else SHA,
        )

    result = _run(tmp_path, _needs())

    assert result.returncode == 1, result.stdout + result.stderr
    assert "stale artifact" in result.stdout


def test_missing_collect_record_exits_non_zero(tmp_path: Path) -> None:
    """Without the collect preflight the report cannot be proven non-vacuous."""
    for filename in REPORTS:
        _write_report(
            tmp_path,
            filename,
            write_collect=filename != "unit-junit.xml",
        )

    result = _run(tmp_path, _needs())

    assert result.returncode == 1, result.stdout + result.stderr
    assert "collect preflight" in result.stdout


def test_undeclared_retention_exits_non_zero(tmp_path: Path) -> None:
    """The artifact retention window must be declared, not inherited silently."""
    _write_all(tmp_path)

    result = _run(tmp_path, _needs(), retention_days=None)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "retention" in result.stdout


def test_unparseable_needs_json_fails_closed(tmp_path: Path) -> None:
    _write_all(tmp_path)

    result = _run(tmp_path, "{not json")

    assert result.returncode != 0
    assert "cannot parse --needs-json" in result.stderr


def test_github_step_summary_is_written_and_exit_zero(tmp_path: Path) -> None:
    _write_all(tmp_path)
    summary = tmp_path / "summary.md"

    result = _run(tmp_path, _needs(), summary_file=summary)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""
    written = summary.read_text(encoding="utf-8")
    assert "# CI Verification Summary" in written
    assert "Failures + errors: **0**" in written
