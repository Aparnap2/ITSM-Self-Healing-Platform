#!/usr/bin/env python3
"""Aggregate pytest JUnit reports into a reviewable CI summary.

Usage:
    python tools/ci_summary.py \
        --reports reports \
        --sha "$GITHUB_SHA" \
        --run-id "$GITHUB_RUN_ID" \
        --run-attempt "$GITHUB_RUN_ATTEMPT" \
        --head-sha "$PR_HEAD_SHA" \
        --retention-days 30

The script is deterministic and offline. It exits non-zero whenever the run
cannot be proven to be qualified. It never normalises a gap into a green
check:

* a mandatory report is missing, empty, unparseable, or collected zero tests;
* a mandatory report skipped every one of its tests (a silent skip);
* a required job is absent from the run, or did not succeed;
* a report carries a different run's provenance stamp (a stale artifact);
* the artifact retention window was not declared.

Every one of the 15 jobs in ``REQUIRED_JOBS`` is required. A job is relaxed
only when the owner names it explicitly in ``--optional-jobs``; the default
is an empty list, so a DAST failure fails this summary like every other
gate. The optional list is always printed, so a reader can see from the
summary alone whether any gate was relaxed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

#: The seven mandatory marker selections, each uploaded by its CI job.
EXPECTED_REPORTS: dict[str, str] = {
    "unit-junit.xml": "Unit",
    "contract-junit.xml": "Contract",
    "security-junit.xml": "Security & Invariant",
    "integration-junit.xml": "Integration",
    "fault-injection-junit.xml": "Fault Injection",
    "scenarios-junit.xml": "Scenarios",
    "e2e-junit.xml": "E2E",
}

#: The 15 CI job ids that make up the required set. Every job is required.
#: The list is compared against the workflow's ``needs`` payload, so removing,
#: renaming, or silently dropping a job in the workflow fails this summary
#: instead of quietly narrowing the gate. Relaxing a job is an owner decision
#: and must be explicit (``--optional-jobs``).
REQUIRED_JOBS: tuple[str, ...] = (
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
    "ci-summary",
)

#: Number of skipped tests tolerated in a single mandatory suite. Zero by
#: default: a skipped test is a silent skip and must be justified, not
#: tolerated by accident.
DEFAULT_MAX_SKIPPED = 0


@dataclass(frozen=True)
class GroupResult:
    """Counts parsed out of one pytest JUnit report."""

    name: str
    tests: int
    failures: int
    errors: int
    skipped: int
    ids: frozenset[str]

    @property
    def executed(self) -> int:
        """Tests that actually ran (not skipped)."""
        return self.tests - self.skipped


@dataclass(frozen=True)
class Policy:
    """The thresholds this run is judged against."""

    max_skipped: int
    sha: str
    run_id: str
    run_attempt: str
    require_stamps: bool


@dataclass(frozen=True)
class ReportCheck:
    """The verdict for one mandatory report."""

    filename: str
    label: str
    group: GroupResult | None
    collected: int | None
    problems: tuple[str, ...]


@dataclass(frozen=True)
class JobOutcome:
    """The verdict for one required job."""

    name: str
    result: str
    ok: bool
    note: str


def _group_result(label: str, path: Path) -> GroupResult:
    """Parse a JUnit XML report into counts."""
    root = ET.parse(path).getroot()

    cases = list(root.iter("testcase"))
    failures = sum(1 for case in cases if case.find("failure") is not None)
    errors = sum(1 for case in cases if case.find("error") is not None)
    skipped = sum(1 for case in cases if case.find("skipped") is not None)
    ids: set[str] = set()
    for case in cases:
        classname = case.get("classname", "")
        name = case.get("name", "")
        if name:
            ids.add(f"{classname}::{name}")
    return GroupResult(
        name=label,
        tests=len(cases),
        failures=failures,
        errors=errors,
        skipped=skipped,
        ids=frozenset(ids),
    )


def _escape_table(text: str) -> str:
    return text.replace("|", "\\|")


def _stem(filename: str) -> str:
    """Return the report basename without its ``.xml`` suffix."""
    return filename[: -len(".xml")]


def _read_stamp(path: Path) -> dict[str, str]:
    """Read a ``key=value`` provenance stamp."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip():
            values[key.strip()] = value.strip()
    return values


def _read_collected_count(
    reports_dir: Path,
    filename: str,
    policy: Policy,
    problems: list[str],
) -> int | None:
    """Read the ``collected=<n>`` line written by the collect preflight."""
    path = reports_dir / f"{_stem(filename)}.collect.txt"
    if not path.exists():
        if policy.require_stamps:
            problems.append(f"missing collect preflight record `{path.name}`")
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "collected":
            try:
                return int(value.strip())
            except ValueError:
                problems.append(f"`{path.name}` has a bad collected count")
                return None
    if policy.require_stamps:
        problems.append(f"`{path.name}` has no `collected=<n>` line")
    return None


def _check_provenance(
    reports_dir: Path,
    filename: str,
    policy: Policy,
    problems: list[str],
) -> None:
    """Prove the report was produced by this run, not by a stale artifact."""
    path = reports_dir / f"{_stem(filename)}.meta"
    if not path.exists():
        if policy.require_stamps:
            problems.append(f"missing provenance stamp `{path.name}`")
        return
    values = _read_stamp(path)
    expected: tuple[tuple[str, str], ...] = (
        ("sha", policy.sha),
        ("run_id", policy.run_id),
        ("run_attempt", policy.run_attempt),
    )
    for key, want in expected:
        if not want:
            continue
        got = values.get(key)
        if got != want:
            problems.append(f"`{path.name}` {key}={got!r} != {want!r} (stale artifact)")


def _check_report(
    filename: str,
    label: str,
    reports_dir: Path,
    policy: Policy,
) -> ReportCheck:
    """Verify one mandatory report exists, is non-empty, and is not vacuous."""
    problems: list[str] = []
    path = reports_dir / filename
    if not path.exists():
        # Reported in the "Missing mandatory reports" section; the exit code
        # still fails because the report is absent from the evidence set.
        return ReportCheck(filename, label, None, None, ())
    if path.stat().st_size == 0:
        problems.append(f"`{filename}` is empty (0 bytes)")
        return ReportCheck(filename, label, None, None, tuple(problems))
    try:
        group = _group_result(label, path)
    except ET.ParseError as exc:
        problems.append(f"`{filename}` is not parseable XML: {exc}")
        return ReportCheck(filename, label, None, None, tuple(problems))

    if group.tests == 0:
        problems.append(f"`{filename}` collected ZERO tests")
    elif group.executed == 0:
        problems.append(f"`{filename}` skipped all {group.tests} test(s) — a silent skip")
    if group.failures or group.errors:
        problems.append(f"`{filename}`: {group.failures} failed, {group.errors} errored")
    limit = policy.max_skipped
    if group.skipped > limit:
        problems.append(f"`{filename}` skipped {group.skipped} test(s), limit {limit}")

    collected = _read_collected_count(reports_dir, filename, policy, problems)
    if collected == 0:
        problems.append(f"`{filename}` collect preflight counted ZERO tests")
    elif collected is not None and group.tests > collected:
        problems.append(f"`{filename}` reports {group.tests} test(s), collected {collected}")
    _check_provenance(reports_dir, filename, policy, problems)
    return ReportCheck(filename, label, group, collected, tuple(problems))


def _parse_needs(raw: str | None) -> dict[str, str]:
    """Return ``job id -> result`` from ``${{ toJSON(needs) }}``."""
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"cannot parse --needs-json: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("--needs-json must be a JSON object")

    outcomes: dict[str, str] = {}
    for name, record in payload.items():
        if isinstance(record, dict):
            value = record.get("result")
            outcomes[str(name)] = "unknown" if value is None else str(value)
        else:
            outcomes[str(name)] = str(record)
    return outcomes


def _evaluate_jobs(
    outcomes: dict[str, str],
    self_job: str,
    optional_jobs: frozenset[str],
) -> list[JobOutcome]:
    """Judge every required job against the run's job results.

    A job that is absent from the payload did not run at all, which is a
    failure. A job that did not reach ``success`` is a failure unless the
    owner explicitly marked it optional.
    """
    evaluated: list[JobOutcome] = []
    for name in REQUIRED_JOBS:
        if name == self_job:
            continue
        if name not in outcomes:
            note = "absent from the needs payload — did not run"
            evaluated.append(JobOutcome(name, "absent", False, note))
            continue
        result = outcomes[name]
        if result == "success":
            evaluated.append(JobOutcome(name, result, True, "success"))
            continue
        if name in optional_jobs:
            evaluated.append(JobOutcome(name, result, True, f"{result} — owner-marked optional"))
            continue
        evaluated.append(JobOutcome(name, result, False, result))
    for name in sorted(set(outcomes) - set(REQUIRED_JOBS)):
        note = "not in REQUIRED_JOBS — the required set must be updated explicitly"
        evaluated.append(JobOutcome(name, outcomes[name], False, note))
    return evaluated


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate CI JUnit reports into a CI summary.")
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    parser.add_argument(
        "--head-sha",
        default="",
        help="PR head SHA, printed for run binding (blank for a push run).",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=0,
        help="Explicit artifact retention window; 0 means 'not declared' and fails.",
    )
    parser.add_argument(
        "--max-skipped",
        type=int,
        default=DEFAULT_MAX_SKIPPED,
        help="Skipped tests tolerated per mandatory suite.",
    )
    parser.add_argument(
        "--optional-jobs",
        default="",
        help="Comma-separated jobs allowed to be non-success (empty by default).",
    )
    parser.add_argument(
        "--needs-json",
        default=os.environ.get("NEEDS_RESULTS"),
        help="JSON from ${{ toJSON(needs) }}; non-success required jobs fail the summary.",
    )
    parser.add_argument(
        "--self-job",
        default="ci-summary",
        help="Name of this summary job; excluded from the needs check.",
    )
    parser.add_argument(
        "--require-needs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require job results to be supplied (disable only for a local re-check).",
    )
    parser.add_argument(
        "--require-stamps",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require the collect preflight record and the provenance stamp per report.",
    )
    parser.add_argument(
        "--post-to-summary",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Write the summary to $GITHUB_STEP_SUMMARY instead of stdout.",
    )
    return parser


def _suite_row(check: ReportCheck) -> str:
    """Render one row of the mandatory test-suite table."""
    if check.group is None:
        cells = [_escape_table(check.label), "—", "—", "—", "—", "—", "**MISSING**"]
        return "| " + " | ".join(cells) + " |"
    group = check.group
    collected = "—" if check.collected is None else str(check.collected)
    cells = [
        _escape_table(check.label),
        collected,
        str(group.tests),
        str(group.failures),
        str(group.errors),
        str(group.skipped),
        str(group.executed),
    ]
    return "| " + " | ".join(cells) + " |"


def main() -> int:
    args = _build_parser().parse_args()

    reports_dir: Path = args.reports
    sha: str = str(args.sha)
    run_id: str = str(args.run_id)
    run_attempt: str = str(args.run_attempt)
    head_sha: str = str(args.head_sha)
    retention_days: int = int(args.retention_days)
    max_skipped: int = int(args.max_skipped)
    self_job: str = str(args.self_job)
    require_needs: bool = bool(args.require_needs)
    require_stamps: bool = bool(args.require_stamps)
    post_to_summary: bool = bool(args.post_to_summary)
    optional_jobs: frozenset[str] = frozenset(
        name.strip() for name in str(args.optional_jobs).split(",") if name.strip()
    )

    if not reports_dir.is_dir():
        raise SystemExit(f"reports directory not found: {reports_dir}")

    policy = Policy(
        max_skipped=max_skipped,
        sha=sha,
        run_id=run_id,
        run_attempt=run_attempt,
        require_stamps=require_stamps,
    )

    problems: list[str] = []
    if self_job not in REQUIRED_JOBS:
        problems.append(f"self job {self_job!r} is not in REQUIRED_JOBS")
    unknown = sorted(optional_jobs - set(REQUIRED_JOBS))
    if unknown:
        names = ", ".join(unknown)
        problems.append(f"--optional-jobs names unknown job(s): {names}")
    if retention_days <= 0:
        problems.append("artifact retention was not declared (--retention-days must be > 0)")

    checks = [
        _check_report(filename, label, reports_dir, policy)
        for filename, label in EXPECTED_REPORTS.items()
    ]
    groups: list[GroupResult] = []
    missing: list[str] = []
    for check in checks:
        if check.group is None:
            missing.append(check.filename)
        else:
            groups.append(check.group)
    for check in checks:
        problems.extend(check.problems)

    outcomes = _parse_needs(args.needs_json)
    if require_needs and not outcomes:
        problems.append(
            "no job results were supplied (NEEDS_RESULTS empty) — job conclusions unverified"
        )
    job_outcomes = _evaluate_jobs(outcomes, self_job, optional_jobs)
    failed_jobs = [job for job in job_outcomes if not job.ok]

    failed = sum(group.failures + group.errors for group in groups)
    skipped = sum(group.skipped for group in groups)
    unique = len(set().union(*(group.ids for group in groups))) if groups else 0
    expiry = "NOT DECLARED"
    if retention_days > 0:
        window = datetime.now(UTC) + timedelta(days=retention_days)
        expiry = window.strftime("%Y-%m-%d %H:%M UTC")
    retention_label = str(retention_days) if retention_days > 0 else "NOT DECLARED"
    optional_label = ", ".join(sorted(optional_jobs)) or "none"

    lines: list[str] = []
    lines.append("# CI Verification Summary")
    lines.append("")
    lines.append(f"- **Commit under test:** `{sha}`")
    lines.append(f"- **Run:** `{run_id or 'unknown'}` — attempt `{run_attempt or 'unknown'}`")
    lines.append(f"- **PR head SHA:** `{head_sha or 'n/a (push run)'}`")
    lines.append(f"- **Required jobs:** {len(REQUIRED_JOBS)} — all required")
    lines.append(f"- **Owner-marked optional jobs:** {optional_label}")
    lines.append(f"- **Artifact retention:** {retention_label} days — expires {expiry}")
    lines.append("")

    lines.append("## Required job results")
    lines.append("")
    lines.append("| Job | Result | Verdict |")
    lines.append("| --- | --- | --- |")
    for job in job_outcomes:
        verdict = "PASS" if job.ok else "FAIL"
        cells = [f"`{job.name}`", f"`{job.result}`", f"{verdict} — {job.note}"]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    lines.append("## Mandatory test suites")
    lines.append("")
    lines.append("| Area | Collected | Tests | Failed | Errors | Skipped | Executed |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for check in checks:
        lines.append(_suite_row(check))
    lines.append("")
    lines.append(f"- Unique tests across reports: **{unique}**")
    lines.append(f"- Failures + errors: **{failed}**")
    lines.append(f"- Skipped tests: **{skipped}**")
    lines.append("")

    if missing:
        lines.append("**Missing mandatory reports:**")
        for filename in sorted(missing):
            lines.append(f"- `{filename}`")
        lines.append("")
        lines.append("**Missing mandatory group(s) — this run is not qualified.**")
        lines.append("")
    if failed_jobs:
        lines.append("**Required jobs that did not succeed:**")
        for job in failed_jobs:
            lines.append(f"- `{job.name}`: {job.result} ({job.note})")
        lines.append("")
        lines.append("**Required job(s) did not succeed — this run is not qualified.**")
        lines.append("")
    if problems:
        lines.append("**Disqualifying findings:**")
        for problem in problems:
            lines.append(f"- {problem}")
        lines.append("")
        lines.append("**This run is not qualified.**")
        lines.append("")

    output = "\n".join(lines) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and post_to_summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")
    return 1 if (problems or missing or failed_jobs or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
