#!/usr/bin/env python3
"""Aggregate pytest JUnit reports into a reviewable CI summary.

Usage:
    python tools/ci_summary.py --reports reports --sha "$GITHUB_SHA"

The script is deterministic and offline. It exits non-zero when a mandatory
report is missing or contains a failure/error; it never normalises a missing
group into a passing green check.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
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


@dataclass(frozen=True)
class GroupResult:
    name: str
    tests: int
    failures: int
    errors: int
    skipped: int
    ids: frozenset[str]


def _group_result(label: str, path: Path) -> GroupResult:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise SystemExit(f"cannot parse {path}: {exc}") from exc

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


def _failed_needs(raw: str | None, self_job: str, optional_jobs: frozenset[str]) -> list[str]:
    """Return required jobs whose result is not ``success``.

    GitHub exposes ``needs`` to a job as JSON via ``toJSON(needs)``. A job
    that is missing from the mapping did not run at all; that is a failure for
    qualification purposes. Jobs named in ``optional_jobs`` may be ``skipped``
    (for example a PR-only job on a push event) without failing the summary.
    """
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"cannot parse --needs-json: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("--needs-json must be a JSON object")

    failures: list[str] = []
    for name, record in payload.items():
        if name == self_job:
            continue
        result = record.get("result") if isinstance(record, dict) else record
        if result == "success":
            continue
        if result == "skipped" and name in optional_jobs:
            continue
        failures.append(f"{name}: {result}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--post-to-summary", action="store_true", default=True)
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
        "--optional-jobs",
        default="dependency-review,dast",
        help="Comma-separated jobs allowed to be skipped without failing.",
    )
    args = parser.parse_args()

    if not args.reports.is_dir():
        raise SystemExit(f"reports directory not found: {args.reports}")

    results: list[GroupResult] = []
    missing: list[str] = []
    for filename, label in EXPECTED_REPORTS.items():
        candidate = args.reports / filename
        if not candidate.exists():
            missing.append(filename)
            continue
        results.append(_group_result(label, candidate))

    failed_needs = _failed_needs(
        args.needs_json,
        args.self_job,
        frozenset(name.strip() for name in args.optional_jobs.split(",") if name.strip()),
    )

    lines: list[str] = []
    lines.append("# CI Verification Summary")
    lines.append(f"Commit: `{args.sha}`")
    lines.append("")
    failed = sum(group.failures + group.errors for group in results)
    skipped = sum(group.skipped for group in results)
    if missing:
        lines.append("**Missing mandatory reports:**")
        for filename in sorted(missing):
            lines.append(f"- `{filename}`")
        lines.append("")
    if failed_needs:
        lines.append("**Required jobs that did not succeed:**")
        for entry in failed_needs:
            lines.append(f"- `{entry}`")
        lines.append("")
    lines.append("| Area | Tests | Failed | Errors | Skipped |")
    lines.append("| --- | ---: | ---: | ----: | ------: |")
    for group in results:
        lines.append(
            f"| {_escape_table(group.name)} "
            f"| {group.tests} | {group.failures} | {group.errors} | {group.skipped} |"
        )
    unique = len(set().union(*(group.ids for group in results))) if results else 0
    lines.append("")
    lines.append(f"Unique tests across reports: **{unique}**")
    lines.append(f"Failures + errors: **{failed}**")
    lines.append(f"Skipped tests: **{skipped}**")
    if missing:
        lines.append("**Missing mandatory group(s) — this run is not qualified.**")
    if failed_needs:
        lines.append("**Required job(s) did not succeed — this run is not qualified.**")

    output = "\n".join(lines) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and args.post_to_summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")
    return 1 if missing or failed or failed_needs else 0


if __name__ == "__main__":
    sys.exit(main())
