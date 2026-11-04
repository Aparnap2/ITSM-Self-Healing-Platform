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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--post-to-summary", action="store_true", default=True)
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

    output = "\n".join(lines) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and args.post_to_summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")
    return 1 if missing or failed else 0


if __name__ == "__main__":
    sys.exit(main())
