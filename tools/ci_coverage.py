"""Check that CI actually runs every test suite the project declares.

Explicit coverage, not assumption: a suite that exists in ``pyproject.toml``
but is not executed by any CI job is a silently unrun suite, and a job that
runs a suite CI no longer knows about is a silently dropped gate. This
script is the mechanical check of both, and it prints the matrix it verified.

Run offline; no network, no services.

    uv run python tools/ci_coverage.py

Exit codes: 0 every declared suite is covered, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPO_ROOT / "Makefile"

#: The Makefile target that runs each pytest suite. The CI workflow invokes
#: these targets, so the mapping is the suite's identity in CI.
SUITE_TARGETS: dict[str, str] = {
    "unit": "test-unit",
    "contract": "test-contract",
    "security": "test-security",
    "fault_injection": "test-fault-injection",
    "integration": "test-integration",
    "scenarios": "test-scenarios",
    "e2e": "test-e2e",
}

#: What each suite category proves, and what it deliberately does not.
CATEGORY_NOTES: dict[str, str] = {
    "unit": "pure domain, policy and contract logic; no network, no services",
    "contract": "adapters against the simulators (Moto/Mockoon) and offline stubs",
    "security": "tenant isolation, RLS and privilege invariants against real PostgreSQL",
    "fault_injection": "deterministic failure paths: redelivery, DLQ, interruption, timeout",
    "integration": "full stack against real PostgreSQL and NATS JetStream",
    "scenarios": "the 24-scenario audit harness (offline, deterministic)",
    "e2e": "end-to-end verification against the live stack",
}

#: What the repository does NOT gate, stated so the gap is visible rather
#: than implied. These are not covered by any suite and must not be claimed.
KNOWN_UNCOVERED: tuple[str, ...] = (
    "no throughput or latency benchmark (concurrency is asserted for "
    "correctness only, never for speed)",
    "no trace-export assertion against a real OTLP collector (spans are "
    "verified in-process; the collector path is exercised only by the stack)",
    "no load test against the public API surface (the webhook is exercised "
    "at the ingestion boundary)",
    "no multi-node NATS or PostgreSQL failover (single-node services only)",
)


def _declared_markers() -> set[str]:
    """The pytest markers the project declares."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    tool = data.get("tool", {})
    pytest_section = tool.get("pytest", {})
    markers = pytest_section.get("markers")
    if markers is None:
        markers = pytest_section.get("ini_options", {}).get("markers", [])
    names: set[str] = set()
    for marker in markers:
        name = str(marker).split(":", 1)[0].strip()
        if name:
            names.add(name)
    return names


def _makefile_targets() -> set[str]:
    text = MAKEFILE.read_text(encoding="utf-8")
    return set(re.findall(r"^([a-zA-Z0-9_-]+):", text, flags=re.MULTILINE))


#: Keys that appear at the same indent level as a job but are not jobs.
NOT_A_JOB = frozenset(
    {
        "steps",
        "env",
        "permissions",
        "needs",
        "if",
        "name",
        "services",
        "container",
        "runs-on",
        "timeout-minutes",
        "outputs",
        "defaults",
        "concurrency",
        "strategy",
        "continue-on-error",
    }
)


def _workflow_suites() -> dict[str, set[str]]:
    """Map each CI job to the pytest suites it runs."""
    text = WORKFLOW.read_text(encoding="utf-8")
    jobs: dict[str, set[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        job_match = re.match(r"^  ([a-z0-9-]+):\s*$", line)
        if job_match:
            key = job_match.group(1)
            if key in NOT_A_JOB:
                continue
            current = key
            jobs.setdefault(current, set())
            continue
        if current is None:
            continue
        target = re.search(r"make (test-[a-z0-9-]+)", line)
        if target is None:
            continue
        for suite, suite_target in SUITE_TARGETS.items():
            if target.group(1) == suite_target:
                jobs[current].add(suite)
    return jobs


def main() -> int:
    declared = _declared_markers()
    targets = _makefile_targets()
    jobs = _workflow_suites()

    problems: list[str] = []

    for suite, target in sorted(SUITE_TARGETS.items()):
        if target not in targets:
            problems.append(f"the Makefile has no target {target!r} for suite {suite!r}")
    for suite in sorted(declared - set(SUITE_TARGETS)):
        problems.append(f"the declared marker {suite!r} has no suite mapping")
    for suite in sorted(set(SUITE_TARGETS) - declared):
        problems.append(f"suite {suite!r} is mapped but not declared as a pytest marker")

    covered: dict[str, list[str]] = {}
    for job, suites in sorted(jobs.items()):
        for suite in sorted(suites):
            covered.setdefault(suite, []).append(job)
    for suite in sorted(declared):
        if suite not in covered:
            problems.append(f"suite {suite!r} is not run by any CI job")

    print("CI coverage matrix")
    print("------------------")
    for suite in sorted(declared):
        runners = ", ".join(covered.get(suite, [])) or "NOT RUN BY CI"
        note = CATEGORY_NOTES.get(suite, "")
        print(f"  {suite:<16} {runners:<28} {note}")

    print()
    print("Known gaps (not gated, deliberately stated):")
    for gap in KNOWN_UNCOVERED:
        print(f"  - {gap}")

    if problems:
        print()
        print("CI COVERAGE FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print()
    print(f"CI COVERAGE OK: {len(declared)} declared suites, all run by CI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
