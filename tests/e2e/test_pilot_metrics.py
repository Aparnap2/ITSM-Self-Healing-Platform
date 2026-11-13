"""Pilot measurement harness (PRD §9 success metrics).

Turns the seeded pilot scenarios into a reproducible, committed evidence
artifact: detection recall, false-positive rate, evidence preservation and
end-to-end latency for the **deterministic detection layer**.

Offline and deterministic: no network, no database, no LLM, no container.
Every number in the artifact except the wall-clock latency block is
byte-stable across runs.

The harness writes ``evals/reports/pilot-metrics.json``. Re-running it
refreshes the latency block, so the committed report legitimately shows a
diff after a local run; commit the refreshed report together with whatever
change caused it (the test fails until the report is regenerated and
committed, so a stale report can never be mistaken for a current one).

These are measurements of a simulated pilot. They are not a benchmark, not a
certification, and not a claim of production readiness.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from itsm_agent.collectors.aws.cloudtrail import normalize_record as ct_norm
from itsm_agent.collectors.github.audit_log import normalize_record as gh_norm
from itsm_agent.collectors.postgresql.pgaudit import normalize_record as pg_norm
from itsm_agent.collectors.postgresql.pgaudit import parse_pgaudit_line
from itsm_agent.detection.engine import RULE_VERSION, run_detection
from itsm_agent.domain.events import SourceEvent
from itsm_agent.domain.models import ApprovalEvidence, EvidenceReference, Finding
from itsm_agent.reporting.evidence_bundle import build_evidence_bundle

pytestmark = pytest.mark.e2e

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = REPO_ROOT / "evals" / "datasets" / "pilot_scenarios.json"
REPORT_PATH = REPO_ROOT / "evals" / "reports" / "pilot-metrics.json"

#: Date the committed measurement artifact was produced. Deliberately a
#: constant (not ``date.today()``) so the report stays byte-comparable
#: between runs; bump it when the measurements are re-taken.
MEASURED_ON = "2026-11-13"

REPRODUCE_COMMAND = "uv run pytest tests/e2e/test_pilot_metrics.py -q"

#: Envelope the pilot dataset is expected to stay inside (documented size).
MIN_SCENARIOS = 10
MAX_SCENARIOS = 16
MIN_PER_LABEL = 4


class ScenarioSpec(BaseModel):
    """One labelled pilot scenario.

    The dataset is an external input, so it is validated with a typed schema
    that rejects unknown fields (fail closed on typos in the dataset).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    label: Literal["malicious", "benign"]
    source: Literal["cloudtrail", "pgaudit", "github"]
    tenant_id: UUID
    expect_finding: bool
    expect_outcome: str | None = None
    expect_finding_type: str | None = None
    forbid_outcomes: list[str] = Field(default_factory=list)
    known_gap: bool = False
    note: str = ""
    approvals: list[ApprovalEvidence] | None = None
    covered_sources: list[str] | None = None
    event: dict[str, Any] | None = None
    log_line: str | None = None

    @field_validator("approvals", mode="before")
    @classmethod
    def _known_approval_fields(cls, value: object) -> object:
        """Reject approval records with fields the approval contract does not define."""
        if not isinstance(value, list):
            return value
        allowed = set(ApprovalEvidence.model_fields)
        for item in value:
            if isinstance(item, dict):
                unknown = sorted(set(item) - allowed)
                if unknown:
                    raise ValueError(f"unknown approval field(s): {unknown}")
        return value

    @model_validator(mode="after")
    def _payload_matches_source(self) -> ScenarioSpec:
        """Each scenario carries exactly the raw payload its source needs."""
        if self.source == "pgaudit":
            if not self.log_line:
                raise ValueError("pgaudit scenario requires 'log_line'")
            if self.event is not None:
                raise ValueError("pgaudit scenario must not carry 'event'")
        else:
            if self.event is None:
                raise ValueError(f"{self.source} scenario requires 'event'")
            if self.log_line is not None:
                raise ValueError(f"{self.source} scenario must not carry 'log_line'")
        return self


@dataclass(frozen=True)
class ScenarioResult:
    """Measured outcome of one scenario."""

    id: str
    label: str
    source: str
    known_gap: bool
    expect_finding: bool
    expect_outcome: str | None
    expect_finding_type: str | None
    finding_count: int
    finding_types: tuple[str, ...]
    finding_outcomes: tuple[str, ...]
    produced_finding: bool
    matched_expectation: bool | None
    matching_finding_count: int
    false_positive: bool
    false_negative: bool
    findings_with_evidence: int
    findings_without_evidence: int
    evidence_content_hashes: tuple[str, ...]
    forbidden_outcome_violations: tuple[str, ...]
    latency_ms: float

    def as_dict(self) -> dict[str, Any]:
        """Serialisable view (no latency: latency lives in its own block)."""
        return {
            "id": self.id,
            "label": self.label,
            "source": self.source,
            "known_gap": self.known_gap,
            "expect_finding": self.expect_finding,
            "expect_outcome": self.expect_outcome,
            "expect_finding_type": self.expect_finding_type,
            "finding_count": self.finding_count,
            "finding_types": list(self.finding_types),
            "finding_outcomes": list(self.finding_outcomes),
            "produced_finding": self.produced_finding,
            "matched_expectation": self.matched_expectation,
            "matching_finding_count": self.matching_finding_count,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "findings_with_evidence": self.findings_with_evidence,
            "findings_without_evidence": self.findings_without_evidence,
            "evidence_content_hashes": list(self.evidence_content_hashes),
            "forbidden_outcome_violations": list(self.forbidden_outcome_violations),
        }


def load_specs() -> list[ScenarioSpec]:
    """Load and validate the labelled pilot dataset."""
    raw = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{DATASET_PATH} must contain a JSON array of scenarios")
    return [ScenarioSpec.model_validate(item) for item in raw]


def _build_events(spec: ScenarioSpec) -> list[SourceEvent]:
    """Normalize a scenario's raw payload with the production collectors."""
    if spec.source == "cloudtrail":
        record = spec.event or {}
        return [ct_norm(record, spec.tenant_id)]
    if spec.source == "pgaudit":
        parsed = parse_pgaudit_line(spec.log_line or "")
        if parsed is None:
            raise ValueError(f"scenario {spec.id}: pgAudit line could not be parsed")
        return [pg_norm(parsed, spec.tenant_id)]
    return [gh_norm(spec.event or {}, spec.tenant_id)]


def _matches_expectation(finding: Finding, spec: ScenarioSpec) -> bool:
    """True when the finding satisfies every expectation the scenario declares."""
    if spec.expect_finding_type is None and spec.expect_outcome is None:
        return False
    if spec.expect_finding_type is not None and finding.finding_type != spec.expect_finding_type:
        return False
    return not (spec.expect_outcome is not None and finding.outcome != spec.expect_outcome)


def _measure(spec: ScenarioSpec) -> ScenarioResult:
    """Normalize + detect one scenario and capture its measured outcome."""
    start = time.perf_counter_ns()
    events = _build_events(spec)
    findings = run_detection(
        events,
        list(spec.approvals) if spec.approvals is not None else None,
        covered_sources=list(spec.covered_sources) if spec.covered_sources is not None else None,
    )
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000

    produced = bool(findings)
    matched: bool | None = None
    matching_count = 0
    if spec.expect_finding:
        matching_count = sum(1 for f in findings if _matches_expectation(f, spec))
        matched = matching_count > 0

    # Evidence preservation: the bundle a reviewer would receive must carry the
    # content hash of the raw source record that produced the finding.
    source_hashes = {ev.payload_hash for ev in events}
    with_evidence = 0
    for finding in findings:
        references = [
            EvidenceReference(
                id=uuid4(),
                finding_id=finding.id,
                source_event_id=ev.event_id,
                content_hash=ev.payload_hash,
                trust_level="SIMULATOR_OBSERVATION",
                collected_at=ev.observed_at,
            )
            for ev in events
        ]
        bundle = build_evidence_bundle(finding, references)
        entries = bundle["evidence"]
        bundle_hashes: set[str] = set()
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    value = entry.get("content_hash")
                    if isinstance(value, str):
                        bundle_hashes.add(value)
        if bundle_hashes == source_hashes:
            with_evidence += 1

    violations = tuple(sorted({f.outcome for f in findings if f.outcome in spec.forbid_outcomes}))
    is_benign = spec.label == "benign"

    return ScenarioResult(
        id=spec.id,
        label=spec.label,
        source=spec.source,
        known_gap=spec.known_gap,
        expect_finding=spec.expect_finding,
        expect_outcome=spec.expect_outcome,
        expect_finding_type=spec.expect_finding_type,
        finding_count=len(findings),
        finding_types=tuple(sorted(f.finding_type for f in findings)),
        finding_outcomes=tuple(sorted(f.outcome for f in findings)),
        produced_finding=produced,
        matched_expectation=matched,
        matching_finding_count=matching_count,
        false_positive=is_benign and produced,
        false_negative=(not is_benign) and matched is False,
        findings_with_evidence=with_evidence,
        findings_without_evidence=len(findings) - with_evidence,
        evidence_content_hashes=tuple(sorted(source_hashes)),
        forbidden_outcome_violations=violations,
        latency_ms=latency_ms,
    )


def _percentile(values: list[float], quantile: float) -> float:
    """Linear-interpolation percentile over a non-empty sample."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 4)
    position = quantile * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return round(ordered[int(position)], 4)
    weight = position - low
    return round(ordered[low] + (ordered[high] - ordered[low]) * weight, 4)


def _compute() -> tuple[dict[str, Any], dict[str, Any]]:
    """Measure the whole dataset. Returns (deterministic metrics, latency block)."""
    specs = load_specs()
    # One warm-up pass over the same data precedes the measured pass so that
    # one-off first-call costs (for example regex compilation in the pgAudit
    # parser) are not attributed to scenario latency.
    for spec in specs:
        _measure(spec)
    results = sorted((_measure(spec) for spec in specs), key=lambda r: r.id)

    malicious = [r for r in results if r.label == "malicious"]
    benign = [r for r in results if r.label == "benign"]
    true_positives = sum(1 for r in malicious if r.matched_expectation)
    false_negatives = sum(1 for r in malicious if r.matched_expectation is False)
    false_positives = sum(1 for r in benign if r.produced_finding)
    true_negatives = len(benign) - false_positives
    supported = [r for r in malicious if not r.known_gap]
    supported_hits = sum(1 for r in supported if r.matched_expectation)

    total_findings = sum(r.finding_count for r in results)
    findings_with_evidence = sum(r.findings_with_evidence for r in results)
    findings_without_evidence = sum(r.findings_without_evidence for r in results)
    malicious_findings = sum(r.finding_count for r in malicious)
    matching_findings = sum(r.matching_finding_count for r in malicious)

    false_positive_by_type: dict[str, int] = {}
    for row in results:
        if row.label == "benign" and row.produced_finding:
            for finding_type in row.finding_types:
                false_positive_by_type[finding_type] = (
                    false_positive_by_type.get(finding_type, 0) + 1
                )

    metrics: dict[str, Any] = {
        "scenario_count": len(results),
        "benign_scenario_count": len(benign),
        "malicious_scenario_count": len(malicious),
        "known_gap_scenario_count": sum(1 for r in results if r.known_gap),
        "detection": {
            "true_positive_scenarios": true_positives,
            "false_negative_scenarios": false_negatives,
            "false_positive_scenarios": false_positives,
            "true_negative_scenarios": true_negatives,
            "recall": round(true_positives / len(malicious), 4) if malicious else 0.0,
            "recall_supported_rules": (
                round(supported_hits / len(supported), 4) if supported else 0.0
            ),
            "false_positive_rate": (round(false_positives / len(benign), 4) if benign else 0.0),
            "precision": (
                round(true_positives / (true_positives + false_positives), 4)
                if (true_positives + false_positives)
                else 0.0
            ),
        },
        "findings": {
            "total_findings": total_findings,
            "findings_on_malicious_scenarios": malicious_findings,
            "findings_matching_expectation": matching_findings,
            "matched_finding_ratio": (
                round(matching_findings / malicious_findings, 4) if malicious_findings else 0.0
            ),
            "findings_with_evidence": findings_with_evidence,
            "findings_without_evidence": findings_without_evidence,
            "evidence_preservation_ratio": (
                round(findings_with_evidence / total_findings, 4) if total_findings else 0.0
            ),
        },
        "false_positive_breakdown_by_finding_type": dict(sorted(false_positive_by_type.items())),
        "scenarios": [r.as_dict() for r in results],
    }

    latencies = [r.latency_ms for r in results]
    latency: dict[str, Any] = {
        "unit": "milliseconds",
        "measurement": "monotonic clock (time.perf_counter_ns) around normalize + detect",
        "warm_up_pass": (
            "one unmeasured pass over the same dataset precedes the measured pass so that "
            "one-off first-call costs are not attributed to scenario latency"
        ),
        "scenario_count": len(latencies),
        "min_ms": round(min(latencies), 4) if latencies else 0.0,
        "p50_ms": _percentile(latencies, 0.50),
        "p95_ms": _percentile(latencies, 0.95),
        "max_ms": round(max(latencies), 4) if latencies else 0.0,
        "mean_ms": round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
        "per_scenario_ms": {r.id: round(r.latency_ms, 4) for r in results},
    }
    return metrics, latency


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_artifact(metrics: dict[str, Any], latency: dict[str, Any]) -> dict[str, Any]:
    """Assemble the committed evidence artifact (no run-varying timestamps)."""
    return {
        "artifact_version": "1.0",
        "measured_on": MEASURED_ON,
        "dataset": {
            "path": "evals/datasets/pilot_scenarios.json",
            "sha256": _sha256(DATASET_PATH),
            "scenario_count": metrics["scenario_count"],
        },
        "rule_version": RULE_VERSION,
        "method": {
            "layer_measured": "deterministic detection layer (itsm_agent.detection.engine)",
            "scenario_source": "hand-labelled simulated pilot dataset (no production data)",
            "detected_definition": (
                "a malicious scenario counts as detected when the engine produces at least "
                "one finding whose finding_type and outcome satisfy the scenario's "
                "expect_finding_type and expect_outcome"
            ),
            "false_positive_definition": (
                "a benign scenario counts as a false positive when the engine produces any "
                "finding at all"
            ),
            "recall_definition": "detected malicious scenarios / all labelled malicious scenarios",
            "recall_supported_rules_definition": (
                "detected malicious scenarios / malicious scenarios that the current rule set "
                "claims to support (scenarios flagged known_gap are excluded)"
            ),
            "false_positive_rate_definition": (
                "benign scenarios producing any finding / all labelled benign scenarios"
            ),
            "evidence_preservation_definition": (
                "a finding preserves evidence when the evidence bundle built for it carries "
                "the content hash of the raw source record that produced it"
            ),
            "matched_finding_ratio_definition": (
                "share of the findings raised on malicious scenarios that match the scenario's "
                "expected finding type and outcome; the remainder are extra findings the engine "
                "raised alongside the expected one (for example the generic escalation heuristic "
                "in addition to the specific approval finding)"
            ),
            "latency_measurement": (
                "monotonic clock (time.perf_counter_ns) around normalize + detect, per scenario; "
                "one unmeasured warm-up pass over the same dataset precedes the measured pass"
            ),
            "reproduce_command": REPRODUCE_COMMAND,
            "environment": {
                "network": "not used",
                "database": "not used",
                "llm": "not used",
                "data": "simulated only",
            },
        },
        "metrics": metrics,
        "latency": latency,
        "limitations": [
            "Simulated sources only: no real tenant, no production telemetry.",
            "Small labelled dataset: these rates are not statistically meaningful benchmarks.",
            "Measures the deterministic detection layer only; the agentic investigation layer "
            "is not exercised by these numbers.",
            "Not a certification and not a production-readiness claim.",
            "No real approval, identity or ITSM system was consulted.",
        ],
    }


def _read_artifact() -> dict[str, Any] | None:
    if not REPORT_PATH.exists():
        return None
    raw = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None
    return raw


def test_pilot_dataset_is_well_formed() -> None:
    """The labeled dataset satisfies the documented pilot envelope."""
    specs = load_specs()
    ids = [spec.id for spec in specs]
    assert len(ids) == len(set(ids)), "scenario ids must be unique"
    assert MIN_SCENARIOS <= len(specs) <= MAX_SCENARIOS, (
        f"pilot dataset holds {len(specs)} scenarios, expected {MIN_SCENARIOS}-{MAX_SCENARIOS}"
    )
    benign = [s for s in specs if s.label == "benign"]
    malicious = [s for s in specs if s.label == "malicious"]
    assert len(benign) >= MIN_PER_LABEL
    assert len(malicious) >= MIN_PER_LABEL
    for spec in specs:
        if spec.label == "benign":
            assert spec.expect_finding is False
            assert spec.expect_outcome is None
        else:
            assert spec.expect_finding is True
        if spec.known_gap:
            assert spec.label == "malicious"


def test_pilot_metrics_are_internally_consistent() -> None:
    """Measure the pilot, check the numbers agree, and publish the artifact."""
    metrics, latency = _compute()

    rows = metrics["scenarios"]
    detection = metrics["detection"]
    findings = metrics["findings"]

    assert len(rows) == metrics["scenario_count"]
    assert metrics["benign_scenario_count"] + metrics["malicious_scenario_count"] == len(rows)

    table_tp = sum(1 for r in rows if r["label"] == "malicious" and r["matched_expectation"])
    table_fp = sum(1 for r in rows if r["label"] == "benign" and r["produced_finding"])
    assert table_tp == detection["true_positive_scenarios"]
    assert table_fp == detection["false_positive_scenarios"]
    assert (
        detection["true_positive_scenarios"] + detection["false_negative_scenarios"]
        == metrics["malicious_scenario_count"]
    )
    assert (
        detection["false_positive_scenarios"] + detection["true_negative_scenarios"]
        == metrics["benign_scenario_count"]
    )
    assert detection["recall"] == pytest.approx(
        table_tp / metrics["malicious_scenario_count"], abs=1e-4
    )
    assert detection["false_positive_rate"] == pytest.approx(
        table_fp / metrics["benign_scenario_count"], abs=1e-4
    )
    assert detection["precision"] == pytest.approx(table_tp / (table_tp + table_fp), abs=1e-4)

    for row in rows:
        assert row["produced_finding"] == (row["finding_count"] > 0)
        assert row["false_positive"] == (row["label"] == "benign" and row["produced_finding"])
        assert row["false_negative"] == (
            row["label"] == "malicious" and row["matched_expectation"] is False
        )
        assert (
            row["findings_with_evidence"] + row["findings_without_evidence"] == row["finding_count"]
        )
        # Fail-closed invariant: a scenario that forbids an outcome must never
        # produce it.
        assert row["forbidden_outcome_violations"] == []
        if row["label"] == "malicious":
            if row["known_gap"]:
                assert row["matched_expectation"] is False, (
                    f"{row['id']} is declared a known gap but is now detected; "
                    "re-label the scenario and refresh the dataset"
                )
            else:
                assert row["matched_expectation"] is True, (
                    f"{row['id']} is labelled malicious and supported by the rule set "
                    "but produced no matching finding"
                )

    assert (
        findings["findings_with_evidence"] + findings["findings_without_evidence"]
        == (findings["total_findings"])
    )
    assert findings["evidence_preservation_ratio"] == pytest.approx(
        findings["findings_with_evidence"] / findings["total_findings"], abs=1e-4
    )

    assert latency["scenario_count"] == metrics["scenario_count"]
    assert latency["min_ms"] <= latency["p50_ms"] <= latency["p95_ms"] <= latency["max_ms"]
    assert len(latency["per_scenario_ms"]) == metrics["scenario_count"]

    artifact = _build_artifact(metrics, latency)
    previous = _read_artifact()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(artifact, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    if previous is not None:
        assert previous.get("metrics") == metrics, (
            "pilot detection metrics changed since the committed report "
            f"({REPORT_PATH}). The report was regenerated; review the diff, update "
            "docs/pilot.md with the new numbers and commit both."
        )


def test_pilot_metrics_are_stable_across_runs() -> None:
    """Two consecutive computations of the same dataset must agree exactly."""
    first, _ = _compute()
    second, _ = _compute()
    assert first == second
