"""Unit tests for the observability contract.

Marker: ``unit``. Three properties are pinned here:

* **Doc/code parity** — every metric the documentation lists is declared in
  code, and every metric the code declares is documented. The document used
  to advertise names that were never emitted; that drift must fail the build.
* **Bounded labels** — no metric may be labelled with an unbounded value
  (tenant, subject, finding id, token), or the exported series count grows
  without limit.
* **The helpers actually move the counters** — a declared metric that is
  never incremented is a lie.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from itsm_agent.observability.http_boundary import route_label, status_class
from itsm_agent.observability.metrics import (
    METRIC_SPECS,
    declared_metrics,
    get_metrics_registry,
    observe_api_request,
    observe_consumer_message,
    observe_detection_finding,
    observe_investigation,
    observe_model_call,
    observe_outbox_published,
    observe_reviewer_transition,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOC_PATH = REPO_ROOT / "docs" / "observability.md"

#: Label names that would make the series count unbounded.
FORBIDDEN_LABELS = frozenset(
    {
        "tenant",
        "tenant_id",
        "subject",
        "subject_id",
        "finding",
        "finding_id",
        "event_id",
        "source_event_id",
        "token",
        "secret",
        "principal",
        "principal_id",
        "reviewer",
        "reviewer_id",
    }
)

_METRIC_NAME = re.compile(r"itsm_[a-z0-9_]+")


def _documented_names() -> set[str]:
    """Metric names listed in the documentation's metric table.

    Only the first column of a table row is read, so a module path in prose
    (``src/itsm_agent/...``) is not mistaken for a metric name.
    """
    text = DOC_PATH.read_text(encoding="utf-8")
    names: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        match = re.match(r"\|\s*`(?P<name>[a-z0-9_]+)`", line)
        if match is not None:
            names.add(match.group("name"))
    return names


def test_documentation_lists_exactly_the_declared_metrics() -> None:
    documented = _documented_names()
    declared = set(declared_metrics())

    missing_from_docs = declared - documented
    not_declared = documented - declared

    assert not missing_from_docs, f"metrics declared but not documented: {missing_from_docs}"
    assert not not_declared, f"metrics documented but not declared: {not_declared}"


def test_no_metric_is_labelled_with_an_unbounded_value() -> None:
    for spec in METRIC_SPECS:
        forbidden = FORBIDDEN_LABELS & set(spec.labels)
        assert not forbidden, f"{spec.name} has unbounded label(s): {sorted(forbidden)}"


def test_every_spec_declares_a_unique_bounded_label_set() -> None:
    for spec in METRIC_SPECS:
        assert len(set(spec.labels)) == len(spec.labels), spec.name


def _value(name: str, labels: dict[str, str] | None = None) -> float:
    """Current sample value.

    The registry is process-wide, so tests compare deltas rather than
    absolutes: another suite may already have moved the same counter.
    """
    return get_metrics_registry().get_sample_value(name, labels or {}) or 0.0


def test_counters_move_when_their_helper_is_called() -> None:
    before = _value("itsm_outbox_published_total", {"outcome": "published"})

    observe_outbox_published("published")
    observe_consumer_message("processed")
    observe_detection_finding("P2")
    observe_reviewer_transition("applied")
    observe_investigation("completed")
    observe_model_call()

    assert _value("itsm_outbox_published_total", {"outcome": "published"}) == before + 1
    assert _value("itsm_consumer_messages_total", {"outcome": "processed"}) >= 1
    assert _value("itsm_detection_findings_total", {"severity": "P2"}) >= 1
    assert _value("itsm_reviewer_transitions_total", {"outcome": "applied"}) >= 1
    assert _value("itsm_investigation_total", {"outcome": "completed"}) >= 1
    assert _value("itsm_investigation_model_calls_total") >= 1


def test_api_request_metric_is_labelled_by_bounded_route() -> None:
    labels = {
        "route": route_label("GET", "/v1/findings"),
        "method": "GET",
        "status_class": status_class(200),
    }
    before = _value("itsm_api_requests_total", labels)

    observe_api_request(route_label("GET", "/v1/findings"), "GET", status_class(200), 0.01)

    assert labels["route"] == "findings_list"
    assert _value("itsm_api_requests_total", labels) == before + 1


def test_unknown_routes_collapse_to_a_single_bounded_label() -> None:
    assert route_label("GET", "/v1/anything/else/12345") == "other"
    assert route_label("PATCH", "/v1/findings") == "other"


def test_status_classes_are_bounded() -> None:
    assert status_class(200) == "2xx"
    assert status_class(404) == "4xx"
    assert status_class(503) == "5xx"
