"""HTTP boundary instrumentation: bounded route labels and status outcomes.

The API is the only HTTP surface in the platform, so the route vocabulary and
the outcome vocabulary live here. Both are **closed sets**: a request can only
ever produce one of the values declared in this module, which is what keeps
the exported metric series bounded.

Nothing here ever puts a tenant id, a reviewer id, a subject, a finding id or
a correlation id into a metric label.
"""

from __future__ import annotations

from collections.abc import Mapping

#: Placeholder for one path segment that carries an opaque identifier.
_ID_SEGMENT = "{id}"

#: Route label used for anything that does not match a known template.
OTHER_ROUTE = "other"

#: ``(method, path segments) -> route label``. The order matters: the more
#: specific templates are listed first.
_ROUTE_TEMPLATES: Mapping[tuple[str, tuple[str, ...]], str] = {
    ("POST", ("v1", "incidents", "webhook")): "ingestion_webhook",
    ("GET", ("v1", "findings")): "findings_list",
    ("GET", ("v1", "findings", _ID_SEGMENT, "decisions")): "finding_decisions",
    ("POST", ("v1", "findings", _ID_SEGMENT, "decisions")): "finding_decision",
    ("POST", ("v1", "findings", _ID_SEGMENT, "transition")): "finding_transition",
    ("GET", ("v1", "findings", _ID_SEGMENT, "transitions")): "finding_transitions",
    ("GET", ("v1", "findings", _ID_SEGMENT, "bundle")): "finding_bundle",
    ("GET", ("v1", "findings", _ID_SEGMENT)): "finding_detail",
    ("GET", ("healthz",)): "healthz",
    ("GET", ("metrics",)): "metrics",
}

#: Route label of the signed ingestion webhook.
INGESTION_ROUTE = "ingestion_webhook"

#: Route label of the reviewer lifecycle transition endpoint.
TRANSITION_ROUTE = "finding_transition"


def _segments(path: str) -> tuple[str, ...]:
    return tuple(part for part in path.split("/") if part)


def route_label(method: str, path: str) -> str:
    """Map a request to a bounded route label.

    Unknown methods and unknown paths collapse to ``"other"`` so a new route
    can never widen the exported label space without an explicit decision.
    """
    segments = _segments(path)
    for (template_method, template_segments), label in _ROUTE_TEMPLATES.items():
        if template_method != method or len(template_segments) != len(segments):
            continue
        if all(
            expected in (actual, _ID_SEGMENT)
            for expected, actual in zip(template_segments, segments, strict=True)
        ):
            return label
    return OTHER_ROUTE


def status_class(status_code: int) -> str:
    """Map an HTTP status code to a bounded status class."""
    if 100 <= status_code < 200:
        return "1xx"
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "other"


def ingestion_outcome(status_code: int) -> str:
    """Map the ingestion webhook response to a bounded outcome.

    The webhook answers ``202`` when the event was durably accepted, ``200``
    for a deduplicated replay, ``503`` when durable acceptance failed, a
    ``4xx`` for a rejected request and ``5xx`` for a server-side failure.
    """
    if status_code == 202:
        return "accepted"
    if status_code == 200:
        return "duplicate"
    if status_code == 503:
        return "unavailable"
    if 400 <= status_code < 500:
        return "rejected"
    if status_code >= 500:
        return "error"
    return "other"


def transition_outcome(status_code: int) -> str:
    """Map the reviewer transition response to a bounded outcome.

    ``200`` means the lifecycle transition was applied, ``409`` means the
    domain refused it (invalid transition, or a verifier that is not
    independent), a ``4xx`` means the request was rejected before any write.
    """
    if status_code == 200:
        return "applied"
    if status_code == 409:
        return "refused"
    if 400 <= status_code < 500:
        return "rejected"
    if status_code >= 500:
        return "error"
    return "other"


__all__ = [
    "INGESTION_ROUTE",
    "OTHER_ROUTE",
    "TRANSITION_ROUTE",
    "ingestion_outcome",
    "route_label",
    "status_class",
    "transition_outcome",
]
