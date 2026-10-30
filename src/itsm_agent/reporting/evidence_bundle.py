"""Evidence bundle generation (Task 14). Deterministic, reproducible."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from itsm_agent.domain.models import EvidenceReference, Finding


def build_evidence_bundle(
    finding: Finding,
    evidence: list[EvidenceReference],
    review_decisions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a deterministic evidence bundle dict."""
    evidence_sorted = sorted(evidence, key=lambda e: str(e.id))
    bundle = {
        "finding": {
            "id": str(finding.id),
            "tenant_id": str(finding.tenant_id),
            "finding_type": finding.finding_type,
            "severity": str(finding.severity),
            "status": finding.status,
            "title": finding.title,
            "description": finding.description,
            "detected_at": finding.detected_at.isoformat(),
            "rule_version": finding.rule_version,
            "outcome": finding.outcome,
        },
        "evidence": [
            {
                "id": str(e.id),
                "source_event_id": str(e.source_event_id) if e.source_event_id else None,
                "access_fact_id": str(e.access_fact_id) if e.access_fact_id else None,
                "content_hash": e.content_hash,
                "excerpt": e.excerpt,
                "trust_level": e.trust_level,
                "collected_at": e.collected_at.isoformat(),
            }
            for e in evidence_sorted
        ],
        "review_decisions": review_decisions or [],
        "limitations": [
            "Evidence is limited to configured sources and retention windows.",
            "Report is evidence, not certification.",
        ],
    }
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    bundle["bundle_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    return bundle


__all__ = ["build_evidence_bundle"]
