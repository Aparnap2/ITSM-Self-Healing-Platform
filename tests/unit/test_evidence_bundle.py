"""Unit tests for evidence bundle generation (no I/O)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from itsm_agent.domain.models import EvidenceReference, Finding, Severity
from itsm_agent.reporting.evidence_bundle import build_evidence_bundle


def test_bundle_deterministic() -> None:
    tenant = uuid.uuid4()
    finding = Finding(
        id=uuid.uuid4(),
        tenant_id=tenant,
        finding_type="PRIVILEGE_ESCALATION",
        severity=Severity.P2,
        status="OPEN",
        title="t",
        description="d",
        detected_at=datetime.now(UTC),
        rule_version="v1",
        outcome="SUSPICIOUS",
    )
    ev = EvidenceReference(
        id=uuid.uuid4(),
        finding_id=finding.id,
        source_event_id=uuid.uuid4(),
        content_hash="a" * 64,
        trust_level="SIMULATOR_OBSERVATION",
        collected_at=datetime.now(UTC),
    )
    b1 = build_evidence_bundle(finding, [ev])
    b2 = build_evidence_bundle(finding, [ev])
    assert b1["bundle_hash"] == b2["bundle_hash"]
    assert len(b1["evidence"]) == 1
    assert "limitations" in b1


def test_bundle_empty_evidence() -> None:
    tenant = uuid.uuid4()
    finding = Finding(
        id=uuid.uuid4(),
        tenant_id=tenant,
        finding_type="X",
        severity=Severity.P3,
        status="OPEN",
        title="t",
        description="d",
        detected_at=datetime.now(UTC),
        rule_version="v1",
        outcome="INCONCLUSIVE",
    )
    b = build_evidence_bundle(finding, [])
    assert b["evidence"] == []
    assert "bundle_hash" in b
