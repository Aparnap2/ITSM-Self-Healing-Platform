"""Unit tests for GitHub audit normalization (no network)."""

from __future__ import annotations

import uuid

from itsm_agent.collectors.github.audit_log import (
    _idempotency_key,
    _parse_ts,
    normalize_record,
)

TENANT = uuid.uuid4()


def _record(**overrides: object) -> dict[str, object]:
    base = {
        "_document_id": "doc-1",
        "@timestamp": 1735689600000,  # 2025-01-01T00:00:00Z
        "action": "org.add_member",
        "actor": "alice",
        "user": "bob",
        "org": "myorg",
        "created_at": "2025-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def test_normalize_basic() -> None:
    ev = normalize_record(_record(), TENANT)
    assert ev.tenant_id == TENANT
    assert ev.source == "github"
    assert ev.source_event_id == "doc-1"
    assert ev.event_type == "org.add_member"
    assert ev.actor_id == "alice"
    assert ev.resource_id == "bob"
    assert ev.idempotency_key == f"{TENANT}:github:doc-1"


def test_idempotency_fallback() -> None:
    rec = _record()
    del rec["_document_id"]
    rec.pop("id", None)
    key = _idempotency_key(TENANT, rec)
    assert key.startswith(f"{TENANT}:github:fallback:")


def test_parse_ts_epoch_millis() -> None:
    dt = _parse_ts(1735689600000)
    assert dt.tzinfo is not None
    assert dt.year == 2025


def test_payload_hash_stable() -> None:
    ev1 = normalize_record(_record(), TENANT)
    ev2 = normalize_record(_record(), TENANT)
    assert ev1.payload_hash == ev2.payload_hash
