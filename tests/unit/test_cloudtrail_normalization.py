"""Unit tests for CloudTrail normalization (no network)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from itsm_agent.collectors.aws.cloudtrail import (
    _idempotency_key,
    _parse_dt,
    normalize_record,
)

TENANT = uuid.uuid4()


def _record(**overrides: object) -> dict[str, object]:
    base = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": "arn:aws:iam::123:user/alice",
            "accountId": "123",
            "userName": "alice",
        },
        "eventTime": "2026-01-01T12:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.0",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/Admin"},
        "responseElements": {"credentials": {"accessKeyId": "AKIA..."}},
        "requestID": "req-1",
        "eventID": "evt-123",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123",
        "eventCategory": "Management",
    }
    base.update(overrides)
    return base


def test_normalize_basic() -> None:
    ev = normalize_record(_record(), TENANT)
    assert ev.tenant_id == TENANT
    assert ev.source == "cloudtrail"
    assert ev.source_event_id == "evt-123"
    assert ev.event_type == "AssumeRole"
    assert ev.event_category == "auth"
    assert ev.actor_id == "arn:aws:iam::123:user/alice"
    assert ev.principal_id == "AIDAEXAMPLE"
    assert ev.resource_id == "arn:aws:iam::123:role/Admin"
    assert ev.resource_type == "roleArn"
    assert ev.outcome == "success"
    assert ev.correlation_metadata["source_ip"] == "203.0.113.5"
    assert ev.idempotency_key == f"{TENANT}:cloudtrail:evt-123"


def test_normalize_failure_outcome() -> None:
    ev = normalize_record(_record(errorCode="AccessDenied", errorMessage="denied"), TENANT)
    assert ev.outcome == "failure"


def test_idempotency_fallback() -> None:
    rec = _record()
    del rec["eventID"]
    key = _idempotency_key(TENANT, rec)
    assert key.startswith(f"{TENANT}:cloudtrail:fallback:")
    assert "AssumeRole" in key


def test_parse_dt_z() -> None:
    dt = _parse_dt("2026-01-01T12:00:00Z")
    assert dt.tzinfo is not None
    assert dt.year == 2026


def test_payload_hash_stable() -> None:
    ev1 = normalize_record(_record(), TENANT)
    ev2 = normalize_record(_record(), TENANT)
    assert ev1.payload_hash == ev2.payload_hash


@pytest.mark.asyncio
async def test_collect_with_fake_fetcher() -> None:
    from itsm_agent.collectors.aws.cloudtrail import CloudTrailCollector

    tenant = uuid.uuid4()
    records = [_record(eventID=f"e{i}") for i in range(3)]

    async def fetcher(since: datetime) -> list[dict[str, object]]:
        return records

    collector = CloudTrailCollector(tenant_id=tenant, fetch_records=fetcher)
    events = await collector.collect(datetime.now(UTC))
    assert len(events) == 3
    assert all(e.tenant_id == tenant for e in events)


pytestmark = pytest.mark.unit
