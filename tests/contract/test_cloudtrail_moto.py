"""Contract test: CloudTrail collector against Moto S3 (no real AWS)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import boto3  # type: ignore[import-untyped]
import pytest
from moto import mock_aws

from itsm_agent.collectors.aws.cloudtrail import CloudTrailCollector


@pytest.mark.asyncio
async def test_moto_s3_roundtrip() -> None:
    tenant = uuid.uuid4()

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "ct-trail-bucket"
        s3.create_bucket(Bucket=bucket)
        record = {
            "eventVersion": "1.09",
            "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123:root", "accountId": "123"},
            "eventTime": "2026-01-01T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.1",
            "requestParameters": {"userName": "bob"},
            "responseElements": None,
            "requestID": "r1",
            "eventID": "e-moto-1",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123",
            "eventCategory": "Management",
        }
        body = json.dumps({"Records": [record]}).encode()
        s3.put_object(Bucket=bucket, Key="trail.json", Body=body)

        obj = s3.get_object(Bucket=bucket, Key="trail.json")
        body = json.loads(obj["Body"].read())
        records = body["Records"]

        async def fetcher(since: datetime) -> list[dict[str, Any]]:
            return records  # type: ignore[no-any-return]

        collector = CloudTrailCollector(tenant_id=tenant, fetch_records=fetcher)
        events = await collector.collect(datetime.now(UTC))
        assert len(events) == 1
        assert events[0].event_type == "CreateUser"
        assert events[0].tenant_id == tenant
        assert events[0].source == "cloudtrail"


pytestmark = pytest.mark.contract
