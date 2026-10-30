"""Contract test: GitHub audit fetcher via respx (no real network)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from itsm_agent.collectors.github.audit_log import fetch_github_audit_log


@pytest.mark.asyncio
async def test_fetch_pagination_and_rate_limit() -> None:
    org = "myorg"
    token = "tok"
    since = datetime(2025, 1, 1, tzinfo=UTC)
    page1 = [
        {
            "_document_id": "d1",
            "action": "org.add_member",
            "actor": "alice",
            "@timestamp": 1735689600000,
        }
    ]
    page2 = [
        {"_document_id": "d2", "action": "repo.create", "actor": "bob", "@timestamp": 1735689600000}
    ]

    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"https://api.github.com/orgs/{org}/audit-log").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=page1,
                    headers={
                        "Link": '<https://api.github.com/orgs/myorg/audit-log?page=2>; rel="next"'
                    },
                ),
                httpx.Response(200, json=page2, headers={"Link": ""}),
            ]
        )
        records = await fetch_github_audit_log(org, token, since)
    assert len(records) == 2
    assert records[0]["_document_id"] == "d1"
    assert records[1]["_document_id"] == "d2"


@pytest.mark.asyncio
async def test_rate_limit_stops() -> None:
    org = "myorg"
    token = "tok"
    since = datetime(2025, 1, 1, tzinfo=UTC)
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"https://api.github.com/orgs/{org}/audit-log").mock(
            return_value=httpx.Response(429, json=[])
        )
        records = await fetch_github_audit_log(org, token, since)
    assert records == []
