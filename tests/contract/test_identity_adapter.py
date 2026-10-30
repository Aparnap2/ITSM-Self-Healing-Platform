"""Contract tests for the Mockoon identity adapter (respx-mocked)."""

from __future__ import annotations

import httpx
import pytest
import respx

from itsm_agent.adapters.identity.mockoon_identity import MockoonIdentityAdapter

BASE = "http://mockoon-identity.test"


def _adapter() -> MockoonIdentityAdapter:
    return MockoonIdentityAdapter(base_url=BASE, timeout_seconds=2.0, max_retries=1)


@pytest.mark.contract
@respx.mock
async def test_verified_principal() -> None:
    respx.get(f"{BASE}/principals/alice").mock(
        return_value=httpx.Response(
            200,
            json={
                "principal_id": "alice",
                "display_name": "Alice",
                "active": True,
                "roles": ["approver"],
                "verified_at": "2026-01-01T00:00:00Z",
            },
        )
    )
    adapter = _adapter()
    result = await adapter.verify_principal("alice")
    assert result.outcome == "VERIFIED"
    assert result.identity is not None and result.identity.active
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_unknown_principal() -> None:
    respx.get(f"{BASE}/principals/ghost").mock(
        return_value=httpx.Response(200, json={"found": False})
    )
    adapter = _adapter()
    result = await adapter.verify_principal("ghost")
    assert result.outcome == "UNKNOWN_PRINCIPAL"
    assert result.identity is None
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_inactive_principal() -> None:
    respx.get(f"{BASE}/principals/bob").mock(
        return_value=httpx.Response(
            200,
            json={
                "principal_id": "bob",
                "display_name": "Bob",
                "active": False,
                "roles": [],
                "verified_at": "2026-01-01T00:00:00Z",
            },
        )
    )
    adapter = _adapter()
    result = await adapter.verify_principal("bob")
    assert result.outcome == "INACTIVE"
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_unavailable_provider_maps_to_error_outcome() -> None:
    respx.get(f"{BASE}/principals/carol").mock(
        return_value=httpx.Response(500, json={"error": "down"})
    )
    adapter = _adapter()
    result = await adapter.verify_principal("carol")
    assert result.outcome == "ERROR"
    await adapter.aclose()


pytestmark = pytest.mark.contract
