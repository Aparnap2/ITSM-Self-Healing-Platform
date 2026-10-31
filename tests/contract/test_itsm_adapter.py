"""Contract tests for the Mockoon ITSM adapter (respx-mocked, no live HTTP)."""

from __future__ import annotations

import httpx
import pytest
import respx

from itsm_agent.adapters.http import (
    AdapterUnavailableError,
    EndpointNotAllowedError,
)
from itsm_agent.adapters.itsm.mockoon_itsm import MockoonItsMAdapter

BASE = "http://mockoon-itsm.test"


def _adapter() -> MockoonItsMAdapter:
    return MockoonItsMAdapter(base_url=BASE, timeout_seconds=2.0, max_retries=1)


@pytest.mark.contract
@respx.mock
async def test_create_ticket_returns_typed_ref() -> None:
    respx.post(f"{BASE}/tickets").mock(
        return_value=httpx.Response(200, json={"ticket_id": "TCK-1", "url": None})
    )
    adapter = _adapter()
    ref = await adapter.create_ticket(
        title="Service down",
        description="desc",
        severity="P2",
        service_name="svc-a",
        correlation_id="c-1",
    )
    assert ref.system == "mockoon-itsm"
    assert ref.ticket_id == "TCK-1"
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_get_ticket_validates_snapshot() -> None:
    respx.get(f"{BASE}/tickets/TCK-1").mock(
        return_value=httpx.Response(
            200,
            json={
                "ticket_id": "TCK-1",
                "status": "OPEN",
                "title": "Service down",
                "description": "desc",
                "updated_at": "2026-01-01T00:00:00Z",
            },
        )
    )
    adapter = _adapter()
    snap = await adapter.get_ticket("TCK-1")
    assert snap.status == "OPEN"
    assert snap.updated_at.tzinfo is not None
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_update_ticket_typed_result() -> None:
    respx.patch(f"{BASE}/tickets/TCK-1").mock(
        return_value=httpx.Response(
            200, json={"accepted": True, "result_code": "UPDATED", "summary": "ok"}
        )
    )
    from itsm_agent.ports.itsm import TicketUpdate

    adapter = _adapter()
    result = await adapter.update_ticket(
        TicketUpdate(ticket_id="TCK-1", status="RESOLVED", comment="done")
    )
    assert result.accepted is True
    assert result.result_code == "UPDATED"
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_non_allowlisted_path_rejected() -> None:
    adapter = _adapter()
    with pytest.raises(EndpointNotAllowedError):
        await adapter._http.request_json("DELETE", "/admin/wipe")
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_5xx_after_bounded_retries_raises_unavailable() -> None:
    route = respx.post(f"{BASE}/tickets").mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )
    adapter = _adapter()
    with pytest.raises(AdapterUnavailableError):
        await adapter.create_ticket(
            title="t",
            description="d",
            severity="P1",
            service_name="svc",
            correlation_id="c",
        )
    assert route.call_count == 2  # 1 initial + 1 retry (max_retries=1)
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_malformed_response_fails_closed() -> None:
    respx.get(f"{BASE}/tickets/TCK-1").mock(
        return_value=httpx.Response(200, json={"unexpected": True})
    )
    adapter = _adapter()
    from itsm_agent.adapters.http import UnexpectedResponseError

    with pytest.raises(UnexpectedResponseError):
        await adapter.get_ticket("TCK-1")
    await adapter.aclose()


pytestmark = pytest.mark.contract
