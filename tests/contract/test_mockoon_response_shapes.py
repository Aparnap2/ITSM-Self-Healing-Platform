"""Contract: Mockoon response bodies must match adapter schemas."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from itsm_agent.ports.identity import PrincipalIdentity
from itsm_agent.ports.infrastructure import ActionResult, VerifiedState
from itsm_agent.ports.itsm import TicketRef, TicketSnapshot

MOCKOON = Path("simulators/mockoon/mockoon.json")


def _resolve_templates(body: str) -> str:
    # Replace Mockoon templates with concrete sample values.
    body = body.replace("{{uuid}}", "11111111-2222-3333-4444-555555555555")
    body = re.sub(r"\{\{urlParam '(\w+)'\}\}", r"sample-\1", body)
    body = re.sub(r"\{\{body '(\w+)'\}\}", r"sample-\1", body)
    return body


def _first_200(route: dict[str, Any]) -> dict[str, Any] | None:
    for resp in route.get("responses", []):
        if 200 <= int(resp.get("statusCode", 0)) < 300:
            try:
                result = json.loads(_resolve_templates(resp["body"]))
                if isinstance(result, dict):
                    return result
                return None
            except (json.JSONDecodeError, KeyError, TypeError):
                return None
    return None


@pytest.mark.contract
def test_mockoon_ticket_create_shape() -> None:
    data = json.loads(MOCKOON.read_text())
    route = next(r for r in data["routes"] if r["endpoint"] == "tickets" and r["method"] == "post")
    body = _first_200(route)
    assert body is not None
    ref = TicketRef(system="mockoon-itsm", ticket_id=body["ticket_id"], url=body.get("url"))
    assert ref.ticket_id


@pytest.mark.contract
def test_mockoon_ticket_snapshot_shape() -> None:
    data = json.loads(MOCKOON.read_text())
    route = next(
        r for r in data["routes"] if r["endpoint"] == "tickets/:ticketId" and r["method"] == "get"
    )
    body = _first_200(route)
    assert body is not None
    snap = TicketSnapshot.model_validate(body)
    assert snap.ticket_id


@pytest.mark.contract
def test_mockoon_principal_shape() -> None:
    data = json.loads(MOCKOON.read_text())
    route = next(
        r
        for r in data["routes"]
        if r["endpoint"] == "principals/principal-sim-001" and r["method"] == "get"
    )
    body = _first_200(route)
    assert body is not None
    ident = PrincipalIdentity.model_validate(body)
    assert ident.principal_id


@pytest.mark.contract
def test_mockoon_verified_state_shape() -> None:
    data = json.loads(MOCKOON.read_text())
    route = next(
        r for r in data["routes"] if r["endpoint"] == "state/:serviceId" and r["method"] == "get"
    )
    body = _first_200(route)
    assert body is not None
    state = VerifiedState.model_validate(body)
    assert state.service_name


@pytest.mark.contract
def test_mockoon_action_result_shape() -> None:
    data = json.loads(MOCKOON.read_text())
    route = next(
        r
        for r in data["routes"]
        if r["endpoint"] == "actions/restart_service" and r["method"] == "post"
    )
    body = _first_200(route)
    assert body is not None
    result = ActionResult.model_validate(body)
    assert result.status


@pytest.mark.contract
def test_mockoon_missing_field_fails_validation() -> None:
    # TicketSnapshot requires ticket_id, status, title, description, updated_at
    incomplete = {"ticket_id": "t1", "status": "OPEN"}
    with pytest.raises(ValidationError):
        TicketSnapshot.model_validate(incomplete)


@pytest.mark.contract
def test_mockoon_wrong_type_fails_validation() -> None:
    bad = {
        "ticket_id": "t1",
        "status": "OPEN",
        "title": "x",
        "description": "d",
        "updated_at": "not-a-date",
    }
    with pytest.raises(ValidationError):
        TicketSnapshot.model_validate(bad)


pytestmark = pytest.mark.contract
