"""Contract: Mockoon endpoints must cover every adapter-allowlisted path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from itsm_agent.adapters.identity.mockoon_identity import _ALLOWED_PATHS as IDENTITY_PATHS
from itsm_agent.adapters.infrastructure.mockoon_infra import (
    _ACTION_PATHS as INFRA_ACTION_PATHS,
)
from itsm_agent.adapters.infrastructure.mockoon_infra import (
    _STATE_PATHS as INFRA_STATE_PATHS,
)
from itsm_agent.adapters.itsm.mockoon_itsm import _ALLOWED_PATHS as ITSM_PATHS

MOCKOON = Path("simulators/mockoon/mockoon.json")


def _normalize(path: str) -> str:
    # Adapter style "/tickets/{id}" -> Mockoon style "tickets/:ticketId"? We compare
    # the static segments only by stripping brace/colon params.
    parts = []
    for seg in path.strip("/").split("/"):
        if seg.startswith("{") and seg.endswith("}") or seg.startswith(":"):
            parts.append(":param")
        else:
            parts.append(seg)
    return "/".join(parts)


def _mockoon_endpoints() -> set[str]:
    data = json.loads(MOCKOON.read_text())
    out: set[str] = set()
    for route in data.get("routes", []):
        out.add(_normalize("/" + route["endpoint"]))
    return out


@pytest.mark.contract
def test_mockoon_covers_adapter_paths() -> None:
    adapter_paths: set[str] = set()
    for p in ITSM_PATHS:
        adapter_paths.add(_normalize(p))
    for p in IDENTITY_PATHS:
        adapter_paths.add(_normalize(p))
    for p in INFRA_ACTION_PATHS:
        adapter_paths.add(_normalize(p))
    for p in INFRA_STATE_PATHS:
        adapter_paths.add(_normalize(p))

    mockoon = _mockoon_endpoints()
    missing = adapter_paths - mockoon
    assert not missing, f"Mockoon missing adapter paths: {sorted(missing)}"


@pytest.mark.contract
def test_mockoon_file_exists() -> None:
    assert MOCKOON.is_file()


pytestmark = pytest.mark.contract
