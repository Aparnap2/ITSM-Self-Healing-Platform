"""Unit tests for the staging readiness gate's verdict algebra (offline).

Marker: ``unit``. The probes themselves are live-only; what is testable
offline is the rule that decides the gate, and that rule must fail closed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "demo_readiness.py"


@pytest.fixture(scope="module")
def readiness_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_readiness_under_test", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _report(module: ModuleType, mode: str = "full") -> Any:
    return module.Readiness(commit="deadbeef", started_at="2026-01-01T00:00:00Z", mode=mode)


def test_all_pass_is_pass(readiness_module: ModuleType) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    report.add("b", "PASS", "ok")
    assert report.verdict == "PASS"


def test_any_fail_is_fail(readiness_module: ModuleType) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    report.add("b", "FAIL", "boom")
    assert report.verdict == "FAIL"


def test_not_run_never_reads_as_pass_in_the_full_gate(
    readiness_module: ModuleType,
) -> None:
    """In full mode an unrun check is not evidence of readiness."""
    report = _report(readiness_module, mode="full")
    report.add("a", "PASS", "ok")
    report.add("b", "NOT RUN", "API unreachable")
    assert report.verdict == "FAIL"


def test_smoke_mode_makes_no_qualification_claim(
    readiness_module: ModuleType,
) -> None:
    """A smoke check is not the gate, and says so in its own name."""
    report = _report(readiness_module, mode="fast")
    report.add("a", "PASS", "ok")
    report.add("b", "NOT RUN", "skipped in the fast path")
    assert report.gate == "STAGING_SMOKE"
    assert report.verdict == "PASS"
    assert report.evidence()["gate"] == "STAGING_SMOKE"


def test_full_mode_reports_the_qualification_gate_name(
    readiness_module: ModuleType,
) -> None:
    report = _report(readiness_module, mode="full")
    report.add("a", "PASS", "ok")
    assert report.gate == "STAGING_READY"
    assert report.evidence()["gate"] == "STAGING_READY"


def test_not_applicable_does_not_block_an_otherwise_passing_gate(
    readiness_module: ModuleType,
) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    report.add("b", "NOT APPLICABLE", "feature not enabled in this mode")
    assert report.verdict == "PASS"


def test_evidence_is_bound_to_the_commit_and_states_its_limits(
    readiness_module: ModuleType,
) -> None:
    report = _report(readiness_module)
    report.add("a", "PASS", "ok")
    evidence = report.evidence()

    assert evidence["gate"] == "STAGING_READY"
    assert evidence["commit"] == "deadbeef"
    assert evidence["verdict"] == "PASS"
    assert evidence["checks"] == [{"name": "a", "verdict": "PASS", "detail": "ok"}]
    limits = evidence["does_not_prove"]
    assert any("throughput" in item for item in limits)
    assert any("production readiness" in item for item in limits)


def test_http_success_predicate_is_not_any_2xx_parsing_quirk(
    readiness_module: ModuleType,
) -> None:
    assert readiness_module._is_ok(200)
    assert readiness_module._is_ok(204)
    assert not readiness_module._is_ok(301)
    assert not readiness_module._is_ok(401)
    assert not readiness_module._is_ok(500)


def test_a_failing_gate_writes_evidence_even_when_none_was_requested(
    readiness_module: ModuleType,
) -> None:
    """A gate that can fail without leaving a file cannot be investigated.

    The unexplained transient that motivated this rule printed a FAIL to the
    terminal and wrote nothing, so there was no artifact to explain it with.
    """
    target = readiness_module.evidence_target("", "FAIL", "2026-11-18T12:16:38.123456+00:00")
    assert target is not None
    assert target.parent.name == "failures"
    assert target.name == "readiness-20261118T121638Z.json"


def test_failure_evidence_never_lands_beside_passing_evidence(
    readiness_module: ModuleType,
) -> None:
    """Passes and failures must not share a directory.

    A record that mixes them lets a stray failure read as a qualification
    artifact, and lets a directory of passes hide that the gate ever failed.
    """
    passing = readiness_module.evidence_target(
        "evals/reports/staging/readiness-x.json", "PASS", "2026-11-18T12:26:19+00:00"
    )
    failing = readiness_module.evidence_target(
        "evals/reports/staging/readiness-x.json", "FAIL", "2026-11-18T12:26:19+00:00"
    )
    assert passing is not None and failing is not None
    assert passing.parent != failing.parent
    assert failing.parent.name == "failures"


def test_not_run_writes_failure_evidence_too(readiness_module: ModuleType) -> None:
    """NOT RUN is not a pass, so it is not filed with the passes either."""
    target = readiness_module.evidence_target("", "NOT RUN", "2026-11-18T12:26:19+00:00")
    assert target is not None and target.parent.name == "failures"


def test_a_passing_gate_writes_nothing_unless_asked(
    readiness_module: ModuleType,
) -> None:
    assert readiness_module.evidence_target("", "PASS", "2026-11-18T12:26:19+00:00") is None


def test_evidence_carries_diagnostics_slot(readiness_module: ModuleType) -> None:
    """The artifact must be able to explain a refusal, not only date it."""
    report = _report(readiness_module)
    report.add("oidc token accepted", "FAIL", "HTTP 403")
    report.diagnostics["auth_failure"] = {"requested_tenant": "1111...", "directory": {}}
    assert report.evidence()["diagnostics"]["auth_failure"]["requested_tenant"] == "1111..."


def test_directory_probe_never_raises_when_it_cannot_look(
    readiness_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A diagnostic that fails must not replace the failure it explains."""
    monkeypatch.delenv("ITSM_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    probe = readiness_module.directory_probe("reviewer-a")
    assert probe["available"] is False
    assert isinstance(probe["reason"], str) and probe["reason"]


async def test_jetstream_requires_the_named_durable_consumer(
    readiness_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A durable consumer with the expected name must be present."""

    class _FakeResponse:
        def __init__(self, body: dict[str, Any]) -> None:
            self.status_code = 200
            self._body = body

        def json(self) -> dict[str, Any]:
            return self._body

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse(
                {
                    "streams": 2,
                    "consumers": 1,
                    "account_details": [
                        {
                            "consumer_detail": [
                                {
                                    "config": {"durable_name": "itsm-workflow"},
                                }
                            ]
                        }
                    ],
                }
            )

    monkeypatch.setattr(readiness_module.httpx, "AsyncClient", _FakeClient)

    report = _report(readiness_module)
    await readiness_module.check_jetstream(report)

    rows = [c for c in report.checks if c.name == "nats jetstream"]
    assert len(rows) == 1
    assert rows[0].verdict == "PASS"


async def test_jetstream_rejects_an_ephemeral_consumer(
    readiness_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ephemeral consumer (no durable_name) must not satisfy the check."""

    class _FakeResponse:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {
                "streams": 2,
                "consumers": 1,
                "account_details": [
                    {
                        "consumer_detail": [
                            {"config": {}},
                        ]
                    }
                ],
            }

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(readiness_module.httpx, "AsyncClient", _FakeClient)

    report = _report(readiness_module)
    await readiness_module.check_jetstream(report)

    rows = [c for c in report.checks if c.name == "nats jetstream"]
    assert len(rows) == 1
    assert rows[0].verdict == "FAIL"
    assert "itsm-workflow" in rows[0].detail


async def test_jetstream_rejects_a_wrong_durable_name(
    readiness_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A durable consumer with a different name must not satisfy the check."""

    class _FakeResponse:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {
                "streams": 2,
                "consumers": 1,
                "account_details": [
                    {
                        "consumer_detail": [
                            {"config": {"durable_name": "wrong-name"}},
                        ]
                    }
                ],
            }

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(readiness_module.httpx, "AsyncClient", _FakeClient)

    report = _report(readiness_module)
    await readiness_module.check_jetstream(report)

    rows = [c for c in report.checks if c.name == "nats jetstream"]
    assert len(rows) == 1
    assert rows[0].verdict == "FAIL"


async def test_jetstream_fails_on_http_error(
    readiness_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An HTTP error must produce a FAIL, not an exception."""
    import httpx

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, *args: Any, **kwargs: Any) -> Any:
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(readiness_module.httpx, "AsyncClient", _FakeClient)

    report = _report(readiness_module)
    await readiness_module.check_jetstream(report)

    rows = [c for c in report.checks if c.name == "nats jetstream"]
    assert len(rows) == 1
    assert rows[0].verdict == "FAIL"


async def test_a_findings_request_failure_is_recorded_and_does_not_abort(
    readiness_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`/healthz` answering is not the same endpoint answering `/v1/findings`.

    A timeout in the findings request used to escape as an unhandled exception,
    so the run died before the report was written and left no artifact saying
    what failed.
    """
    import httpx

    async def token(_subject: str) -> str:
        return "token"

    async def times_out(_token: str | None) -> tuple[int, str]:
        raise httpx.ReadTimeout("findings request timed out")

    class _FakeResponse:
        status_code = 200
        text = ""

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(readiness_module.httpx, "AsyncClient", _FakeClient)
    monkeypatch.setattr(readiness_module, "_token", token)
    monkeypatch.setattr(readiness_module, "_findings_status", times_out)
    monkeypatch.setattr(readiness_module, "directory_probe", lambda _subject: {"member": False})

    report = _report(readiness_module)
    await readiness_module.check_authentication(report, full=True)

    rows = [c for c in report.checks if c.name == "oidc token accepted"]
    assert len(rows) == 1
    assert rows[0].verdict == "FAIL"
    assert "request failed" in rows[0].detail
    assert report.diagnostics["auth_failure"]["http_status"] is None
    assert report.verdict == "FAIL"
