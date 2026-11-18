"""Unit tests for the manual staging rehearsal runner.

Marker: ``unit``. **No network access and no real model call.** The runner is
a manual operator tool; these tests pin the two properties that matter
without a deployment:

* the preflight fails closed, names exactly what is missing, exits ``2`` and
  touches neither the network nor the database;
* the hard cap on real model calls is honoured, and a model failure is dumped
  for offline debugging instead of being retried.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from itsm_agent.domain.events import InvestigationProposal, InvestigationRequest
from itsm_agent.investigations.groq_model import (
    InvestigationModelOutputInvalidError,
    InvestigationModelUnavailableError,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "e2e_staging_run.py"


def _load_runner() -> ModuleType:
    """Import the operator tool by path (it lives outside the package)."""
    spec = importlib.util.spec_from_file_location("itsm_e2e_staging_run", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()

FULL_ENV: dict[str, str] = {
    "ITSM_POSTGRES_DSN": "postgresql://itsm_app@db/itsm",
    "ITSM_NATS_URL": "nats://nats:4222",
    "ITSM_WEBHOOK_SECRET": "webhook-secret-value-0123456789",
    "ITSM_AUTH_HMAC_SECRET": "reviewer-secret-value-0123456789",
    "ITSM_GROQ_API_KEY": "gsk-not-a-real-key",
}


def _env(**overrides: str) -> dict[str, str]:
    env = dict(FULL_ENV)
    env.update(overrides)
    return env


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any socket connection an immediate, loud failure."""

    def _blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the preflight path must not touch the network")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def test_preflight_accepts_a_complete_environment() -> None:
    assert runner.missing_requirements(FULL_ENV) == []


@pytest.mark.parametrize(
    ("variable", "label"),
    [
        ("ITSM_POSTGRES_DSN", "database DSN"),
        ("ITSM_NATS_URL", "NATS URL"),
        ("ITSM_WEBHOOK_SECRET", "webhook signing secret"),
        ("ITSM_GROQ_API_KEY", "Groq API key"),
    ],
)
def test_preflight_names_each_missing_requirement(variable: str, label: str) -> None:
    env = _env()
    env.pop(variable)

    missing = runner.missing_requirements(env)

    assert len(missing) == 1
    assert label in missing[0]
    assert variable in missing[0]


def test_preflight_accepts_the_documented_dsn_and_nats_fallbacks() -> None:
    env = _env()
    env.pop("ITSM_POSTGRES_DSN")
    env.pop("ITSM_NATS_URL")
    env["DATABASE_URL"] = "postgresql://fallback@db/itsm"
    env["NATS_URL"] = "nats://fallback:4222"

    assert runner.missing_requirements(env) == []


def test_preflight_rejects_a_short_reviewer_secret() -> None:
    env = _env(ITSM_AUTH_HMAC_SECRET="too-short")

    missing = runner.missing_requirements(env)

    assert len(missing) == 1
    assert "at least 16 characters" in missing[0]


@pytest.mark.parametrize(
    "variable",
    [
        "ITSM_POSTGRES_DSN",
        "ITSM_NATS_URL",
        "ITSM_WEBHOOK_SECRET",
        "ITSM_AUTH_HMAC_SECRET",
        "ITSM_GROQ_API_KEY",
    ],
)
def test_main_exits_two_and_touches_no_network_when_a_requirement_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    no_network: None,
    variable: str,
) -> None:
    for key, value in FULL_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(variable, raising=False)
    if variable == "ITSM_POSTGRES_DSN":
        monkeypatch.delenv("DATABASE_URL", raising=False)
    if variable == "ITSM_NATS_URL":
        monkeypatch.delenv("NATS_URL", raising=False)

    async def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the run must not start when the preflight failed")

    monkeypatch.setattr(runner, "run_staging", forbidden)

    assert runner.main([]) == 2

    captured = capsys.readouterr()
    assert variable in captured.err
    assert "preflight FAILED" in captured.err


def test_main_exits_two_without_touching_the_network_when_nothing_is_configured(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    no_network: None,
) -> None:
    for key in list(FULL_ENV) + ["DATABASE_URL", "NATS_URL"]:
        monkeypatch.delenv(key, raising=False)

    async def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the run must not start when the preflight failed")

    monkeypatch.setattr(runner, "run_staging", forbidden)

    assert runner.main([]) == 2

    captured = capsys.readouterr()
    for label in (
        "database DSN",
        "NATS URL",
        "webhook signing secret",
        "Groq API key",
        "reviewer credential",
    ):
        assert label in captured.err


# ---------------------------------------------------------------------------
# The LLM budget
# ---------------------------------------------------------------------------


class _FakeInner:
    """Stand-in for the Groq adapter. Never touches the network."""

    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0
        self.model_name = "fake-model"
        self.last_raw_payload: dict[str, Any] | None = None

    async def investigate(
        self, request: InvestigationRequest, evidence: dict[uuid.UUID, str]
    ) -> InvestigationProposal:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return InvestigationProposal(
            investigation_id=request.investigation_id,
            hypothesis="h",
            supporting_evidence=[],
            contradicting_evidence=[],
            missing_evidence=[],
            uncertainty="low",
            recommended_disposition="DISMISS",
            model_version="fake-model",
            prompt_version="investigation-v1",
        )


def _request() -> InvestigationRequest:
    return InvestigationRequest(
        investigation_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        evidence_snapshot_ids=[],
        question="q",
        max_tool_calls=5,
        max_model_calls=2,
        deadline_seconds=60.0,
    )


def test_default_budget_constant_is_three() -> None:
    assert runner.DEFAULT_LLM_BUDGET_CALLS == 3


async def test_the_budget_is_honoured(tmp_path: Path) -> None:
    inner = _FakeInner()
    budgeted = runner.BudgetedInvestigationModel(inner=inner, budget=3, debug_dir=tmp_path)

    for _ in range(3):
        await budgeted.investigate(_request(), {})

    assert budgeted.calls_used == 3
    assert inner.calls == 3

    with pytest.raises(runner.LlmBudgetExceeded):
        await budgeted.investigate(_request(), {})

    # The refused call never reached the model.
    assert inner.calls == 3


async def test_a_model_failure_dumps_the_raw_response_and_does_not_retry(
    tmp_path: Path,
) -> None:
    inner = _FakeInner(error=InvestigationModelUnavailableError("endpoint unreachable"))
    inner.last_raw_payload = {"choices": [{"message": {"content": "{}"}}]}
    budgeted = runner.BudgetedInvestigationModel(inner=inner, budget=3, debug_dir=tmp_path)

    with pytest.raises(InvestigationModelUnavailableError):
        await budgeted.investigate(_request(), {})

    assert inner.calls == 1
    assert budgeted.failure is not None
    assert budgeted.debug_path is not None
    assert budgeted.debug_path.parent == tmp_path
    assert budgeted.debug_path.name.startswith("llm_debug_")
    dumped = json.loads(budgeted.debug_path.read_text(encoding="utf-8"))
    assert dumped["error_type"] == "InvestigationModelUnavailableError"
    assert dumped["raw_response"] == inner.last_raw_payload


async def test_an_invalid_model_output_is_also_dumped(tmp_path: Path) -> None:
    inner = _FakeInner(error=InvestigationModelOutputInvalidError("not json"))
    budgeted = runner.BudgetedInvestigationModel(inner=inner, budget=3, debug_dir=tmp_path)

    with pytest.raises(InvestigationModelOutputInvalidError):
        await budgeted.investigate(_request(), {})

    assert budgeted.debug_path is not None
    assert budgeted.debug_path.exists()


# ---------------------------------------------------------------------------
# The report states what the run does and does not prove.
# ---------------------------------------------------------------------------


def test_report_states_that_the_proposal_is_advisory() -> None:
    from itsm_agent.domain.models import Finding, Severity

    finding = Finding(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        finding_type="PRIVILEGE_ESCALATION",
        severity=Severity.P2,
        status="OPEN",
        title="t",
        description="d",
        detected_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        rule_version="detection-rules-v2",
        risk_score=70,
        outcome="SUSPICIOUS",
    )
    options = runner.StagingOptions(
        env=_env(), api_base_url="http://127.0.0.1:8000", report_path=Path("/tmp/report.json")
    )
    report = runner._build_report(  # noqa: SLF001 - report contract
        options=options,
        log=runner.RunLog(),
        started_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        record=runner.malicious_cloudtrail_record(),
        source_event_id=uuid.uuid4(),
        ingest_outcome="ACCEPTED",
        webhook_result={"status_code": 202, "body": "{}"},
        finding=finding,
        status_before_investigation="OPEN",
        status_after_investigation="OPEN",
        investigation_status="COMPLETED",
        proposal=None,
        model_calls_used=1,
        llm_budget_calls=3,
        bundle={},
        bundle_error="",
        model_failure=None,
        debug_path=None,
    )

    statements = report["statements"]
    assert "ADVISORY" in statements["proposal_is_advisory"]
    assert statements["finding_status_unchanged_by_model"] is True
    assert statements["model_calls_used"] == 1
    assert statements["what_this_run_does_not_prove"]
    assert any("simulated" in item for item in statements["what_this_run_does_not_prove"])


def test_malicious_record_is_an_assume_role_to_admin() -> None:
    record = runner.malicious_cloudtrail_record()
    assert record["eventName"] == "AssumeRole"
    assert record["requestParameters"]["roleArn"].endswith("/Admin")
    assert record["eventSource"] == "sts.amazonaws.com"


def test_required_environments_cover_every_documented_variable() -> None:
    required: Mapping[str, tuple[str, ...]] = runner.REQUIRED_ENVIRONMENTS
    names = {name for names in required.values() for name in names}
    assert names == {
        "ITSM_POSTGRES_DSN",
        "DATABASE_URL",
        "ITSM_NATS_URL",
        "NATS_URL",
        "ITSM_WEBHOOK_SECRET",
        "ITSM_GROQ_API_KEY",
    }
    # The reviewer credential is a MODE, not a single mandatory variable: an
    # OIDC deployment must not be told to set an HMAC secret.
    assert "ITSM_AUTH_HMAC_SECRET" not in names


# ---------------------------------------------------------------------------
# Credential modes (the rehearsal authenticates the way the deployment does)
# ---------------------------------------------------------------------------


def test_oidc_mode_is_preferred_over_the_local_hmac_bearer() -> None:
    env = _env(
        ITSM_IDENTITY_BASE_URL="https://127.0.0.1:8443",
        ITSM_IDENTITY_CA_FILE="/tmp/simulator-ca.pem",
        ITSM_REVIEWER_SUBJECT_A="reviewer-a",
        ITSM_REVIEWER_SUBJECT_B="reviewer-b",
    )
    assert runner.credential_mode(env) == runner.CREDENTIAL_MODE_OIDC
    assert runner.missing_requirements(env) == []


def test_an_explicit_token_selects_the_token_mode() -> None:
    env = _env(ITSM_REVIEWER_TOKEN="header.payload.signature")
    assert runner.credential_mode(env) == runner.CREDENTIAL_MODE_TOKEN


def test_the_local_hmac_bearer_is_a_last_resort() -> None:
    assert runner.credential_mode(FULL_ENV) == runner.CREDENTIAL_MODE_HMAC


def test_no_credential_mode_fails_the_preflight() -> None:
    env = _env()
    env.pop("ITSM_AUTH_HMAC_SECRET")
    assert runner.credential_mode(env) is None
    assert any("reviewer credential" in item for item in runner.missing_requirements(env))


def test_the_oidc_mode_needs_two_distinct_subjects() -> None:
    env = _env(
        ITSM_IDENTITY_BASE_URL="https://127.0.0.1:8443",
        ITSM_IDENTITY_CA_FILE="/tmp/simulator-ca.pem",
        ITSM_REVIEWER_SUBJECT_A="reviewer-a",
    )
    missing = runner.missing_requirements(env)
    assert any("two reviewer subjects" in item for item in missing)

    same = _env(
        ITSM_IDENTITY_BASE_URL="https://127.0.0.1:8443",
        ITSM_IDENTITY_CA_FILE="/tmp/simulator-ca.pem",
        ITSM_REVIEWER_SUBJECT_A="reviewer-a",
        ITSM_REVIEWER_SUBJECT_B="reviewer-a",
    )
    assert any("must differ" in item for item in runner.missing_requirements(same))


# ---------------------------------------------------------------------------
# Evidence grounding: the proposal must cite evidence that exists
# ---------------------------------------------------------------------------


def _proposal(*cited: str) -> Any:
    from itsm_agent.domain.events import InvestigationProposal

    return InvestigationProposal(
        investigation_id=uuid.uuid4(),
        hypothesis="a hypothesis",
        supporting_evidence=list(cited),
        contradicting_evidence=[],
        missing_evidence=[],
        uncertainty="medium",
        recommended_disposition="CONFIRM",
        model_version="m1",
        prompt_version="p1",
    )


def test_grounding_accepts_evidence_inside_the_snapshot() -> None:
    source_event_id = uuid.uuid4()
    persisted = SimpleNamespace(id=uuid.uuid4(), source_event_id=source_event_id)

    result = runner._evidence_grounding(  # noqa: SLF001 - unit assertion
        proposal=_proposal(str(source_event_id)),
        snapshot_ids=(source_event_id,),
        persisted=[persisted],
    )

    assert result["checked"] is True
    assert result["in_snapshot"] is True
    assert result["resolves_to_persisted_evidence"] is True


def test_grounding_rejects_a_fabricated_evidence_reference() -> None:
    source_event_id = uuid.uuid4()
    persisted = SimpleNamespace(id=uuid.uuid4(), source_event_id=source_event_id)

    result = runner._evidence_grounding(  # noqa: SLF001 - unit assertion
        proposal=_proposal(str(uuid.uuid4())),
        snapshot_ids=(source_event_id,),
        persisted=[persisted],
    )

    assert result["in_snapshot"] is False
    assert result["resolves_to_persisted_evidence"] is False


def test_grounding_without_a_proposal_is_not_checked() -> None:
    result = runner._evidence_grounding(  # noqa: SLF001 - unit assertion
        proposal=None,
        snapshot_ids=(),
        persisted=[],
    )
    assert result["checked"] is False


# ---------------------------------------------------------------------------
# The report must never carry a credential
# ---------------------------------------------------------------------------


def test_the_report_is_sanitised_of_configured_secrets() -> None:
    api_key = "gsk-not-a-real-key"
    report = {"model": {"api_key": api_key}, "note": "nothing secret here"}

    sanitized = runner.sanitize_report(report, [api_key])

    assert api_key not in json.dumps(sanitized)
    assert sanitized["note"] == "nothing secret here"


def test_the_report_path_lives_in_the_committed_staging_directory() -> None:
    path = runner.default_report_path("2026-11-16T101500Z")
    assert path.parent == runner.DEFAULT_REPORT_DIR
    assert "staging" in path.parts


def test_oidc_mode_report_redaction_never_reads_a_reviewer_token(
    tmp_path: Path,
) -> None:
    """Regression: the OIDC path must not require ITSM_REVIEWER_TOKEN.

    `sanitize_report` used to evaluate `options.reviewer_token` unconditionally,
    so an OIDC run crashed *after* doing all the work — the mode the staging
    deployment actually uses could never produce a report.
    """
    env = _env(
        ITSM_IDENTITY_BASE_URL="https://127.0.0.1:8444",
        ITSM_IDENTITY_CA_FILE="/tmp/simulator-ca.pem",
        ITSM_REVIEWER_SUBJECT_A="reviewer-a",
        ITSM_REVIEWER_SUBJECT_B="reviewer-b",
    )
    env.pop("ITSM_AUTH_HMAC_SECRET", None)
    env.pop("ITSM_REVIEWER_TOKEN", None)

    options = runner.StagingOptions(
        env=env,
        api_base_url="http://127.0.0.1:8001",
        report_path=tmp_path / "report.json",
    )

    assert options.credential_mode == runner.CREDENTIAL_MODE_OIDC
    # Must not raise, and must redact only what was actually used.
    assert runner.redaction_secrets(options) == ["gsk-not-a-real-key"]


def test_token_mode_redacts_the_supplied_token(tmp_path: Path) -> None:
    env = _env(ITSM_REVIEWER_TOKEN="header.payload.signature")
    env.pop("ITSM_AUTH_HMAC_SECRET", None)
    options = runner.StagingOptions(
        env=env,
        api_base_url="http://127.0.0.1:8001",
        report_path=tmp_path / "report.json",
    )
    assert runner.redaction_secrets(options) == [
        "gsk-not-a-real-key",
        "header.payload.signature",
    ]


def test_hmac_mode_redacts_the_signing_secret_not_a_token(tmp_path: Path) -> None:
    options = runner.StagingOptions(
        env=_env(),
        api_base_url="http://127.0.0.1:8001",
        report_path=tmp_path / "report.json",
    )
    assert runner.redaction_secrets(options) == [
        "gsk-not-a-real-key",
        "reviewer-secret-value-0123456789",
    ]
