"""Contract tests for the infrastructure adapter + simulator + verifier.

Covers: respx-mocked action/state paths, the two-distinct-paths rule,
fault-injection modes, idempotent replay, and independent verification.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from itsm_agent.adapters.http import UnexpectedResponseError
from itsm_agent.adapters.infrastructure.mockoon_infra import (
    MockoonInfrastructureActionAdapter,
    MockoonInfrastructureStateReader,
)
from itsm_agent.simulators.infrastructure.simulator import (
    InfrastructureSimulator,
    UnknownServiceError,
)
from itsm_agent.simulators.infrastructure.verifier import IndependentVerifier

BASE = "http://mockoon-infra.test"


@pytest.mark.contract
@respx.mock
async def test_action_path_typed_success() -> None:
    respx.post(f"{BASE}/actions/restart_service").mock(
        return_value=httpx.Response(
            200,
            json={
                "action_type": "RESTART_SERVICE",
                "service_name": "svc-a",
                "status": "SUCCEEDED",
                "result_code": "RESTART_OK",
                "summary": "ok",
                "observed_at": "2026-01-01T00:00:00Z",
            },
        )
    )
    adapter = MockoonInfrastructureActionAdapter(base_url=BASE, timeout_seconds=2.0, max_retries=1)
    result = await adapter.restart_service(
        service_name="svc-a", environment="test", idempotency_key="idem-1"
    )
    assert result.status == "SUCCEEDED"
    assert result.result_code == "RESTART_OK"
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_action_transport_failure_maps_to_outcome_unknown() -> None:
    respx.post(f"{BASE}/actions/restart_service").mock(
        return_value=httpx.Response(500, json={"error": "x"})
    )
    adapter = MockoonInfrastructureActionAdapter(base_url=BASE, timeout_seconds=2.0, max_retries=1)
    result = await adapter.restart_service(
        service_name="svc-a", environment="test", idempotency_key="idem-2"
    )
    assert result.status == "OUTCOME_UNKNOWN"
    assert result.result_code == "TRANSPORT_UNAVAILABLE"
    await adapter.aclose()


@pytest.mark.contract
@respx.mock
async def test_verifier_path_reads_state_and_validates_target() -> None:
    respx.get(f"{BASE}/state/svc-a").mock(
        return_value=httpx.Response(
            200,
            json={
                "service_name": "svc-a",
                "environment": "test",
                "status": "HEALTHY",
                "uptime_seconds": 10,
                "restart_count": 1,
                "last_action_result_code": "RESTART_OK",
                "observed_at": "2026-01-01T00:00:00Z",
            },
        )
    )
    reader = MockoonInfrastructureStateReader(base_url=BASE, timeout_seconds=2.0, max_retries=1)
    state = await reader.read_service_state(service_name="svc-a", environment="test")
    assert state.status == "HEALTHY"
    await reader.aclose()


@pytest.mark.contract
@respx.mock
async def test_verifier_rejects_mismatched_target_response() -> None:
    respx.get(f"{BASE}/state/svc-a").mock(
        return_value=httpx.Response(
            200,
            json={
                "service_name": "svc-OTHER",
                "environment": "test",
                "status": "HEALTHY",
                "uptime_seconds": 10,
                "restart_count": 1,
                "last_action_result_code": None,
                "observed_at": "2026-01-01T00:00:00Z",
            },
        )
    )
    reader = MockoonInfrastructureStateReader(base_url=BASE, timeout_seconds=2.0, max_retries=1)
    with pytest.raises(UnexpectedResponseError):
        await reader.read_service_state(service_name="svc-a", environment="test")
    await reader.aclose()


# --- Simulator: fault modes, idempotency, independent verifier ----------


def _sim() -> InfrastructureSimulator:
    sim = InfrastructureSimulator(seed=42)
    sim.seed_service(service_name="svc-a", environment="test", status="DOWN", restart_count=0)
    return sim


@pytest.mark.contract
def test_simulator_transient_fail_then_success() -> None:
    sim = _sim()
    first = sim.restart_service(
        service_name="svc-a",
        environment="test",
        idempotency_key="k1",
        fault_mode="transient_fail",
        transient_failures=1,
    )
    assert first.status == "FAILED"
    second = sim.restart_service(
        service_name="svc-a",
        environment="test",
        idempotency_key="k2",
        fault_mode="transient_fail",
        transient_failures=1,
    )
    assert second.status == "SUCCEEDED"


@pytest.mark.contract
def test_simulator_timeout_then_success_is_ambiguous() -> None:
    sim = _sim()
    first = sim.restart_service(
        service_name="svc-a",
        environment="test",
        idempotency_key="k1",
        fault_mode="timeout_then_success",
    )
    assert first.status == "OUTCOME_UNKNOWN"
    # State must be reconciled before retry: state still DOWN.
    state = sim.read_state(service_name="svc-a", environment="test")
    assert state.status == "DOWN"
    second = sim.restart_service(
        service_name="svc-a",
        environment="test",
        idempotency_key="k2",
        fault_mode="timeout_then_success",
    )
    assert second.status == "SUCCEEDED"


@pytest.mark.contract
def test_simulator_always_fail_never_succeeds() -> None:
    sim = _sim()
    for i in range(3):
        result = sim.restart_service(
            service_name="svc-a",
            environment="test",
            idempotency_key=f"k{i}",
            fault_mode="always_fail",
        )
        assert result.status == "FAILED"
    state = sim.read_state(service_name="svc-a", environment="test")
    assert state.status == "DOWN"


@pytest.mark.contract
def test_simulator_idempotent_replay_does_not_reexecute() -> None:
    sim = _sim()
    first = sim.restart_service(service_name="svc-a", environment="test", idempotency_key="same")
    replay = sim.restart_service(service_name="svc-a", environment="test", idempotency_key="same")
    assert first.result_code == replay.result_code
    state = sim.read_state(service_name="svc-a", environment="test")
    assert state.restart_count == 1  # executed exactly once


@pytest.mark.contract
def test_simulator_unknown_service_fails_closed() -> None:
    sim = _sim()
    with pytest.raises(UnknownServiceError):
        sim.restart_service(service_name="nope", environment="test", idempotency_key="k")
    with pytest.raises(UnknownServiceError):
        sim.read_state(service_name="nope", environment="test")


@pytest.mark.contract
def test_independent_verifier_confirms_recovery() -> None:
    sim = _sim()
    verifier = IndependentVerifier(sim)
    before = verifier.verify(
        service_name="svc-a",
        environment="test",
        predicate="service_healthy",
    )
    assert before.passed is False
    sim.restart_service(service_name="svc-a", environment="test", idempotency_key="k1")
    after = verifier.verify(
        service_name="svc-a",
        environment="test",
        predicate="service_healthy",
        baseline_restart_count=0,
    )
    assert after.passed is True
    assert after.observed_state["status"] == "HEALTHY"
    assert len(after.evidence_hash) == 64


@pytest.mark.contract
def test_action_success_response_is_not_proof() -> None:
    """A SUCCEEDED action response must not flip verifier state by itself."""
    sim = _sim()
    result = sim.restart_service(service_name="svc-a", environment="test", idempotency_key="k1")
    assert result.status == "SUCCEEDED"
    # Verifier reads state independently; here it agrees, but the point is
    # the verifier never consumed the action response.
    verifier = IndependentVerifier(sim)
    observation = verifier.verify(
        service_name="svc-a", environment="test", predicate="service_healthy"
    )
    assert observation.passed is True
    assert observation.verifier_version == "independent-verifier-v1"
