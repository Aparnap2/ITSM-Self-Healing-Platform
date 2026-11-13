"""Unit tests for the finding lifecycle state machine.

Marker: ``unit``. Pure domain policy: no database, no network. The matrix is
checked exhaustively so an accidental edge addition cannot pass silently.
"""

from __future__ import annotations

import pytest

from itsm_agent.domain.finding_lifecycle import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATUSES,
    FindingStatus,
    InvalidTransitionError,
    VerifierNotIndependentError,
    assert_verifier_independent,
    is_terminal,
    validate_transition,
)

pytestmark = pytest.mark.unit

ALL_STATUSES = tuple(status.value for status in FindingStatus)


def _edges() -> set[tuple[str, str]]:
    return {
        (source, target) for source, targets in ALLOWED_TRANSITIONS.items() for target in targets
    }


def test_every_status_is_reachable_from_open_or_is_a_source() -> None:
    # Every status must appear in the matrix (as a source or a target), so a
    # newly added status cannot be silently unreachable.
    sources = set(ALLOWED_TRANSITIONS)
    targets = {target for targets in ALLOWED_TRANSITIONS.values() for target in targets}
    assert sources | targets == set(ALL_STATUSES)


def test_no_transition_leaves_a_terminal_status() -> None:
    for status in TERMINAL_STATUSES:
        assert ALLOWED_TRANSITIONS[status] == frozenset()
        assert is_terminal(status)


def test_resolved_is_not_terminal_but_has_exactly_one_closeout_edge() -> None:
    # RESOLVED keeps only the independent-verification edge.
    assert not is_terminal(FindingStatus.RESOLVED)
    assert ALLOWED_TRANSITIONS[FindingStatus.RESOLVED] == frozenset({FindingStatus.VERIFIED})


def test_no_self_transitions_exist() -> None:
    for source, target in _edges():
        assert source != target


@pytest.mark.parametrize(("source", "target"), sorted(_edges()))
def test_allowed_edges_are_accepted(source: str, target: str) -> None:
    validate_transition(source, target, reason="evidence reviewed")


def test_all_disallowed_edges_are_rejected() -> None:
    allowed = _edges()
    for source in ALL_STATUSES:
        for target in ALL_STATUSES:
            if (source, target) in allowed:
                continue
            with pytest.raises(InvalidTransitionError):
                validate_transition(source, target, reason="evidence reviewed")


def test_unknown_status_is_rejected_with_its_own_code() -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        validate_transition("OPEN", "NOT_A_STATUS", reason="evidence reviewed")
    assert excinfo.value.code == "UNKNOWN_STATUS"


def test_terminal_source_is_rejected_with_its_own_code() -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        validate_transition("VERIFIED", "OPEN", reason="reopen attempt")
    assert excinfo.value.code == "TERMINAL_STATE"


def test_missing_reason_is_rejected_with_its_own_code() -> None:
    for reason in ("", "   "):
        with pytest.raises(InvalidTransitionError) as excinfo:
            validate_transition("OPEN", "ACKNOWLEDGED", reason=reason)
        assert excinfo.value.code == "MISSING_REASON"


def test_open_to_resolved_is_allowed_for_a_single_step_closeout() -> None:
    validate_transition("OPEN", "RESOLVED", reason="remediated while investigating")


def test_accepted_risk_and_false_positive_are_terminal_outcomes() -> None:
    for target in ("FALSE_POSITIVE", "ACCEPTED_RISK"):
        validate_transition("OPEN", target, reason="reviewed")
        assert is_terminal(target)
        with pytest.raises(InvalidTransitionError):
            validate_transition(target, "OPEN", reason="reopen attempt")


# ---------------------------------------------------------------------------
# Independent verification
# ---------------------------------------------------------------------------


def test_independent_verifier_is_accepted() -> None:
    assert_verifier_independent("bob", "alice")


def test_self_verification_is_rejected() -> None:
    with pytest.raises(VerifierNotIndependentError) as excinfo:
        assert_verifier_independent("alice", "alice")
    assert excinfo.value.code == "VERIFIER_NOT_INDEPENDENT"


def test_missing_verifier_is_rejected() -> None:
    with pytest.raises(VerifierNotIndependentError):
        assert_verifier_independent(None, "alice")
    with pytest.raises(VerifierNotIndependentError):
        assert_verifier_independent("   ", "alice")


def test_unknown_resolver_fails_closed() -> None:
    # A legacy RESOLVED finding with no transition history cannot prove
    # independence, so it must not be verifiable.
    with pytest.raises(VerifierNotIndependentError):
        assert_verifier_independent("bob", None)
