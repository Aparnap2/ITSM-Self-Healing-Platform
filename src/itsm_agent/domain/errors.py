"""Domain errors.

Pure domain exceptions. No I/O, no vendor imports (ADR-0001).
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for all domain-rule violations.

    Every error carries a stable machine-readable ``code`` so callers can
    branch on codes, never on exception subclass sniffing or message text.
    """

    code: str = "DOMAIN_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class IllegalTransitionError(DomainError):
    """Raised when a state transition is not in the allowed-transition table."""

    code = "ILLEGAL_TRANSITION"


class PolicyViolationError(DomainError):
    """Raised when code attempts to act without a valid policy authorization."""

    code = "POLICY_VIOLATION"
