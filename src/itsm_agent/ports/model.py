"""Model port: the only way workflow nodes talk to an LLM (PRD §3.2, §6.2).

A real adapter (e.g. Ollama) is implemented by another agent behind this
Protocol. Workflow code depends on the Protocol only; tests use fakes.
LLM output is never authorization — it is re-validated at this boundary.
"""

from __future__ import annotations

from typing import Annotated, Literal, Protocol, runtime_checkable

from pydantic import Field, StringConstraints

from itsm_agent.domain.events import (
    DiagnosticObservation,
    SafeIdentifier,
    StrictModel,
)


class TriageInput(StrictModel):
    """Bounded, sanitized input handed to the model for triage."""

    incident_id: str
    title: str
    description: Annotated[str, StringConstraints(max_length=8000)]
    service_name: SafeIdentifier
    severity: Literal["P1", "P2", "P3", "P4"]
    environment: Literal["local", "test", "staging"]
    evidence: list[DiagnosticObservation] = Field(default_factory=list, max_length=20)


class TriageOutput(StrictModel):
    """PRD §6.2 triage contract.

    The model may recommend a category and failure class, but there is no
    ``authorized`` field: confidence is an evaluation signal, never an
    authorization signal.
    """

    category: Literal[
        "SERVICE_UNHEALTHY",
        "ACCESS_REQUEST",
        "NETWORK_ISSUE",
        "UNKNOWN",
    ]
    affected_service: SafeIdentifier | None = None
    suspected_failure_class: Literal[
        "PROCESS_DOWN",
        "DEPENDENCY_FAILURE",
        "CONFIGURATION",
        "PERMISSION",
        "UNKNOWN",
    ]
    urgency: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    missing_information: list[Annotated[str, StringConstraints(max_length=240)]] = Field(
        default_factory=list, max_length=10
    )
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: Annotated[str, StringConstraints(max_length=1500)]


@runtime_checkable
class ModelPort(Protocol):
    """Protocol every LLM adapter must satisfy."""

    async def triage(self, request: TriageInput) -> TriageOutput:
        """Classify the incident. Must raise on transport/model failure."""
        ...
