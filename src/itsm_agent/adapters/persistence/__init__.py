"""Persistence adapter package (psycopg 3, Phase 3)."""

from __future__ import annotations

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import (
    PsycopgActionIntentRepository,
    PsycopgApprovalRepository,
    PsycopgAuditRepository,
    PsycopgIdentityMappingRepository,
    PsycopgInboxRepository,
    PsycopgIncidentRepository,
    PsycopgOutboxRepository,
    PsycopgReviewDecisionRepository,
    PsycopgTerminalStateRepository,
    PsycopgWorkflowStateRepository,
    RepositoryBundle,
)

__all__ = [
    "PersistenceConfig",
    "create_pool",
    "PsycopgActionIntentRepository",
    "PsycopgApprovalRepository",
    "PsycopgAuditRepository",
    "PsycopgIdentityMappingRepository",
    "PsycopgIncidentRepository",
    "PsycopgInboxRepository",
    "PsycopgOutboxRepository",
    "PsycopgReviewDecisionRepository",
    "PsycopgTerminalStateRepository",
    "PsycopgWorkflowStateRepository",
    "RepositoryBundle",
]
