"""Persistence adapter package (psycopg 3, Phase 3)."""

from __future__ import annotations

from itsm_agent.adapters.persistence.pool import PersistenceConfig, create_pool
from itsm_agent.adapters.persistence.repositories import (
    PsycopgActionIntentRepository,
    PsycopgApprovalRepository,
    PsycopgAuditRepository,
    PsycopgEvidenceReferenceRepository,
    PsycopgFindingRepository,
    PsycopgIdentityMappingRepository,
    PsycopgInboxRepository,
    PsycopgIncidentRepository,
    PsycopgOutboxRepository,
    PsycopgProcessingRecordRepository,
    PsycopgReviewDecisionRepository,
    PsycopgTenantRepository,
    PsycopgTerminalStateRepository,
    PsycopgWorkflowStateRepository,
    RepositoryBundle,
)
from itsm_agent.adapters.persistence.tenant import tenant_transaction

__all__ = [
    "PersistenceConfig",
    "create_pool",
    "tenant_transaction",
    "PsycopgActionIntentRepository",
    "PsycopgApprovalRepository",
    "PsycopgAuditRepository",
    "PsycopgFindingRepository",
    "PsycopgIdentityMappingRepository",
    "PsycopgIncidentRepository",
    "PsycopgInboxRepository",
    "PsycopgOutboxRepository",
    "PsycopgEvidenceReferenceRepository",
    "PsycopgProcessingRecordRepository",
    "PsycopgReviewDecisionRepository",
    "PsycopgTerminalStateRepository",
    "PsycopgTenantRepository",
    "PsycopgWorkflowStateRepository",
    "RepositoryBundle",
]
