"""Tenant identity constants shared by the pure domain and persistence.

The legacy incident/remediation workflow predates multi-tenancy. Its rows are
owned by a dedicated system tenant so they are still subject to RLS and cannot
be read by a real tenant session. Multi-tenant audit findings use the
authenticated tenant from ``SourceEvent``/``Principal`` instead.

This module is pure: no I/O and no persistence imports.
"""

from __future__ import annotations

from uuid import UUID

#: Fixed tenant used by the legacy incident workflow and pre-tenant rows.
#: It is created by migration 011 and is not a reviewer-accessible tenant.
SYSTEM_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

__all__ = ["SYSTEM_TENANT_ID"]
