"""Administration-plane writer for the reviewer authorization directory.

``reviewer_authorizations`` is owned by the administration plane. The runtime
role may READ it and must never write it: the write privileges were revoked in
``migrations/010_runtime_role.sql`` and the startup assertion in
``src/itsm_agent/adapters/persistence/privileges.py`` fails if the runtime
role can write. This module is the controlled write path, reachable only from
the provisioning CLI (``tools/provision_reviewer.py``) — never from the API,
the workers, or the relay.

Properties this path guarantees:

* **Fail closed on empty grants.** An authorization without a subject, a
  role, or a tenant is rejected before any write; the table's own CHECK
  constraints agree.
* **Fail closed without an auditor.** The audit record and the authorization
  change commit in the same transaction, so a grant can never land without its
  audit event. A repository built without an audit collaborator refuses to
  change anything.
* **Versioned.** ``authorization_version`` is bumped on every real change, so
  a reader can tell that the grant changed.
* **No silent widening.** Re-provisioning an identical grant is a no-op
  (``UNCHANGED``): it does not bump the version and does not write an audit
  event, so the audit trail records changes and only changes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import NAMESPACE_DNS, UUID, uuid4, uuid5

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from itsm_agent.domain.models import AuditEventRecord
from itsm_agent.privacy.redaction import redact_secrets

#: Stable namespace so the same (issuer, subject) always maps to the same
#: entity id, which lets the audit trail reference the grant it witnessed.
ENTITY_NAMESPACE = uuid5(NAMESPACE_DNS, "itsm-agent.reviewer-authorization")

#: Audit event types written by this path.
EVENT_GRANTED = "REVIEWER_AUTHORIZATION_GRANTED"
EVENT_UPDATED = "REVIEWER_AUTHORIZATION_UPDATED"
EVENT_REVOKED = "REVIEWER_AUTHORIZATION_REVOKED"


class ProvisioningOutcome(StrEnum):
    """What a provisioning call actually did."""

    CREATED = "CREATED"
    UPDATED = "UPDATED"
    UNCHANGED = "UNCHANGED"
    REVOKED = "REVOKED"


class ProvisioningRefused(Exception):
    """Raised when a grant is refused before anything is written."""


class AuditAppender(Protocol):
    """The narrow slice of the audit repository this path needs."""

    async def append(
        self, event: AuditEventRecord, *, conn: AsyncConnection | None = None
    ) -> AuditEventRecord: ...


@dataclass(frozen=True)
class ReviewerGrant:
    """One authorization grant: who may act, where, and with which roles."""

    issuer: str
    subject: str
    tenant_ids: tuple[UUID, ...]
    roles: tuple[str, ...]
    active: bool = True
    reason: str = ""
    actor: str = "admin-cli"

    def __post_init__(self) -> None:
        if not self.issuer.strip():
            raise ProvisioningRefused("issuer must not be empty")
        if not self.subject.strip():
            raise ProvisioningRefused("subject must not be empty")
        if not self.roles:
            raise ProvisioningRefused("at least one role is required")
        if not self.tenant_ids:
            raise ProvisioningRefused("at least one tenant is required")
        if len(set(self.tenant_ids)) != len(self.tenant_ids):
            raise ProvisioningRefused("tenant list contains duplicates")
        if len(set(self.roles)) != len(self.roles):
            raise ProvisioningRefused("role list contains duplicates")
        if not self.reason.strip():
            raise ProvisioningRefused("a reason is required for every authorization change")

    @property
    def entity_id(self) -> UUID:
        """Stable identifier for this (issuer, subject) pair."""
        return uuid5(ENTITY_NAMESPACE, f"{self.issuer}|{self.subject}")


@dataclass(frozen=True)
class ProvisioningResult:
    """Outcome of one provisioning call, with the state that was written."""

    outcome: ProvisioningOutcome
    issuer: str
    subject: str
    roles: tuple[str, ...]
    tenant_ids: tuple[UUID, ...]
    active: bool
    authorization_version: str
    affected_tenants: tuple[UUID, ...] = ()
    changed: bool = False


def next_authorization_version(current: str | None) -> str:
    """The next version string for an authorization row.

    Versions are a simple integer sequence so a reader can order them. A
    legacy row whose version is not numeric is replaced by ``1`` on its next
    real change; the audit trail records the change either way.
    """
    if current is None:
        return "1"
    return str(int(current) + 1) if current.isdigit() else "1"


class PsycopgReviewerAuthorizationAdminRepository:
    """Controlled write path for ``reviewer_authorizations``.

    The caller must already hold administrative privileges; this repository
    refuses to run against a role that cannot write the table, so a
    misconfigured invocation fails closed instead of silently doing nothing.
    """

    def __init__(
        self,
        pool: AsyncConnectionPool[AsyncConnection],
        *,
        audit: AuditAppender | None = None,
    ) -> None:
        self._pool = pool
        self._audit = audit

    async def assert_may_write(self, *, conn: AsyncConnection | None = None) -> str:
        """Fail closed unless the connected role may write the directory.

        Returns the connected role name. Raises :class:`ProvisioningRefused`
        when the role lacks INSERT/UPDATE on the table — which is exactly the
        state of the runtime role, by design.
        """
        async with self._session(conn) as c, c.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT current_user AS role_name,
                       has_table_privilege(
                           current_user, 'reviewer_authorizations', 'INSERT'
                       ) AS may_insert,
                       has_table_privilege(
                           current_user, 'reviewer_authorizations', 'UPDATE'
                       ) AS may_update
                """
            )
            row = await cur.fetchone()
        if row is None:  # pragma: no cover - the catalog always resolves
            raise ProvisioningRefused("could not determine the connected role")
        role_name = str(row["role_name"])
        if not row["may_insert"] or not row["may_update"]:
            raise ProvisioningRefused(
                f"role {role_name!r} may not write the reviewer authorization "
                "directory; the runtime role must never be able to grant roles"
            )
        return role_name

    async def apply(
        self,
        grant: ReviewerGrant,
        *,
        conn: AsyncConnection | None = None,
    ) -> ProvisioningResult:
        """Grant or update an authorization, with an audited transaction."""
        affected: tuple[UUID, ...] = ()
        async with self._session(conn) as c:
            async with c.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """
                    SELECT tenant_ids, roles, active, authorization_version
                      FROM reviewer_authorizations
                     WHERE issuer = %s AND subject = %s
                     FOR UPDATE
                    """,
                    (grant.issuer, grant.subject),
                )
                current = await cur.fetchone()

                previous_tenants: tuple[UUID, ...] = ()
                if current is None:
                    outcome = ProvisioningOutcome.CREATED
                    version = next_authorization_version(None)
                    changed = True
                else:
                    previous_tenants = tuple(current["tenant_ids"])
                    unchanged = (
                        tuple(current["tenant_ids"]) == grant.tenant_ids
                        and tuple(current["roles"]) == grant.roles
                        and bool(current["active"]) == grant.active
                    )
                    if unchanged:
                        outcome = ProvisioningOutcome.UNCHANGED
                        version = str(current["authorization_version"])
                        changed = False
                    else:
                        outcome = ProvisioningOutcome.UPDATED
                        version = next_authorization_version(str(current["authorization_version"]))
                        changed = True

                if changed:
                    await cur.execute(
                        """
                        INSERT INTO reviewer_authorizations (
                            issuer, subject, tenant_ids, roles, active,
                            authorization_version, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, now())
                        ON CONFLICT (issuer, subject) DO UPDATE
                            SET tenant_ids = EXCLUDED.tenant_ids,
                                roles = EXCLUDED.roles,
                                active = EXCLUDED.active,
                                authorization_version = EXCLUDED.authorization_version,
                                updated_at = now()
                        """,
                        (
                            grant.issuer,
                            grant.subject,
                            list(grant.tenant_ids),
                            list(grant.roles),
                            grant.active,
                            version,
                        ),
                    )

            if changed:
                affected = tuple(dict.fromkeys((*previous_tenants, *grant.tenant_ids)))
                await self._write_audit(
                    issuer=grant.issuer,
                    subject=grant.subject,
                    roles=grant.roles,
                    tenant_ids=grant.tenant_ids,
                    active=grant.active,
                    reason=grant.reason,
                    actor=grant.actor,
                    affected_tenants=affected,
                    event_type=EVENT_GRANTED
                    if outcome is ProvisioningOutcome.CREATED
                    else EVENT_UPDATED,
                    version=version,
                    conn=c,
                )

        return ProvisioningResult(
            outcome=outcome,
            issuer=grant.issuer,
            subject=grant.subject,
            roles=grant.roles,
            tenant_ids=grant.tenant_ids,
            active=grant.active,
            authorization_version=version,
            affected_tenants=affected,
            changed=changed,
        )

    async def revoke(
        self,
        *,
        issuer: str,
        subject: str,
        reason: str,
        actor: str = "admin-cli",
        conn: AsyncConnection | None = None,
    ) -> ProvisioningResult:
        """Deactivate an authorization, keeping the row for the audit trail."""
        if not reason.strip():
            raise ProvisioningRefused("a reason is required to revoke an authorization")
        roles: tuple[str, ...] = ()
        tenants: tuple[UUID, ...] = ()
        version = "1"
        async with self._session(conn) as c:
            async with c.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """
                    SELECT tenant_ids, roles, active, authorization_version
                      FROM reviewer_authorizations
                     WHERE issuer = %s AND subject = %s
                     FOR UPDATE
                    """,
                    (issuer, subject),
                )
                current = await cur.fetchone()
                if current is None:
                    raise ProvisioningRefused(
                        f"no authorization exists for issuer={issuer!r} subject={subject!r}"
                    )
                tenants = tuple(current["tenant_ids"])
                roles = tuple(current["roles"])
                version = next_authorization_version(str(current["authorization_version"]))
                await cur.execute(
                    """
                    UPDATE reviewer_authorizations
                       SET active = FALSE,
                           authorization_version = %s,
                           updated_at = now()
                     WHERE issuer = %s AND subject = %s
                    """,
                    (version, issuer, subject),
                )
            await self._write_audit(
                issuer=issuer,
                subject=subject,
                roles=roles,
                tenant_ids=tenants,
                active=False,
                reason=reason,
                actor=actor,
                affected_tenants=tenants,
                event_type=EVENT_REVOKED,
                version=version,
                conn=c,
            )
        return ProvisioningResult(
            outcome=ProvisioningOutcome.REVOKED,
            issuer=issuer,
            subject=subject,
            roles=roles,
            tenant_ids=tenants,
            active=False,
            authorization_version=version,
            affected_tenants=tenants,
            changed=True,
        )

    async def _write_audit(
        self,
        *,
        issuer: str,
        subject: str,
        roles: tuple[str, ...],
        tenant_ids: tuple[UUID, ...],
        active: bool,
        reason: str,
        actor: str,
        affected_tenants: tuple[UUID, ...],
        event_type: str,
        version: str,
        conn: AsyncConnection,
    ) -> None:
        """Write one audit event per affected tenant, in the same transaction."""
        if self._audit is None:
            raise ProvisioningRefused(
                "no audit collaborator configured; refusing to change an "
                "authorization without an audit record"
            )
        entity_id = uuid5(ENTITY_NAMESPACE, f"{issuer}|{subject}")
        for tenant_id in affected_tenants:
            # The audit table has forced RLS, so the tenant context must be set
            # for the write. It is transaction-local, so it cannot leak to the
            # next tenant's event.
            await conn.execute("SELECT set_config('itsm.tenant_id', %s, true)", (str(tenant_id),))
            event = AuditEventRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                occurred_at=datetime.now(UTC),
                correlation_id=entity_id,
                incident_id=None,
                workflow_id=None,
                actor_type="SYSTEM",
                actor_id=actor,
                event_type=event_type,
                entity_type="reviewer_authorization",
                entity_id=entity_id,
                payload_redacted={
                    "issuer": redact_secrets(issuer),
                    "subject": redact_secrets(subject),
                    "roles": ",".join(roles),
                    "tenant_count": len(tenant_ids),
                    "active": active,
                    "authorization_version": version,
                    "reason": redact_secrets(reason)[:200],
                },
            )
            await self._audit.append(event, conn=conn)

    def _session(
        self, conn: AsyncConnection | None
    ) -> AbstractAsyncContextManager[AsyncConnection]:
        if conn is not None:
            return _borrowed(conn)
        return self._pool.connection()


@asynccontextmanager
async def _borrowed(conn: AsyncConnection) -> AsyncIterator[AsyncConnection]:
    """Yield a caller-owned connection unchanged."""
    yield conn


__all__ = [
    "EVENT_GRANTED",
    "EVENT_REVOKED",
    "EVENT_UPDATED",
    "ENTITY_NAMESPACE",
    "AuditAppender",
    "ProvisioningOutcome",
    "ProvisioningRefused",
    "ProvisioningResult",
    "PsycopgReviewerAuthorizationAdminRepository",
    "ReviewerGrant",
    "next_authorization_version",
]
