"""Administration-plane CLI: provision reviewer authorizations.

The reviewer authorization directory (``reviewer_authorizations``) is owned by
the administration plane. The runtime role may read it and must never write
it; this CLI is the controlled write path, and it refuses to run unless the
connected role actually holds administrative privileges.

It is deliberately not a general-purpose authorization API: it provisions
reviewer identities only, it requires a reason for every change, it versions
every change, and it writes an audit event per affected tenant in the same
transaction as the change.

Usage (staging/local):

    ITSM_ADMIN_DSN=postgresql://admin@localhost:5432/itsm \\
    uv run python tools/provision_reviewer.py \\
        --issuer https://issuer.staging.test \\
        --subject reviewer-a --subject reviewer-b \\
        --roles reviewer --tenants <uuid> --reason "staging rehearsal"

Exit codes: 0 success, 2 refused (configuration, privilege or validation),
1 unexpected error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:  # pragma: no cover - path bootstrap
    sys.path.insert(0, str(REPO_ROOT / "src"))

from itsm_agent.adapters.persistence.pool import (  # noqa: E402
    PersistenceConfig,
    create_pool,
)
from itsm_agent.adapters.persistence.repositories import (  # noqa: E402
    RepositoryBundle,
)
from itsm_agent.adapters.persistence.reviewer_admin import (  # noqa: E402
    ProvisioningRefused,
    ProvisioningResult,
    PsycopgReviewerAuthorizationAdminRepository,
    ReviewerGrant,
)
from itsm_agent.api.auth import Role  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2

#: Roles the directory understands. Anything else is refused: an unknown role
#: would silently grant nothing, which is worse than failing.
KNOWN_ROLES = frozenset(role.value for role in Role)


@dataclass(frozen=True)
class ProvisioningRequest:
    """A validated provisioning request, ready to execute."""

    issuer: str
    subjects: tuple[str, ...]
    roles: tuple[str, ...]
    tenant_ids: tuple[UUID, ...]
    reason: str
    actor: str
    revoke: bool


class RequestError(Exception):
    """The request is invalid; nothing was written."""


def parse_request(args: argparse.Namespace) -> ProvisioningRequest:
    """Validate the CLI arguments. Raises :class:`RequestError` when invalid."""
    subjects = tuple(dict.fromkeys(s.strip() for s in args.subject if s.strip()))
    if not subjects:
        raise RequestError("at least one --subject is required")
    for subject in subjects:
        if len(subject) > 255:
            raise RequestError("subject is too long for the directory key")

    roles = tuple(dict.fromkeys(r.strip().lower() for r in args.roles.split(",") if r.strip()))
    if not roles:
        raise RequestError("at least one role is required")
    unknown = sorted(set(roles) - KNOWN_ROLES)
    if unknown:
        raise RequestError(
            f"unknown role(s): {', '.join(unknown)}; known roles: {', '.join(sorted(KNOWN_ROLES))}"
        )

    tenants: list[UUID] = []
    for raw in args.tenants.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            tenants.append(UUID(raw))
        except ValueError as exc:
            raise RequestError(f"not a valid tenant UUID: {raw!r}") from exc
    if not tenants:
        raise RequestError("at least one --tenants UUID is required")
    if len(set(tenants)) != len(tenants):
        raise RequestError("tenant list contains duplicates")

    if not args.reason.strip():
        raise RequestError("--reason is required: every authorization change is justified")

    if not args.issuer.strip():
        raise RequestError("--issuer is required")

    return ProvisioningRequest(
        issuer=args.issuer.strip(),
        subjects=subjects,
        roles=roles,
        tenant_ids=tuple(tenants),
        reason=args.reason.strip(),
        actor=args.actor,
        revoke=bool(args.revoke),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provision_reviewer",
        description="Provision reviewer authorizations (administration plane).",
    )
    parser.add_argument(
        "--admin-dsn",
        default=os.environ.get("ITSM_ADMIN_DSN", ""),
        help="DSN with administrative privileges (default: $ITSM_ADMIN_DSN)",
    )
    parser.add_argument("--issuer", required=True, help="OIDC issuer of the identity")
    parser.add_argument(
        "--subject",
        action="append",
        default=[],
        help="OIDC subject of the reviewer; repeat for several identities",
    )
    parser.add_argument(
        "--roles",
        required=True,
        help=f"comma-separated roles ({', '.join(sorted(KNOWN_ROLES))})",
    )
    parser.add_argument("--tenants", required=True, help="comma-separated tenant UUIDs")
    parser.add_argument("--reason", required=True, help="why this authorization changes")
    parser.add_argument(
        "--actor",
        default=os.environ.get("USER", "admin-cli"),
        help="who is performing the change (recorded in the audit trail)",
    )
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="deactivate the authorization instead of granting it",
    )
    return parser


async def run(request: ProvisioningRequest, dsn: str) -> tuple[str, list[ProvisioningResult]]:
    """Execute the provisioning request against the administration DSN."""
    pool = create_pool(PersistenceConfig(dsn=dsn, min_size=1, max_size=2))
    await pool.open()
    try:
        bundle = RepositoryBundle(pool)
        repo = PsycopgReviewerAuthorizationAdminRepository(pool, audit=bundle.audit)
        role_name = await repo.assert_may_write()
        results: list[ProvisioningResult] = []
        for subject in request.subjects:
            if request.revoke:
                results.append(
                    await repo.revoke(
                        issuer=request.issuer,
                        subject=subject,
                        reason=request.reason,
                        actor=request.actor,
                    )
                )
            else:
                grant = ReviewerGrant(
                    issuer=request.issuer,
                    subject=subject,
                    tenant_ids=request.tenant_ids,
                    roles=request.roles,
                    active=True,
                    reason=request.reason,
                    actor=request.actor,
                )
                results.append(await repo.apply(grant))
        return role_name, results
    finally:
        await pool.close()


def _summary(results: Sequence[ProvisioningResult], role_name: str | None) -> str:
    payload = {
        "role": role_name,
        "results": [
            {
                "issuer": r.issuer,
                "subject": r.subject,
                "outcome": str(r.outcome),
                "roles": list(r.roles),
                "tenant_ids": [str(t) for t in r.tenant_ids],
                "active": r.active,
                "authorization_version": r.authorization_version,
                "audited_tenants": [str(t) for t in r.affected_tenants],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        request = parse_request(args)
    except RequestError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    dsn = args.admin_dsn.strip()
    if not dsn:
        print(
            "refused: an administrative DSN is required (--admin-dsn or "
            "$ITSM_ADMIN_DSN). The runtime role must never be able to grant "
            "reviewer roles.",
            file=sys.stderr,
        )
        return EXIT_REFUSED

    try:
        role_name, results = asyncio.run(run(request, dsn))
    except ProvisioningRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(_summary(results, role_name))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - process boundary
    raise SystemExit(main())
