"""LOCAL IDENTITY SIMULATOR — development and staging only.

This package stands in for an external identity provider in the isolated
staging environment. It exists because the rehearsal needs a *genuine*
credential that the real OIDC relying party accepts — an HMAC bypass would
prove nothing about the authentication boundary.

What this simulator is:

* a **signing authority** for RS256 JWTs, publishing its public keys on a
  local JWKS endpoint over TLS;
* an issuer of tokens for a fixed, pre-declared set of subjects.

What it is deliberately **not**:

* it holds **no application authorization**. Roles, tenants and reviewer
  state live in the application's own directory (`reviewer_authorizations`),
  and the OIDC relying party resolves them server-side on every request. The
  tokens minted here carry no role or tenant claim, so a token can never
  grant itself access to anything;
* it is **not** an identity provider for production. It binds to loopback
  only, serves a certificate signed by a throwaway CA, and every response is
  labelled as simulator output.

Never point a deployed environment at this package, and never mint
production credentials here.
"""

from __future__ import annotations

__all__ = ["__simulator_notice__"]

#: Machine-readable marker emitted on every simulator response and printed by
#: the CLI, so a simulator artifact can never be mistaken for a real one.
__simulator_notice__ = (
    "LOCAL SIMULATOR — development/staging only; not an identity provider, "
    "holds no application authorization"
)
