# ADR-0003: Moto as default AWS simulator; LocalStack optional pending license verification

Status: Accepted
Date: 2026-10-28

## Context

The platform needs an AWS API simulator for any infrastructure-behavior
tests (PRD §2.1, Phase 2). Two candidates: **Moto** (Apache-2.0, runs
in-process or as a small server) and **LocalStack** (installed locally
via Docker in this environment). LocalStack's community edition license
and plan terms restrict some features and commercial/portfolio use; its
licensing has changed over time and must be verified against the
*current* terms before any reliance. AGENTS.md rule 18 requires
reporting simulator licensing limitations accurately.

## Decision

- **Moto is the default AWS API simulator** for all tests that need AWS
  API behavior. It is used only where genuinely needed — the core
  workflow does not depend on AWS at all.
- **LocalStack is optional and NOT used in the baseline.** It may be
  adopted later only after verifying that its current license/plan
  permits the intended portfolio use, and the verification result is
  documented in this ADR.
- Core deterministic tests must not require either simulator; they run
  offline (PRD §9.3 release gates).

## Consequences

- No licensing ambiguity in the baseline; Apache-2.0 Moto is safe for a
  public portfolio repo.
- Any AWS-specific fixture lives behind the infrastructure port, so
  swapping Moto → LocalStack later touches only test wiring, not domain
  or application code.
- If LocalStack is never cleared, some AWS-fidelity behaviors (e.g.
  certain IAM edge cases) may be less realistic under Moto; this is
  acceptable because real production mutations are out of scope.

## Alternatives considered

1. **LocalStack as default.** Rejected for now: license/plan terms for
   the intended use are unverified; adopting it without verification
   would violate the project's own accuracy rule (AGENTS.md rule 18).
2. **No AWS simulator at all.** Rejected: the PRD contemplates AWS API
   behavior in the infrastructure adapter; a deterministic simulator is
   needed for reproducible fault injection.
3. **Real AWS free tier.** Rejected: violates the no-real-production /
   no-real-credentials constraint and breaks offline determinism.
