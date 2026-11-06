# ADR-0012: LocalStack testing (optional)

Status: Accepted
Date: 2026-10-30

## Context

AWS API fidelity may be needed for some adapter tests. LocalStack licensing
and plan terms must be verified before reliance (AGENTS.md rule 18).

## Decision

- Moto remains the default AWS simulator (Apache-2.0, in-process).
- LocalStack is optional and not used in the baseline.
- Adoption requires documented license/plan verification in this ADR.
- Core deterministic tests require neither simulator.

## Consequences

- No licensing ambiguity in baseline.
- Some AWS-fidelity behaviors may be less realistic under Moto; acceptable
  because real production mutations are out of scope.

## Alternatives considered

1. LocalStack as default. Rejected: unverified license terms.
2. Real AWS. Rejected: violates no-real-credentials and offline determinism.
