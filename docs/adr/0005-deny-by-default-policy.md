# ADR-0005: Deny-by-default deterministic policy engine

Status: Accepted
Date: 2026-10-28

## Context

An LLM proposes remediation actions. If model output could authorize or
execute anything, the system would be unsafe by construction: models
hallucinate, misread injected ticket text, and cannot be audited
deterministically. PRD FR-05 and §8.2 mandate: deny by default, unknown
action/resource/principal → deny, LLM output is never a source of
authorization, the decision is recorded before any side effect, and
approval never overrides a currently denied policy.

## Decision

- The policy engine is a **pure, deterministic domain function** in
  `domain/policies.py`: given (action proposal, target, principal,
  environment, current incident state, policy snapshot) it returns a
  typed `PolicyDecisionResult` with outcome (`ALLOW | DENY |
  REQUIRE_APPROVAL`), reason codes, and policy version.
- **Fail closed:** any unknown action type, resource, principal,
  environment, or malformed proposal yields DENY with an explicit reason
  code. There is no implicit fallback allow.
- **Separation of powers:** LLM proposes and explains; policy code
  authorizes; allowlisted adapters execute; an independent verifier
  establishes success. A model's confidence value can never convert a
  denial into an allow.
- **Proposal identity is a canonical hash** of action type, target,
  parameters, and policy version. Approvals bind to this exact hash,
  expire, and are single-use. Policy and preconditions are re-evaluated
  immediately before execution; a stale approval is invalidated.
- The policy matrix is versioned data (not scattered conditionals) so
  decisions are reproducible and auditable per version.

## Consequences

- Safety invariants are unit-testable offline with zero LLM/network
  (Phase 1 gate: every allow/deny/approval branch tested).
- Legitimate new remediations require an explicit policy-matrix entry —
  intentional friction; the allowlist is the safety property.
- The engine must receive current state as input; it performs no I/O
  itself, so callers are responsible for supplying fresh preconditions
  (enforced by the workflow's re-evaluation step).

## Alternatives considered

1. **LLM-as-judge authorization.** Rejected: nondeterministic,
   unauditable, and directly violates FR-05; also trivially influenced
   by prompt injection in ticket/log content.
2. **ReBAC/OPA-style external policy service.** Rejected: adds a
   network dependency inside the authorization path, conflicting with
   fail-closed behavior when policy state is unavailable and with the
   pure-domain requirement; a versioned in-domain matrix is sufficient
   for the three action types in scope.
3. **Allow-by-default with audit.** Rejected: any missed rule becomes an
   unauthorized side effect; deny-by-default makes the failure mode
   "work not done" instead of "unsafe action taken".
4. **Hard-coded per-call-site checks.** Rejected: scatters policy logic,
   makes the matrix unauditable, and invites drift between call sites.
