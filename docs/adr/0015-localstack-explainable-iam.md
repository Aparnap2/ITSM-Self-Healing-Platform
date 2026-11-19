# ADR-0015: LocalStack Explainable IAM — evaluated, not adopted

Status: Proposed (spike only; no dependency added)
Date: 2026-11-19

## Context

The platform's AWS-facing detection path consumes signed, CloudTrail-shaped
source events. Its security value rests on four properties:

1. the evidence root is an event the platform received and persisted, not a
   string a test harness typed;
2. detection is deterministic, so the same event always yields the same
   finding;
3. the model may explain a finding but cannot authorize anything;
4. a terminal outcome needs independent verification and an audit trail.

LocalStack's Explainable IAM (docs: `/aws/developer-tools/security-testing/
explainable-iam/`, verified 2026-11-19) produces real IAM authorization
decisions with a denial explanation naming the principal, action, resource,
responsible policy type (identity policy, resource policy, permissions
boundary, service control policy) and whether the denial was implicit or
explicit. `IAM_SOFT_MODE=1` records would-be denials without blocking.

That is genuinely richer than what a hand-written fixture carries, so it was
evaluated rather than dismissed. This ADR records the outcome of the
evaluation and the conditions under which it would be revisited.

## Findings that decide it

**1. It is a paid feature.** The documentation lists the feature as
"Included in Plans: Base, Ultimate". It is implemented in a `pro` module
(`localstack.pro.core.services.iam.policy_engine`), i.e. it is not available
in the community image at all. AGENTS.md requires licensing and plan terms to
be verified before reliance, and this repository's baseline must be runnable
by a reviewer without a commercial plan. LocalStack therefore cannot be a
requirement for any gate that supports a public claim.

**2. The explanations are not audit events.** They are delivered in the API
error response and in the LocalStack container log. Neither is a canonical,
signed AWS audit record. Ingesting them means an adapter that scrapes logs
and invents provenance — precisely the "fabricated evidence" failure mode the
platform exists to avoid. Any ingestion would have to stamp the explanation
with its own provenance ("observed by the local simulator at T"), and that
stamp would have to be visible downstream, because an investigator must be
able to tell a simulator observation from a control-plane audit event.

**3. It explains AWS authorization, not platform policy.** The denial answers
"why did AWS refuse this call". The platform's security question is "should
this remediation have happened, and who authorized it". The second question is
answered by the deterministic policy matrix, the approval records and the
separation of duties. Explainable IAM cannot answer it and must never be
mistaken for an authorization source.

**4. The three scenarios it is proposed for are already covered.** Implicit
deny, explicit deny and permissions-boundary denial are represented in the
deterministic scenario suite as event shapes with fixed expectations, and the
domain policy denies unknown action/target/principal without consulting any
external service. What is missing today is not the *decision* — it is the
*fidelity of the denial text* fed to the investigator's prompt.

## Decision

Do not adopt LocalStack Explainable IAM now, and do not add LocalStack to any
runtime or CI dependency set.

The remaining gap it addresses is narrow — prompt-quality evidence for
denial-based findings — and it is not on the critical path of any current
claim. Adding a commercial simulator to close a prompt-quality gap would trade
a licensing constraint and a provenance problem for a marginal gain.

## Conditions for revisiting

Adopt only if all of the following hold:

1. A concrete finding class is identified whose investigation quality is
   demonstrably limited by denial text, with a measured before/after.
2. The operator running the acceptance environment holds a Base or Ultimate
   plan, and the ADR records that as a documented operational prerequisite —
   not a hidden dependency.
3. The explanation reaches the platform through an adapter that records its
   own provenance (who observed it, in which simulated environment, under
   which plan), and the audit payload distinguishes simulator observation
   from audit event.
4. The deterministic detection tests still pass with no LocalStack present,
   and no gate can pronounce PASS only because LocalStack answered.

## Planned experiment (not run)

If condition 1 is met, the smallest useful spike is:

- start LocalStack with `ENFORCE_IAM=1` and `DEBUG=1`;
- create a principal allowed `lambda:CreateFunction` but not `iam:PassRole`,
  and attempt the call — the documented implicit-deny case;
- capture the denial text from both channels (API response and container log)
  and diff them, to see whether the log channel carries anything the response
  does not;
- run the same call under `IAM_SOFT_MODE=1` and confirm the request is not
  blocked while a denial is still recorded;
- feed each captured explanation through the existing evidence adapter as a
  provenance-stamped observation and check that (a) the finding is unchanged,
  (b) the prompt snapshot contains the text, and (c) the grounding check
  passes only if the text was actually rendered into the prompt.

The spike is four steps and produces a single question's answer: does the
denial text change the investigation's explanation in a way an operator would
call better? If that cannot be answered, the feature is not worth its cost.

## Consequences

- The baseline stays runnable with no commercial plan and no internet.
- Denial-based detection keeps its deterministic, fixture-backed coverage.
- The licensing constraint is documented here rather than discovered later by
  a reviewer who cannot reproduce the demo.

## Alternatives considered

1. **LocalStack as the default AWS simulator.** Rejected: paid plan required
   for the feature in question, and the community image does not implement it.
2. **Scrape the LocalStack log into the event stream.** Rejected: creates
   unverifiable provenance; a log line is not an audit event.
3. **Hand-authored denial fixtures (status quo).** Accepted for now: fully
   deterministic and offline, at the cost of less realistic denial prose.
4. **Real AWS.** Rejected: out of scope by project policy; no real
   credentials, no production mutations.
