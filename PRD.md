# Event-Driven, Evidence-First Agentic Security Audit System

## Product Requirements Document (PRD)

**Status:** Pivot slices implemented on `feat/access-audit-foundation`:
frozen canonical event contract (`docs/event-contract.md`), source adapters
(CloudTrail/Moto, pgAudit, GitHub), durable ingestion with outbox + NATS
JetStream consumers and replay, identity resolution, deterministic detection
and coverage, evidence reporting with reviewer decisions, and a controlled
pilot scenario (per-task commits in IMPLEMENTATION_PLAN.md). Release
qualification repair (Task CI-0: CI repair, security scan gates, independent
acceptance verification) is in progress. Not production ready: acceptance
verification is still pending and must not be claimed otherwise.
**Product:** Event-Driven, Evidence-First Agentic Security Audit System
**Deployment target:** Local Docker Compose first; no real enterprise environment required.
**Primary demonstration:** Ingest security events from multiple sources, preserve
immutable evidence, run deterministic detection, selectively invoke agentic
investigation, and produce an auditable compliance report — without claiming
certification.

---

## 1. Product objective

Answer ten audit questions for every in-scope event, with evidence:

1. What happened? (event summary and classification)
2. Who acted? (actor and principal identity)
3. What resource was affected?
4. When did it occur (event time) versus when was it observed/ingested?
5. Was the action authorized by policy at the time?
6. What evidence supports the finding?
7. What is the risk/severity?
8. What investigation or remediation is required?
9. Is the finding resolved and independently verified?
10. What audit trail exists for the decision?

## 2. Ideal customer profile (ICP)

- Security engineering and detection teams needing reproducible, evidence-backed
  audit trails.
- Compliance officers needing control-evidence reports (not certifications).
- Platform/SRE teams operating PostgreSQL, GitHub, and AWS-adjacent estates.
- Auditors and reviewers evaluating agentic AI safety boundaries.

## 3. Initial sources

- **AWS CloudTrail** — API activity and control-plane events.
- **pgAudit** — database audit events.
- **GitHub** — repository, pull request, and audit-log events.
- **Identity/approvals** — IdP and approval workflow events.

## 4. Scope

- Ingest and normalize security events from the initial sources into a canonical
  event contract.
- Preserve raw evidence references and redacted payloads.
- Run deterministic detection rules and policy evaluation.
- Selectively invoke bounded agentic investigation for ambiguous/high-risk cases.
- Produce compliance-evidence reports with explicit limitations.
- Tenant isolation, redaction, retention, and audit completeness.

## 5. Non-goals

- Real production mutations or live enterprise access.
- Compliance certification or legal attestation.
- Real-time SIEM replacement or high-throughput streaming analytics.
- Arbitrary code/shell/SQL execution by models.
- Multi-tenant commercial SaaS.
- Unrestricted AWS access.

## 6. Architecture overview

Event-driven, evidence-first:

```
Source (CloudTrail/pgAudit/GitHub/IdP)
  -> Source adapter (auth, pagination, checkpoint)
  -> Validate + normalize (strict Pydantic)
  -> Append canonical event (PostgreSQL, append-only)
  -> Outbox -> NATS JetStream
  -> Batch consumer
  -> Deterministic analysis (rules + policy)
  -> Investigation requested (selective, bounded LLM)
  -> Verification + audit + compliance report
```

PostgreSQL is the canonical store. NATS JetStream is the async backbone.
Deterministic code authorizes; LLMs propose and explain only.

## 7. 80/20 deterministic-vs-LLM target

- **80% deterministic:** ingestion, validation, normalization, detection rules,
  policy evaluation, verification, audit persistence, reporting.
- **20% agentic:** triage of ambiguous events, investigation summaries,
  narrative generation — bounded, optional, never authoritative.

Core tests run without any LLM.

## 8. Compliance is not certification

Reports provide evidence of controls and findings. They do not constitute a
compliance certification, legal attestation, or audit opinion. Limitations and
untested conditions are always stated.

## 9. Success metrics

- Detection precision/recall on seeded scenarios.
- False-positive rate on benign event streams.
- Audit completeness (required events present for terminal outcomes).
- Evidence preservation (raw reference + hash for every finding).
- End-to-end latency for batch processing.
- Zero unauthorized side effects in adversarial suite.
- Reproducibility: deterministic tests pass offline.

## 10. Known limitations

- Portfolio baseline uses simulators (Mockoon, Moto) for external systems.
- No real production data or credentials.
- Compliance output is evidence, not certification.
- LLM-dependent evaluation is optional and reported separately.
