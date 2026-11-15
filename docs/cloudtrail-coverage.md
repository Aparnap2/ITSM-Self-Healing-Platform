# AWS CloudTrail Coverage (Task 8)

## Supported events (baseline)

- Management events: IAM, STS AssumeRole, KMS, S3 bucket config, EC2 config.
- AssumeRole activity normalized with principal/session/source IP context.

## Escalation detection semantics

- Privilege escalation is decided by an explicit allowlist of API actions
  (`PRIVILEGE_ESCALATION_ACTIONS`), matched case-insensitively on the bare
  action name after a service qualifier (`iam:`, `sts.amazonaws.com:`) is
  stripped.
- The allowlist replaces the previous substring heuristic (`"attach"` matched
  anywhere in the action name), which reported a routine `ec2:AttachVolume`
  operations call as privilege escalation — a measured false positive in the
  pilot report (`docs/pilot.md`).
- Actions that require approval evidence are the escalation set plus the
  privilege-reducing and credential-administration actions
  (`PRIVILEGED_ACTIONS`). Unrelated operations are not examined for approval
  evidence.
- The generic escalation rule consults approval evidence: a valid, matching,
  unexpired approval for the same principal, action and resource suppresses
  the finding. An approval owned by another tenant, or one that is denied,
  revoked, expired or dimension-mismatched, never suppresses anything.
- One event yields at most one escalation-family finding: a definitive
  approval answer (`SUSPICIOUS` / `VIOLATION`) replaces the generic
  classification finding for that event. An uncertainty answer
  (`COVERAGE_GAP` / `UNRESOLVED_IDENTITY`) does not — it reports that
  authorization could not be determined, so the classification finding stands
  beside it.

## Data events

- Data events (S3 object-level, Lambda invoke) are NOT assumed enabled.
- Coverage depends on trail configuration; documented per installation.
- Do not fabricate data-event coverage.

## Simulator limitations (Moto)

- Moto simulates S3/STS/IAM APIs in-process; CloudTrail delivery semantics
  (S3 file layout, SQS notifications, delay) are not fully replicated.
- Real AWS contract tests required before claiming production compatibility.

## Real-AWS gaps

- CloudTrail delivery latency and ordering.
- Cross-account trails and organization trails.
- EventBridge/SQS notification timing.
- KMS-encrypted trail buckets.
