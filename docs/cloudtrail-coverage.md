# AWS CloudTrail Coverage (Task 8)

## Supported events (baseline)

- Management events: IAM, STS AssumeRole, KMS, S3 bucket config, EC2 config.
- AssumeRole activity normalized with principal/session/source IP context.

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
