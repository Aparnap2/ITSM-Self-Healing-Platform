# Controlled Pilot (Task 17)

## Simulated organization

- One AWS account (Moto): CloudTrail management events.
- One PostgreSQL (pgAudit): privilege changes + access.
- One GitHub org: membership/permission changes.
- One identity/approval source (controlled import).

## Scenarios seeded

1. Normal user activity (benign).
2. Suspicious privilege escalation (AssumeRole to admin).
3. Activity without approval evidence.
4. Identity ambiguity (shared service account).
5. Delayed and missing events (coverage gap).

## Measurements

**Measured on 2026-11-13 against rule version `detection-rules-v1`. All data
in this section is simulated — no real tenant, no production telemetry.**

Reproduce:

```sh
uv run pytest tests/e2e/test_pilot_metrics.py -q
```

The harness (`tests/e2e/test_pilot_metrics.py`) loads the labelled dataset in
`evals/datasets/pilot_scenarios.json`, normalizes every scenario with the
production collectors, runs the deterministic detection engine
(`itsm_agent.detection.engine.run_detection`), and writes the committed
evidence artifact `evals/reports/pilot-metrics.json`.

### Method

- **Dataset**: 16 hand-labelled scenarios — 7 benign, 9 malicious — over three
  simulated sources (12 CloudTrail, 3 pgAudit, 1 GitHub audit log). Each
  scenario carries the raw source payload and the expected finding type and
  outcome. Labels are authored by hand, not derived from the engine's
  behaviour; a scenario the current rule set does not support is explicitly
  flagged `known_gap` in the dataset so that the miss is reported rather than
  hidden.
- **Detected**: a malicious scenario counts as *detected* when the engine
  produces at least one finding whose finding type **and** outcome match the
  scenario's expectation.
- **False positive**: a benign scenario counts as a *false positive* when the
  engine produces **any** finding at all.
- **Evidence preservation**: a finding preserves evidence when the evidence
  bundle built for it carries the content hash of the raw source record that
  produced it.
- **Latency**: monotonic clock (`time.perf_counter_ns`) around
  normalize + detect, per scenario; p50/p95 by linear interpolation. One
  unmeasured warm-up pass over the same dataset precedes the measured pass,
  so one-off first-call costs are not charged to a scenario.

### Results

| Metric | Value |
| --- | --- |
| Scenarios | 16 (7 benign / 9 malicious; 1 of the malicious is a declared `known_gap`) |
| Recall over all malicious scenarios | **0.8889** (8 / 9) |
| Recall over rule-supported malicious scenarios | **1.0000** (8 / 8) |
| False-positive rate over benign scenarios | **0.2857** (2 / 7) |
| Precision (scenario level) | **0.8000** (8 / 10) |
| Matched-finding ratio | **0.5714** (8 / 14 findings raised on malicious scenarios) |
| Evidence preservation | **1.0000** (16 / 16 findings) |
| Findings without evidence | 0 |
| Latency p50 / p95 (per scenario) | ≈ **0.05 ms** / ≈ **0.07 ms** (max ≈ 0.08 ms) |

Latency figures are wall-clock measurements on one machine and are refreshed
by every harness run; `evals/reports/pilot-metrics.json` holds the exact
values of the committed run. Observed spread across runs: p50 0.04–0.05 ms,
p95 0.06–0.08 ms.

Per-scenario results (from the committed artifact):

| Scenario | Label | Findings | Outcome | Result |
| --- | --- | --- | --- | --- |
| `benign-ct-s3-getobject` | benign | 0 | – | true negative |
| `benign-ct-s3-listbucket` | benign | 0 | – | true negative |
| `benign-pg-select` | benign | 0 | – | true negative |
| `benign-pg-insert` | benign | 0 | – | true negative |
| `benign-github-team-repo-add` | benign | 0 | – | true negative |
| `benign-ct-ec2-attach-volume` | benign | 1 `PRIVILEGE_ESCALATION` | SUSPICIOUS | **false positive** |
| `benign-ct-approved-assumerole` | benign | 1 `PRIVILEGE_ESCALATION` | SUSPICIOUS | **false positive** |
| `mal-ct-assumerole-admin` | malicious | 1 `PRIVILEGE_ESCALATION` | SUSPICIOUS | detected |
| `mal-ct-missing-approval` | malicious | 2 `MISSING_APPROVAL`, `PRIVILEGE_ESCALATION` | SUSPICIOUS | detected |
| `mal-ct-denied-approval` | malicious | 2 `DENIED_APPROVAL`, `PRIVILEGE_ESCALATION` | VIOLATION | detected |
| `mal-ct-mismatched-approval` | malicious | 2 `APPROVAL_MISMATCH`, `PRIVILEGE_ESCALATION` | VIOLATION | detected |
| `mal-ct-cross-tenant-approval` | malicious | 2 `MISSING_APPROVAL`, `PRIVILEGE_ESCALATION` | SUSPICIOUS | detected |
| `mal-ct-identity-ambiguous` | malicious | 2 `UNRESOLVED_IDENTITY`, `PRIVILEGE_ESCALATION` | INCONCLUSIVE | detected |
| `mal-ct-coverage-gap` | malicious | 2 `COVERAGE_GAP`, `PRIVILEGE_ESCALATION` | COVERAGE_GAP | detected |
| `mal-ct-access-denied` | malicious | 1 `FAILED_ACCESS` | SUSPICIOUS | detected |
| `mal-pg-alter-role-superuser` | malicious | 0 | – | **miss (declared `known_gap`)** |

### What the pilot found

1. **Two false positives, one root cause.** The escalation rule is a
   substring heuristic (`"attach" in event_type`) that never consults
   approval evidence. It therefore reports a routine `ec2:AttachVolume`
   operations call, and it reports a `sts:AssumeRole` that is covered by a
   valid, exact-match, unexpired approval. Both are counted above; neither
   is waived.
2. **One declared coverage gap.** The rule set has no PostgreSQL privilege
   rule, so a seeded `ALTER ROLE app WITH SUPERUSER` is not detected. It is
   labelled `known_gap` in the dataset and is the single miss behind the
   0.8889 recall.
3. **Every specific finding arrives with a generic duplicate.** Six of the
   eight detected malicious scenarios raise the specific approval finding
   *and* the generic `PRIVILEGE_ESCALATION` finding, which is why the
   matched-finding ratio is 0.5714 (8 of 14 findings) even though scenario
   recall is 1.0000 on rule-supported scenarios. This is duplicate triage
   load, not a missed detection.
4. **Fail-closed behaviour held.** The identity-ambiguity scenario produced
   `INCONCLUSIVE` and the incomplete-coverage scenario produced
   `COVERAGE_GAP`; neither produced a `VIOLATION`. The cross-tenant approval
   did not satisfy the action — it was rejected as unapproved.
5. **Manual investigation time reduction: not measured.** No agentic
   investigation and no human-in-the-loop timing were part of this
   measurement.

### Limitations of these numbers

- **Simulated sources only.** Every event is a fixture in the dataset; no
  real tenant, approval store, identity provider or ITSM system was
  consulted.
- **Small dataset.** 16 scenarios is a point estimate with no confidence
  interval. These are not statistically meaningful benchmarks and must not
  be compared against another system's rates.
- **Not a certification.** The artifact is evidence, not a qualification, an
  audit result or a production-readiness claim.
- **Deterministic layer only.** The numbers cover
  `itsm_agent.detection.engine` only; the agentic investigation layer, the
  LangGraph workflow, adapters, persistence and messaging are not exercised
  by them.
- **In-process latency.** The timings are normalize + detect on one machine
  and say nothing about end-to-end ingestion, storage or queue latency.
- **Labelled by hand.** Labels are a human judgement on simulated fixtures;
  they are not ground truth from an incident corpus.

## Known limitations

- Simulated only; no real tenant data.
- LLM investigation optional; core detection deterministic.
- The pilot measures the deterministic detection layer only; the agentic investigation layer is not exercised by these numbers.
