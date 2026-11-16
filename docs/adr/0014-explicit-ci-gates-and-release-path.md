# ADR-0014: Explicit CI gates and a tag-triggered release path

Status: Accepted
Date: 2026-11-16

## Context

The CI pipeline had 15 required jobs and a summary gate, but several of the
guarantees a reader would assume from the job names were not actually
enforced:

- a pytest marker selection that matched nothing produced a confusing
  failure (pytest exit 5) rather than an explicit "zero tests collected"
  error, and a suite whose tests were *all skipped* was green;
- the required set was implicit — it lived in the workflow's `needs` list and
  in an argparse default (`--optional-jobs` defaulted to `dast`), so a job
  dropped from the workflow or a failure in a "required" job could be read
  two different ways;
- a required job that never ran (absent from the `needs` payload) was not
  detected at all;
- artifact retention was inherited from a repository default rather than
  declared, and the summary printed a commit SHA without proving that the
  reports it aggregated came from that commit;
- the `build` job skipped the image build and the container scan when no
  `Dockerfile` was present, and the `e2e` job never asserted that
  PostgreSQL was reachable even though a test in that suite skips itself
  when the database is down;
- there was no deployment path at all: no tag-triggered workflow, no image
  build evidence, no SBOM for a release, no recorded digest.

The standard for the pipeline is *explicit, not toy-grade*: every gate states
what it proves, every step fails loudly, no step can pass vacuously, and a
reader can tell from the workflow alone what is required for a merge.

## Decision

- **The required set is named in code.** `tools/ci_summary.py` declares
  `REQUIRED_JOBS` (all 15) and compares it against the run's `needs`
  payload. A missing job, an unexpected job, or any job that did not reach
  `success` fails the summary. `--optional-jobs` defaults to empty: DAST is
  required, and relaxing a gate is an explicit owner decision that the
  summary prints.
- **No vacuous passes.** Every test target runs a collect preflight
  (`make guard-collect`) that fails when the marker selection collects zero
  tests and records the count next to the report. The summary fails when a
  mandatory report is missing, empty, unparseable, has zero tests, has every
  test skipped, or reports more tests than were collected.
- **Service-backed suites fail closed.** Every pytest job sets
  `ITSM_TEST_STRICT=1`, and every job that starts PostgreSQL or NATS asserts
  the service is reachable before the suite runs.
- **Artifacts carry provenance.** Each report is uploaded with a stamp
  recording the commit SHA, the run id and the run attempt. The summary
  verifies the stamp, so a stale artifact cannot be presented as this run's
  evidence. The retention window is declared explicitly and printed with its
  expiry.
- **Supply-chain hygiene is explicit.** Every action is pinned to a commit
  SHA, every job declares least-privilege `permissions:` and a
  `timeout-minutes`, and main-branch runs are never cancelled.
- **A tag triggers a release path.** `.github/workflows/release.yml` checks
  out the tagged commit, proves the tag/commit binding, re-runs the same
  canonical `make` targets CI runs, builds the image, runs the same
  container scan, generates a CycloneDX SBOM, records the exact SHA and the
  image digest in the job summary, and uploads the reports and the digest as
  artifacts. Publishing to a registry is a separate, opt-in job that runs
  only when the owner has configured a registry variable and a credential,
  and it pushes the exact image that was scanned.

## Consequences

- The required set can no longer be narrowed by editing a workflow file
  alone: the workflow and `REQUIRED_JOBS` must agree.
- A skipped test is now a build failure. That is the point — a skip that
  nobody justified is indistinguishable from a test that does not exist.
- The summary is stricter, so an existing green run could turn red on the
  first run after this change if a suite had been silently skipping. That is
  a discovered gap, not a false positive.
- The release path duplicates the CI gates instead of reusing a CI verdict.
  That costs runner minutes and is the deliberate trade: a release is
  qualified by evidence for the tagged commit, not by a pointer to a run
  that happened to be green.
- The published image is the scanned image, exported and reloaded, because
  the `Dockerfile` installs a Debian package and the build is not
  bit-reproducible.

## Alternatives considered

1. **Keep DAST optional by default** (the previous behaviour). Rejected: it
   made "required" mean two different things in two documents, and the
   qualification record already treated a skipped DAST as not qualified.
2. **Reuse the CI run's verdict in the release workflow.** Rejected: a
   release must be qualified by evidence bound to the tagged commit, and a
   re-used verdict is a pointer that can outlive the evidence.
3. **Rebuild the image in the publish job instead of exporting it.**
   Rejected: the rebuild is not bit-reproducible, so the pushed image would
   not be the image that was scanned.
4. **Create the GitHub Release from the workflow.** Rejected for the
   baseline: it needs `contents: write`, which is a broader permission than
   the evidence pipeline needs. The qualification record remains the release
   evidence.
