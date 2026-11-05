# Security and CI gates

This document describes what the CI pipeline actually enforces, what it can
prove, and — deliberately — what it cannot. It is a companion to
`docs/production-readiness.md`, not a production-readiness claim.

## Gate map

| Gate | Job | Tooling | Blocking signal |
| --- | --- | --- | --- |
| Formatting | `lint` | Ruff | Non-zero exit |
| Static typing | `typecheck` | mypy `--strict` | Non-zero exit |
| Secret scanning | `secret-scan` | gitleaks | Any finding |
| Workflow security | `workflow-security` | zizmor (pinned action) | Findings at/above medium severity + high confidence (`advanced-security: false` makes findings fail the job) |
| Dependency review | `dependency-review` | `actions/dependency-review-action` | New dependency at/above high severity (PR only) |
| SAST | `supply-chain` | Bandit (`make sast`) | Any finding |
| Dependency audit | `supply-chain` | pip-audit (`make audit-deps`) | Any known vulnerability |
| IaC / misconfig / secret | `supply-chain` | Trivy `fs` (`vuln,misconfig,secret`) | CRITICAL/HIGH, fixed-only |
| SBOM | `supply-chain` | Trivy CycloneDX | Artifact generation failure |
| Build + compose | `build` | `docker build`, `docker compose config -q` | Build or config failure |
| Container scan | `build` | Trivy image `vuln,secret,misconfig` | CRITICAL/HIGH, fixed-only |
| DAST | `dast` | OWASP ZAP baseline | Any configured FAIL rule |
| Test suites | `unit-tests` … `scenarios` | pytest markers | Any failure; strict services mean no silent skips |
| Summary | `ci-summary` | `tools/ci_summary.py` | Missing report, any failure, or a required job that did not succeed |

`ci-summary` consumes `${{ toJSON(needs) }}` via `NEEDS_RESULTS`, so a required
job that fails without producing a JUnit artifact still fails the summary. The
PR-only `dependency-review` job and the `dast` job are allowed to be `skipped`
(on non-PR events) without failing the summary.

## DAST scope and honesty

`tools/dast.sh` runs the OWASP ZAP baseline script against
`tools/dast_target.py`:

- it composes the **real** `create_app` factory, the real security-headers
  middleware, the real HMAC ingestion boundary, and the real authenticator;
- persistence is in-memory and explicitly non-production;
- the target binds `127.0.0.1` only and the scan is passive (no attack
  payloads), bounded to one minute;
- `ci/zap-baseline.conf` fails the job only for headers the application
  actually sets, so removing a hardening header breaks CI.

It does **not** prove that the production process serves HTTP correctly, that
the database is reachable, or that authentication is correctly configured in a
deployed environment. Those remain covered (or not) by the integration and E2E
suites and by deployment qualification.

## Container hardening

- The runtime image runs as an unprivileged user (`uid 10001`).
- Compose services run with `read_only: true`, `cap_drop: [ALL]`,
  `no-new-privileges:true`, and a writable `/tmp` tmpfs only.
- Trivy scans the built image for OS/library vulnerabilities, secrets, and
  Dockerfile misconfiguration.

Verified locally:

```
docker build -t itsm-api:local-test .
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true itsm-api:local-test id
# uid=10001(itsm) gid=999(itsm) groups=999(itsm)
```

## Local parity

CI invokes the same `make` targets used locally. Before pushing, run:

```
make verify-ci
```

and, optionally, execute the workflow locally with `act`; see
`docs/ci/act-local-ci.md` for the bounded runner and its limitations.

## Known limitations

- Trivy container scanning uses a tag-based ZAP image; digest pinning of
  scanner images is a follow-up.
- The DAST lane targets an in-memory stub, not a fully wired API process.
- zizmor results are console-gated; SARIF upload to GitHub Advanced Security
  is intentionally not enabled.
- Dependency review runs on pull requests only.
- No release qualification is implied by a green pipeline; see the release
  gate in `docs/production-readiness.md`.
