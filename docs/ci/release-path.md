# The release path

`.github/workflows/release.yml` is the deployment path for a version tag. It
is deliberately **separate from CI**: it does not reuse a CI run's verdict,
it re-runs the canonical verification commands against the tagged commit.

- Trigger: a push of a `vMAJOR.MINOR.PATCH` tag, or `workflow_dispatch` with
  an existing tag name.
- It never runs against a floating branch head: the job checks out the
  **tagged commit** and proves the checkout is the commit the tag points at.

---

## 1. The three jobs

### `verify` — canonical verification of the tagged commit

1. Checks out the repository and `git checkout --detach refs/tags/<tag>`.
2. Fails unless the tag matches `^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`.
3. Fails unless `git rev-parse HEAD` equals
   `git rev-parse refs/tags/<tag>^{commit}`.
4. Records the **exact commit SHA**, the tag and the run id in the job
   summary and in `reports/release-commit.txt`.
5. Starts the same simulators CI uses (PostgreSQL service, NATS container,
   Mockoon container), waits for them, and applies the migrations.
6. Runs **the same canonical commands CI runs**, with the same thresholds:

   | Command | CI job | Threshold |
   | --- | --- | --- |
   | `make format-check` | `lint` | non-zero exit |
   | `make lint` | `lint` | non-zero exit |
   | `make typecheck` | `typecheck` | non-zero exit |
   | `make sast` | `supply-chain` | bandit finding |
   | `make audit-deps` | `supply-chain` | known vulnerability |
   | Trivy `fs` scan | `supply-chain` | CRITICAL/HIGH, fixable only |
   | `make test-unit` | `unit-tests` | any failure |
   | `make test-contract` | `contract-tests` | any failure |
   | `make test-security` | `security-invariants` | any failure |
   | `make test-integration` | `integration-tests` | any failure |
   | `make test-fault-injection` | `fault-injection-tests` | any failure |
   | `make test-scenarios` | `scenarios` | any failure |
   | `make test-e2e` | `e2e-tests` | any failure |

7. Runs `tools/ci_summary.py` over the produced reports with
   `--no-require-needs` (job conclusions are not applicable inside a single
   job) to prove the evidence set is complete, non-vacuous, and bound to this
   commit.
8. Uploads the reports as the `release-verification-reports` artifact.

### `build` — build, scan, record the digest

1. Re-checks out the tagged commit and re-proves the tag/commit binding.
2. `docker build -t itsm-agent:<tag> .` — a missing `Dockerfile` is an
   explicit error.
3. Runs the **same container scan CI runs**: Trivy with `vuln,secret,misconfig`
   scanners, `vuln-type: os,library`, `severity: CRITICAL,HIGH`,
   `ignore-unfixed: true`, `exit-code: 1`.
4. Generates a CycloneDX **image** SBOM (`reports/sbom-image.cyclonedx.json`)
   in addition to the source SBOM.
5. Records the commit SHA and the image digest in `reports/image-digest.txt`
   and in the job summary:

   ```text
   sha=<commit>
   tag=<tag>
   image=itsm-agent
   image_digest=sha256:<config digest>
   ```

6. Exports the image archive so the publish step pushes **exactly the image
   that was scanned**, and uploads the reports, the digest and the archive as
   the `release-image` artifact.

### `publish` — opt-in, and only the scanned image

This job is **skipped unless the owner configures a registry**:

| Setting | Kind | Meaning |
| --- | --- | --- |
| `RELEASE_REGISTRY` | repository **variable** | registry host, e.g. `ghcr.io` |
| `RELEASE_REGISTRY_USER` | repository variable | registry user (defaults to the repository owner) |
| `RELEASE_REGISTRY_TOKEN` | repository **secret** | credential with push access |

Setting the variable is what unlocks the job's `packages: write` permission.
The credential is checked in the first step, which **fails loudly** when the
variable is set but the secret is not.

The job loads the exported image, tags it for the registry, pushes it, and
records the **registry manifest digest** in `reports/registry-digest.txt` and
in the job summary.

---

## 2. Publishing is opt-in, by design

- With no `RELEASE_REGISTRY` variable, the `publish` job is skipped and
  **nothing is pushed anywhere**. The release is then evidence-only: the
  verification and the scanned image exist as artifacts of the run.
- No new secret is required by the baseline. `RELEASE_REGISTRY_TOKEN` is
  referenced only by the opt-in path; while it is unset, the reference
  resolves to an empty string.
- The baseline does not create a GitHub Release. That would require
  `contents: write`, and the qualification record in
  [`../release-qualification.md`](../release-qualification.md) is the
  repository's release evidence today. Adding it is an owner decision.

## 3. Deploy by digest, never by a floating tag

A portfolio deployment pulls the **digest** recorded by the run, not a tag:

```sh
# The manifest digest, recorded in the job summary and in the
# release-registry-digest artifact.
docker pull ghcr.io/OWNER/itsm-agent@sha256:<manifest digest>

# Or pin by the local config digest when the image was never pushed:
docker pull ghcr.io/OWNER/itsm-agent@sha256:<config digest>
```

Two digests are recorded, and they are not the same thing:

| Digest | Where it comes from | What it identifies |
| --- | --- | --- |
| config digest (`docker image inspect --format '{{.Id}}'`) | the built image | the image configuration and its layers |
| manifest digest (`RepoDigests`) | the registry, after a push | the manifest the registry serves |

A tag (`v0.1.0`) is a mutable pointer. The digest is not.

## 4. Reproducing the release path locally

The release path runs the same `make` targets as CI, so:

```sh
# 1. Canonical verification against the tagged commit
git checkout --detach refs/tags/v0.1.0
make compose-up
make verify-ci
make audit-deps
make compose-down

# 2. Build, scan and record the digest
docker build -t itsm-agent:local .
trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 itsm-agent:local
trivy image --format cyclonedx --output reports/sbom-image.cyclonedx.json itsm-agent:local
docker image inspect itsm-agent:local --format '{{.Id}}'

# 3. Check the evidence set
python3 tools/ci_summary.py --reports reports --sha "$(git rev-parse HEAD)" \
  --run-id local --run-attempt 1 --retention-days 30 --no-require-needs
```

## 5. What the release path does not prove

- It does not prove a *deployment* works: nothing here starts the composed
  stack against the released image.
- It does not create a registry entry unless the owner opts in.
- The SBOM is generated by Trivy over the image and the source tree; it is
  not signed and no attestation is produced.
- The image build is **not bit-reproducible** — the `Dockerfile` installs a
  Debian package, whose version can change between builds. This is why the
  publish step pushes the exported, scanned image rather than rebuilding it.
