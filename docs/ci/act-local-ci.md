# Local CI with `act` and the pre-push gate

This document defines the two local confidence layers that run **before** any
push:

1. `.githooks/pre-push` — the fast, offline gate sequence.
2. `tools/act-ci.sh` — a bounded local execution of the GitHub Actions
   workflow using [`nektos/act`](https://nektosact.com/).

Both are advisory locally. GitHub branch protection and the hosted workflow
remain the authoritative merge gate.

Research date: 2026-11-05. `act` version verified locally: `0.2.89` (the
project's current release line is `v0.2.92`; flags used here are stable).

---

## 1. Install the versioned hook

Hooks are stored in `.githooks/` so they are reviewed like any other code.
Enable them once per clone:

```sh
make hooks-install
# equivalent to:
git config core.hooksPath .githooks
```

Verify:

```sh
git config --get core.hooksPath   # -> .githooks
make verify-pre-push              # runs the gate with empty stdin
```

To uninstall:

```sh
git config --unset core.hooksPath
```

`core.hooksPath` can be absolute or relative; a relative value is resolved
from the directory where hooks run. See
[git-config: core.hooksPath](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath).

---

## 2. Pre-push hook contract

Git calls `pre-push` with two arguments — the destination remote name and
URL — and writes one line per ref to stdin:

```text
<local-ref> SP <local-object-name> SP <remote-ref> SP <remote-object-name> LF
```

Deleted refs use `(delete)` as the local ref and the all-zero object name.
A non-zero hook exit aborts the push. Source:
[githooks(5): pre-push](https://git-scm.com/docs/githooks#_pre_push).

The hook in this repository:

| Property | Behaviour |
| --- | --- |
| Stdin | Read only when stdin is not a TTY; manual runs do not block. |
| Gate order | `ruff format --check` → `ruff check` → `mypy src tests` → `pytest -m "unit or contract"` |
| Side effects | None: no Docker, PostgreSQL, NATS, simulators, network calls, or secrets. |
| Failure output | Prints the exact failing command and its exit code, then exits non-zero. |
| SAST | `make sast` (bandit, offline) runs by default when bandit is installed. `PREPUSH_SECURITY=0` disables it. |
| Dependency audit | `make audit-deps` is opt-in with `PREPUSH_AUDIT_DEPS=1` because pip-audit contacts a vulnerability service. |
| Missing optional tools | Skipped with a message; they are never allowed to break an offline run. |
| Bypass | `SKIP_PREPUSH=1` prints a loud warning and exits 0. `git push --no-verify` also bypasses any Git hook. |

Emergency bypass (visible in the warning text):

```sh
SKIP_PREPUSH=1 git push
```

Bypassing means CI becomes the first — not the second — line of defence. Do
not bypass before merging.

Why these gates: OWASP recommends SAST, secret scanning, dependency analysis,
and early commit-time checks in the pipeline; GitHub recommends secret
scanning, push protection, code scanning, and dependency review for every
repository. See the references at the end.

---

## 3. Run GitHub Actions locally with `act`

### Preconditions

- `act` on `PATH`, or `ACT_BIN=/path/to/act`.
- A reachable Docker daemon.
- The pinned runner image available locally (or network access to pull it).

```sh
make act-ci          # fast: lint + typecheck
make act-ci ACT_FULL=1
# or directly:
tools/act-ci.sh
tools/act-ci.sh --full
tools/act-ci.sh --with-secret-scan
tools/act-ci.sh --dry-run
```

### `.actrc`

The repository-level `.actrc` is intentionally minimal:

```text
-P
ubuntu-latest=catthehacker/ubuntu:act-22.04
--container-architecture
linux/amd64
--pull=false
--env-file
/dev/null
--secret-file
/dev/null
```

Why each line exists:

- `-P ubuntu-latest=catthehacker/ubuntu:act-22.04` — pins every
  `runs-on: ubuntu-latest` job to the current medium `act` image. The tag is
  published on
  [Docker Hub](https://hub.docker.com/r/catthehacker/ubuntu/tags?page=1&name=act-22.04)
  for `linux/amd64`, `linux/arm/v7`, and `linux/arm64`. For stricter
  reproducibility, replace the tag with the image digest shown by
  `docker image inspect`.
- `--container-architecture linux/amd64` — keeps runs consistent on arm64
  hosts (requires Docker API 1.41+; ignored on older daemons).
- `--pull=false` — use the local image instead of pulling on every run. This
  also makes offline runs possible once the image is cached.
- `--env-file /dev/null` and `--secret-file /dev/null` — **critical**.
  `act` defaults to `.env` and `.secrets` respectively. This repository has a
  local `.env`, so the default would silently feed local credentials into the
  runner container. Pointing both flags at `/dev/null` keeps secrets out of
  local CI. Override deliberately (and only with disposable test values) if a
  workflow truly needs non-secret inputs.

`act` parses `.actrc` files from the XDG location, `$HOME`, the invocation
directory, then CLI arguments, in that order. CLI flags therefore win. Source:
[act usage](https://nektosact.com/usage/index.html).

### Runner image

`catthehacker/ubuntu:act-22.04` is a medium image (~536 MB compressed,
`linux/amd64`). It includes the common CLI tools, but it is a Docker image,
not a GitHub-hosted VM. The `full-*` images are closer to GitHub's images but
are much larger (~19 GB uncompressed). The `micro` images are smaller and
omit many tools. Source:
[act runners](https://nektosact.com/usage/runners.html).

Pull once:

```sh
docker pull catthehacker/ubuntu:act-22.04
```

If the image cannot be pulled and is not cached, `--pull=false` makes the
failure immediate and explicit rather than a silent wait.

---

## 4. `tools/act-ci.sh` behaviour

| Mode | Jobs | Intended use |
| --- | --- | --- |
| default | `lint`, `typecheck` | Seconds-to-low-minutes pre-push confidence. |
| `--with-secret-scan` | adds `secret-scan` | Only when action/image pulls and token context are available. |
| `--full` | every job in `.github/workflows/ci.yml` | Deliberate, long-running verification. Uses an ephemeral artifact server so upload/download steps have somewhere to write. |

The script:

- verifies `act --version` and `docker info` and fails with actionable text;
- hard-bounds runtime with `timeout` (default 900 s fast, 3600 s full);
- streams output while teeing to a temp log;
- refuses to pass secrets (`--env-file /dev/null --secret-file /dev/null`);
- exits non-zero on a non-zero `act` exit, a timeout, a reported job failure,
  or fewer successful jobs than requested. A skipped job is never reported as
  success.

`ACT_OFFLINE=1` adds `--action-offline-mode`, which prevents re-fetching
actions that are already cached. It does not make a cold cache work offline.

---

## 5. What `act` proves — and what it cannot

### It can prove

- The workflow YAML parses and the job graph (`needs`) is coherent.
- Actions referenced by the workflow can be resolved/downloaded.
- `run:` steps execute in a Linux container with the tools in that image.
- Fast gates such as ruff and mypy behave as expected under a clean checkout.
- A workflow edit did not obviously break syntax or job wiring.

### It cannot prove

`act` is explicit about its incompatibilities. The following are ignored or
only partially implemented (source:
[act unsupported features](https://nektosact.com/not_supported.html)):

- `concurrency` groups and cancellation.
- `run-name`, step summaries, problem matchers, and annotations.
- The full `github` context; it is incomplete.
- Run-step cancellation.
- `job.permissions`.
- `job.timeout-minutes`.
- `job.continue-on-error`.
- `job.environment` and deployment-environment secret scoping.
- The OIDC URL used by cloud federation.
- Node availability for JavaScript actions unless the image's `PATH` includes
  it.

It also does not reproduce GitHub-hosted runner behaviour exactly: GitHub uses
fresh virtual machines, while `act` uses Docker containers (no systemd, a
different kernel/filesystem/network setup, different preinstalled software).
Service containers, privileged operations, and host networking can behave
differently. Artifact handling differs across runs, and `act` cannot validate
branch protection, required reviewers, environment approval rules, or
GitHub-hosted secrets. Source:
[act runners / differences](https://nektosact.com/usage/runners.html).

In short: `act` is a fast workflow smoke test, not a CI substitute. A green
local run does not prove the hosted run will be green.

---

## 6. Network, images, and offline use

- **First run:** needs network to pull the runner image and any actions the
  workflow uses.
- **Later runs:** `--pull=false` stops repeated image pulls; action caching
  avoids repeated downloads. `ACT_OFFLINE=1` enforces cache-only action use.
- **Air-gapped:** pre-pull `catthehacker/ubuntu:act-22.04` and warm the action
  cache on a connected host, then copy the Docker image and `~/.cache/act`
  (or the path set by `--action-cache-path`) to the offline host.
- The pre-push hook itself never needs network; `PREPUSH_AUDIT_DEPS=1` is the
  only opt-in network path.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `ERROR: 'act' not found` | Install `act` or set `ACT_BIN`. |
| `ERROR: Docker daemon is not reachable` | Start Docker; check `/var/run/docker.sock` permissions. |
| `image not found` with `--pull=false` | `docker pull catthehacker/ubuntu:act-22.04`, or temporarily run with `-p`/`--pull`. |
| `exec format error` on arm64 | The image lacks the requested architecture; keep `--container-architecture linux/amd64` (with emulation enabled) or use a native image. |
| Actions fail to download | Warm the action cache or run once without `ACT_OFFLINE=1`. |
| `ci-summary` fails in `--full` | Artifact semantics are the most fragile part of local runs; inspect the temp artifact directory and the job log. Do not treat this as hosted-CI proof. |
| A job is skipped | The script reports `INCONCLUSIVE`, not success. Investigate the `if:`/`needs:` cause. |

---

## 8. References

- `act` usage and flags: <https://nektosact.com/usage/index.html>
- `act` runners, images, `--pull`, architecture: <https://nektosact.com/usage/runners.html>
- `act` unsupported features: <https://nektosact.com/not_supported.html>
- `act` installation: <https://nektosact.com/installation/index.html>
- Git `pre-push` hook: <https://git-scm.com/docs/githooks#_pre_push>
- Git `core.hooksPath`: <https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath>
- OWASP CI/CD Security Cheat Sheet (SAST, secrets, dependency management):
  <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html>
- OWASP DevSecOps Guideline — secrets detection before commit:
  <https://owasp.org/www-project-devsecops-guideline/latest/01a-Secrets-Management>
- GitHub — security hardening for GitHub Actions:
  <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions>
- GitHub — quickstart for securing a repository (secret scanning, push
  protection, code scanning, dependency alerts):
  <https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository>
- `catthehacker/ubuntu` image tags:
  <https://hub.docker.com/r/catthehacker/ubuntu/tags>
