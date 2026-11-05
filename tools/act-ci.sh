#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Bounded local GitHub Actions runner using `act`.
#
# Default: run the fast CI jobs (lint, typecheck) from .github/workflows/ci.yml.
# --full : run every job in that workflow (heavier; includes service-backed
#          jobs and the artifact-summary job).
#
# Safety properties:
#   * validates `act` and the Docker daemon before doing anything;
#   * never passes real secrets: --env-file/--secret-file point at /dev/null;
#   * the only network use is action/image pulls performed by act itself;
#   * runtime is bounded by `timeout` when available;
#   * reports failure or an inconclusive run instead of claiming success.
#
# This script does NOT replace CI. See docs/ci/act-local-ci.md for the exact
# fidelity limits of local `act` runs.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

WORKFLOW=".github/workflows/ci.yml"
FULL=0
WITH_SECRET_SCAN=0
DRY_RUN=0
ARTIFACT_DIR=""
TIMEOUT_SECONDS=${ACT_TIMEOUT:-900}
ACT_EVENT=${ACT_EVENT:-push}

usage() {
    cat <<'USAGE'
Usage: tools/act-ci.sh [options]

Options:
  --full                Run every job in .github/workflows/ci.yml.
                        Default is the fast jobs: lint + typecheck.
  --with-secret-scan    Add the secret-scan job to the fast set. It requires
                        action/image pulls and a usable GITHUB_TOKEN context,
                        so it is opt-in.
  --timeout SECONDS     Wall-clock bound (default: 900 fast, 3600 full).
  --dry-run             Validate the workflow without creating containers.
  -h, --help            Show this help.

Environment:
  ACT_BIN               Path/name of the act binary (default: `act`, then
                        $HOME/bin/act).
  ACT_TIMEOUT           Default timeout in seconds.
  ACT_EVENT             Event to simulate (default: push).
  ACT_OFFLINE=1         Pass --action-offline-mode (use cached actions only).
  ACT_FULL=1            Convenience alias used by `make act-ci`.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --full)
            FULL=1
            TIMEOUT_SECONDS=${ACT_TIMEOUT:-3600}
            ;;
        --with-secret-scan)
            WITH_SECRET_SCAN=1
            ;;
        --timeout)
            shift
            if [ "$#" -eq 0 ]; then
                echo "ERROR: --timeout requires a number of seconds." >&2
                exit 2
            fi
            TIMEOUT_SECONDS=$1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ "${ACT_FULL:-0}" = "1" ]; then
    FULL=1
    TIMEOUT_SECONDS=${ACT_TIMEOUT:-3600}
fi

# --- Preconditions ---------------------------------------------------------

if [ ! -f "$WORKFLOW" ]; then
    echo "ERROR: workflow not found: $REPO_ROOT/$WORKFLOW" >&2
    exit 1
fi

ACT_BIN=${ACT_BIN:-}
if [ -z "$ACT_BIN" ]; then
    if command -v act >/dev/null 2>&1; then
        ACT_BIN=$(command -v act)
    elif [ -x "${HOME}/bin/act" ]; then
        ACT_BIN="${HOME}/bin/act"
    else
        echo "ERROR: 'act' not found." >&2
        echo "       Install it: https://nektosact.com/installation/index.html" >&2
        echo "       Or set ACT_BIN=/path/to/act." >&2
        exit 127
    fi
fi

if ! ACT_VERSION_OUTPUT=$("$ACT_BIN" --version 2>&1); then
    echo "ERROR: '$ACT_BIN --version' failed:" >&2
    echo "$ACT_VERSION_OUTPUT" >&2
    exit 127
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed or not on PATH." >&2
    echo "       act needs a Docker daemon to create runner containers." >&2
    exit 127
fi

if ! DOCKER_VERSION=$(docker info --format '{{.ServerVersion}}' 2>/dev/null); then
    echo "ERROR: Docker daemon is not reachable." >&2
    echo "       Start Docker, or check permissions on /var/run/docker.sock." >&2
    exit 1
fi

# --- Build the act invocation ---------------------------------------------

ACT_ARGS=("$ACT_EVENT" -W "$WORKFLOW")
EXPECTED_JOBS=0

if [ "$FULL" -eq 1 ]; then
    ARTIFACT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/act-artifacts.XXXXXX")
    ACT_ARGS+=(--artifact-server-path "$ARTIFACT_DIR")
    # Count unique job IDs in the workflow so a skipped job is not reported
    # as success. `act -l` column 2 is the job ID.
    EXPECTED_JOBS=$("$ACT_BIN" -l -W "$WORKFLOW" 2>/dev/null \
        | awk 'NR > 1 && NF >= 2 {print $2}' | sort -u | wc -l | tr -d ' ')
else
    FAST_JOBS=(lint typecheck)
    if [ "$WITH_SECRET_SCAN" -eq 1 ]; then
        FAST_JOBS+=(secret-scan)
    fi
    for job in "${FAST_JOBS[@]}"; do
        ACT_ARGS+=(-j "$job")
    done
    EXPECTED_JOBS=${#FAST_JOBS[@]}
fi

# No repository secrets or .env values, ever. act defaults to .env/.secrets;
# these explicit flags override that default and keep local credentials out.
ACT_ARGS+=(--env-file /dev/null --secret-file /dev/null)

if [ "${ACT_OFFLINE:-0}" = "1" ]; then
    ACT_ARGS+=(--action-offline-mode)
fi

if [ "$DRY_RUN" -eq 1 ]; then
    ACT_ARGS+=(-n)
fi

# --- Run with a hard wall-clock bound -------------------------------------

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN=$(command -v timeout)
fi

run_act() {
    if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" --signal=INT --kill-after=30 "${TIMEOUT_SECONDS}s" \
            "$ACT_BIN" "$@"
    else
        echo "WARNING: 'timeout' not found; running without a hard bound." >&2
        "$ACT_BIN" "$@"
    fi
}

LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/act-ci.XXXXXX.log")
KEEP_LOG=0

cleanup() {
    if [ "$KEEP_LOG" -ne 1 ]; then
        rm -f "$LOG_FILE"
    fi
    if [ -n "$ARTIFACT_DIR" ]; then
        rm -rf "$ARTIFACT_DIR"
    fi
}
trap cleanup EXIT

printf '==============================================================\n'
printf 'act local CI\n'
printf '  act:      %s\n' "$ACT_VERSION_OUTPUT"
printf '  docker:   %s\n' "$DOCKER_VERSION"
printf '  workflow: %s\n' "$WORKFLOW"
printf '  event:    %s\n' "$ACT_EVENT"
if [ "$FULL" -eq 1 ]; then
    printf '  mode:     full (%s expected job(s))\n' "$EXPECTED_JOBS"
else
    printf '  mode:     fast (jobs: %s)\n' "${FAST_JOBS[*]}"
fi
printf '  timeout:  %ss\n' "$TIMEOUT_SECONDS"
printf '  secrets:  disabled (--env-file /dev/null --secret-file /dev/null)\n'
printf '==============================================================\n\n'

set +e
run_act "${ACT_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
STATUS=${PIPESTATUS[0]}
set -e

SUCCEEDED=$(grep -c 'Job succeeded' "$LOG_FILE" 2>/dev/null || true)
FAILED_JOBS=$(grep -c 'Job failed' "$LOG_FILE" 2>/dev/null || true)
SUCCEEDED=${SUCCEEDED:-0}
FAILED_JOBS=${FAILED_JOBS:-0}

printf '\n==============================================================\n'
printf 'act summary\n'
printf '  jobs requested: %s\n' "$EXPECTED_JOBS"
printf '  jobs succeeded: %s\n' "$SUCCEEDED"
printf '  jobs failed:    %s\n' "$FAILED_JOBS"
printf '  act exit code:  %s\n' "$STATUS"

if [ "$STATUS" -eq 124 ]; then
    KEEP_LOG=1
    printf '  result:         FAIL — timed out after %ss\n' "$TIMEOUT_SECONDS"
    printf '==============================================================\n'
    exit 124
fi

if [ "$STATUS" -ne 0 ]; then
    KEEP_LOG=1
    printf '  result:         FAIL — act returned a non-zero exit code\n'
    printf '  log:            %s\n' "$LOG_FILE"
    printf '==============================================================\n'
    exit "$STATUS"
fi

if [ "$FAILED_JOBS" -ne 0 ]; then
    KEEP_LOG=1
    printf '  result:         FAIL — act reported failed job(s)\n'
    printf '  log:            %s\n' "$LOG_FILE"
    printf '==============================================================\n'
    exit 1
fi

if [ "$SUCCEEDED" -lt "$EXPECTED_JOBS" ]; then
    KEEP_LOG=1
    printf '  result:         INCONCLUSIVE — only %s of %s job(s) succeeded\n' \
        "$SUCCEEDED" "$EXPECTED_JOBS"
    printf '                  (a skipped or unexecuted job is not success)\n'
    printf '  log:            %s\n' "$LOG_FILE"
    printf '==============================================================\n'
    exit 1
fi

printf '  result:         PASS — all requested jobs succeeded\n'
printf '==============================================================\n'
exit 0
