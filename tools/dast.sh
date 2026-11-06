#!/usr/bin/env bash
# Isolated OWASP ZAP baseline scan against the deterministic DAST target.
#
#   tools/dast.sh
#
# Scope contract:
#   - The target is tools/dast_target.py: the real app factory and middleware
#     with in-memory fakes. It is NOT the production server.
#   - The target binds 127.0.0.1 only. No public/Internet target is scanned.
#   - Passive baseline scan only (no attack payloads), bounded to 1 minute.
#
# Exit codes mirror zap-baseline.py: 0 clean, 1 FAIL rule matched, other errors
# propagate. A missing Docker binary is a hard failure, never a silent skip.

set -eu

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT="${DAST_PORT:-8010}"
TARGET="http://127.0.0.1:${PORT}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
REPORTS_DIR="${REPO_ROOT}/reports"
LOG_FILE="${REPORTS_DIR}/dast-target.log"

command -v docker >/dev/null 2>&1 || {
  echo "dast: docker is required but not installed" >&2
  exit 3
}
command -v curl >/dev/null 2>&1 || {
  echo "dast: curl is required but not installed" >&2
  exit 3
}

# The ZAP image may run as an unprivileged user; the bind-mounted reports
# directory must be writable by it or the scan aborts with EACCES.
mkdir -p "$REPORTS_DIR"
chmod 0777 "$REPORTS_DIR"

cleanup() {
  if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "dast: starting deterministic target on ${TARGET}"
DAST_PORT="$PORT" uv run python tools/dast_target.py >"$LOG_FILE" 2>&1 &
TARGET_PID=$!

ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 "${TARGET}/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "dast: target exited before becoming ready; log follows:" >&2
    cat "$LOG_FILE" >&2
    exit 3
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "dast: target did not become ready within 60s; log follows:" >&2
  cat "$LOG_FILE" >&2
  exit 3
fi

echo "dast: running ZAP baseline (passive, 1 minute spider)"
set +e
docker run --rm \
  --network host \
  -v "${REPO_ROOT}/ci/zap-baseline.conf:/zap/config/zap-baseline.conf:ro" \
  -v "${REPORTS_DIR}:/zap/wrk:rw" \
  "$ZAP_IMAGE" \
  zap-baseline.py \
  -t "$TARGET" \
  -c /zap/config/zap-baseline.conf \
  -i \
  -m 1 \
  -r /zap/wrk/zap-report.html \
  -J /zap/wrk/zap-report.json
ZAP_EXIT=$?
set -e

echo "dast: ZAP exit code ${ZAP_EXIT} (0=clean, 1=FAIL rule, 2=warn only, 3=error)"
exit "$ZAP_EXIT"
