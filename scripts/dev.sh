#!/usr/bin/env bash
# Run the Go relay and the Vite dev server together for local development.
#
#   ./scripts/dev.sh
#
# Re-runs `npm install` in portal/ first (idempotent). Streams labeled output
# from both servers. Ctrl-C tears everything down.

set -euo pipefail
set +m  # quiet bash's "Terminated: 15" job-control notifications on cleanup

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[dev] installing portal/ dependencies..."
(cd portal && npm install)

# Bounded to a process tree we own so we never touch processes that
# just happen to be on :8080 / :5173 (e.g. another dev shell the user
# already had running when this one started).
kill_tree() {
  local sig=$1 pid=$2
  local child
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    kill_tree "$sig" "$child"
  done
  kill "-$sig" "$pid" 2>/dev/null || true
}

cleanup() {
  trap - INT TERM EXIT
  echo
  echo "[dev] shutting down..."
  local pid
  for pid in "${RELAY_SUBSHELL:-}" "${VITE_SUBSHELL:-}"; do
    [[ -n "$pid" ]] && kill_tree TERM "$pid"
  done
  # Give them a moment to exit gracefully.
  sleep 0.5
  for pid in "${RELAY_SUBSHELL:-}" "${VITE_SUBSHELL:-}"; do
    [[ -n "$pid" ]] && kill_tree KILL "$pid"
  done
  wait 2>/dev/null || true
  echo "[dev] done."
  exit 0
}
trap cleanup INT TERM EXIT

prefix() {
  local label="$1"
  awk -v label="$label" '{ printf "[%s] %s\n", label, $0; fflush() }'
}

echo "[dev] starting relay (:8080) and vite (:5173). Ctrl-C to stop."

(go run . --serve 2>&1 | prefix "relay") &
RELAY_SUBSHELL=$!
(cd portal && npm run dev 2>&1 | prefix "vite") &
VITE_SUBSHELL=$!

wait
