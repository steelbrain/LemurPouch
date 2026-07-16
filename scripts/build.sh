#!/usr/bin/env bash
# Build the LemurPouch relay for production: install portal/ deps, bundle
# the frontend with Vite, then compile the Go binary with the bundled
# assets embedded via //go:embed.
#
#   ./scripts/build.sh [go build flags...]
#
# Go env vars (GOOS, GOARCH, CGO_ENABLED, etc.) are inherited from the
# caller, so cross-compiling is just:
#
#   GOOS=linux  GOARCH=arm64 ./scripts/build.sh -o LemurPouch-linux-arm64
#   GOOS=darwin GOARCH=arm64 ./scripts/build.sh -o LemurPouch-darwin-arm64
#   GOOS=windows GOARCH=amd64 ./scripts/build.sh -o LemurPouch-windows-amd64.exe
#
# Any positional args are forwarded verbatim to `go build`, so flags like
# -o, -ldflags, and -tags work as expected. With no -o, the binary is
# written to ./LemurPouch (./LemurPouch.exe on windows GOOS).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[build] installing portal/ dependencies..."
(cd portal && npm install)

echo "[build] bundling frontend (vite build)..."
(cd portal && npm run build)
# vite empties dist/ before each build, which removes the .gitkeep sentinel
# that lets //go:embed compile from a fresh clone. Restore it.
touch portal/dist/.gitkeep

GOOS_EFFECTIVE="${GOOS:-$(go env GOOS)}"
GOARCH_EFFECTIVE="${GOARCH:-$(go env GOARCH)}"

# Default the output to ./LemurPouch unless the caller passed -o.
# (Go's default also produces ./LemurPouch from the module's last path
# segment; the explicit -o pins the binary name even if the module path
# is renamed in the future.)
has_output_flag=0
for arg in "$@"; do
  if [ "$arg" = "-o" ]; then
    has_output_flag=1
    break
  fi
done
if [ "$has_output_flag" -eq 0 ]; then
  default_name="LemurPouch"
  if [ "$GOOS_EFFECTIVE" = "windows" ]; then
    default_name="LemurPouch.exe"
  fi
  set -- -o "$default_name" "$@"
fi

echo "[build] compiling go binary (GOOS=${GOOS_EFFECTIVE} GOARCH=${GOARCH_EFFECTIVE})..."
go build "$@"

echo "[build] done."
