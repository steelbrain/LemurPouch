#!/bin/sh
# install.sh — Install LemurPouch, then launch the interactive picker.
#
# Usage:
#   curl -fsSL https://lemurpouch.com/install.sh | sh
#   curl -fsSL https://lemurpouch.com/install.sh | sh -s -- --serve
#   curl -fsSL https://lemurpouch.com/install.sh | sh -s -- --serve --listen 0.0.0.0:9000
#   curl -fsSL https://lemurpouch.com/install.sh | sh -s -- --connect http://HOST:8080/
#
# Default (no args): run bare LemurPouch → Start a relay / Connect to a relay.
# Re-runs are idempotent: download skipped if the binary already exists.
# Set LP_FORCE=1 to re-download.

set -eu

REPO="steelbrain/LemurPouch"
BINARY_NAME="LemurPouch"

# --- Platform detection -----------------------------------------------------

case "$(uname -s)" in
    Linux)                os="linux";   archive_ext="tar.gz" ;;
    Darwin)               os="darwin";  archive_ext="tar.gz" ;;
    MINGW*|MSYS*|CYGWIN*) os="windows"; archive_ext="zip"; BINARY_NAME="LemurPouch.exe" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
asset="LemurPouch-${os}-${arch}.${archive_ext}"

# --- Install location -------------------------------------------------------
#
# ~/.local/bin is the XDG convention for user-installed executables and is on
# PATH in most modern shells, so the binary is runnable as `LemurPouch`
# afterward (on every OS — macOS no longer hides it under Application Support).

install_dir="$HOME/.local/bin"
bin_path="$install_dir/$BINARY_NAME"

# --- Download + extract -----------------------------------------------------

if [ -e "$bin_path" ] && [ -z "${LP_FORCE:-}" ]; then
    echo "Found existing binary at $bin_path"
    echo "(Set LP_FORCE=1 to re-download.)"
else
    mkdir -p "$install_dir"

    tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t LemurPouch)
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM

    archive_path="$tmp_dir/$asset"
    sums_path="$tmp_dir/SHA256SUMS"
    base_url="https://github.com/${REPO}/releases/latest/download"

    if command -v curl >/dev/null 2>&1; then
        fetch() { curl -fSL "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then
        fetch() { wget -O "$2" "$1"; }
    else
        echo "Need either curl or wget to download the release." >&2
        exit 1
    fi

    echo "Downloading ${asset}"
    fetch "${base_url}/${asset}" "$archive_path"

    echo "Verifying checksum"
    fetch "${base_url}/SHA256SUMS" "$sums_path"
    expected=$(awk -v f="$asset" '$2==f || $2=="*"f { print $1 }' "$sums_path")
    if [ -z "$expected" ]; then
        echo "Could not find $asset in SHA256SUMS." >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$archive_path" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$archive_path" | awk '{print $1}')
    else
        echo "Need sha256sum or shasum to verify the download." >&2
        exit 1
    fi
    if [ "$expected" != "$actual" ]; then
        echo "Checksum mismatch for $asset" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi

    echo "Extracting to $install_dir"
    if [ "$archive_ext" = "zip" ]; then
        command -v unzip >/dev/null 2>&1 || {
            echo "Required command 'unzip' not found. Install it and re-run." >&2
            exit 1
        }
        unzip -o -q "$archive_path" -d "$install_dir"
    else
        tar -xzf "$archive_path" -C "$install_dir"
    fi

    rm -rf "$tmp_dir"
    trap - EXIT INT TERM

    chmod +x "$bin_path"

    # macOS Gatekeeper marks files downloaded by curl/wget with the
    # com.apple.quarantine xattr; stripping it lets the binary run without
    # the "cannot be opened" prompt. No-op on systems without xattr.
    if [ "$os" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
        xattr -dr com.apple.quarantine "$bin_path" 2>/dev/null || true
    fi
fi

echo ""
echo "Installed at: $bin_path"
echo ""

# --- Launch -----------------------------------------------------------------
#
# Under curl|sh stdin is the script pipe, so interactive modes reattach
# /dev/tty when available. Default is bare LemurPouch (TTY → picker).
# Explicit --serve / --connect / --listen are forwarded; bare --listen
# (legacy install docs) implies --serve.

wants_connect=0
wants_serve=0
has_listen=0
for arg in "$@"; do
    case "$arg" in
        --connect) wants_connect=1 ;;
        --serve)   wants_serve=1 ;;
        --listen)  has_listen=1 ;;
    esac
done

# Preserve `sh -s -- --listen :9000` from older docs (used to auto-inject --serve).
if [ "$has_listen" -eq 1 ] && [ "$wants_serve" -eq 0 ] && [ "$wants_connect" -eq 0 ]; then
    set -- --serve "$@"
    wants_serve=1
fi

# --serve is non-interactive: no TTY required.
if [ "$wants_serve" -eq 1 ]; then
    echo "Starting the LemurPouch relay (Ctrl-C to stop)..."
    echo ""
    exec "$bin_path" "$@"
fi

# Picker (no mode flags) or --connect need a real terminal.
if (exec </dev/tty) 2>/dev/null; then
    if [ "$wants_connect" -eq 1 ]; then
        echo "Starting LemurPouch client (Ctrl-C to stop)..."
    else
        echo "Starting LemurPouch (choose relay or client)..."
    fi
    echo ""
    exec "$bin_path" "$@" </dev/tty
fi

echo "Installed. No controlling TTY available for interactive mode."
if [ "$#" -gt 0 ]; then
    echo "Run: $bin_path $*"
else
    echo "Run: $bin_path"
    echo "  (interactive picker: Start a relay / Connect to a relay)"
    echo "  or: $bin_path --serve"
    echo "  or: $bin_path --connect http://HOST:8080/"
fi
echo ""
exit 0
