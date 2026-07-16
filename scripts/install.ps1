# install.ps1 — Install LemurPouch, then launch the interactive picker.
#
# Usage:
#   irm https://lemurpouch.com/install.ps1 | iex
#   powershell -File .\install.ps1 --serve
#   powershell -File .\install.ps1 --connect http://HOST:8080/
#
# Default (no args): run bare LemurPouch.exe → Start a relay / Connect.
# Re-runs are idempotent: download skipped if the binary already exists.
# Set $env:LP_FORCE='1' to re-download.
# Note: `irm | iex` cannot forward args — use download-then-run for flags.

$ErrorActionPreference = 'Stop'

$Repo       = 'steelbrain/LemurPouch'
$BinaryName = 'LemurPouch.exe'

# --- Platform detection -----------------------------------------------------

# PROCESSOR_ARCHITECTURE reflects the *current process* — under a 32-bit
# process on 64-bit Windows it'll be "x86" with ARCHITEW6432="AMD64". Prefer
# the override so we always pick the OS-native binary.
$rawArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$osArch = switch -Regex ($rawArch) {
    '^(AMD64|x86_64)$' { 'amd64'; break }
    '^ARM64$'          { 'arm64'; break }
    default { throw "Unsupported Windows architecture: $rawArch" }
}

$Asset    = "LemurPouch-windows-$osArch.zip"
$BaseUrl  = "https://github.com/$Repo/releases/latest/download"

# --- Install location (~/.local/bin = per-user, no admin needed) ------------
#
# Mirrors the Unix installer: ~/.local/bin under the user's home directory.

$InstallDir = Join-Path $HOME '.local\bin'
$BinPath    = Join-Path $InstallDir $BinaryName

# --- Download + extract -----------------------------------------------------

if ((Test-Path -LiteralPath $BinPath) -and -not $env:LP_FORCE) {
    Write-Host "Found existing binary at $BinPath"
    Write-Host "(Set `$env:LP_FORCE='1' to re-download.)"
} else {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "LemurPouch-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    try {
        $tmpZip   = Join-Path $tmpDir $Asset
        $sumsPath = Join-Path $tmpDir 'SHA256SUMS'

        Write-Host "Downloading $Asset"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "$BaseUrl/$Asset"      -OutFile $tmpZip   -UseBasicParsing

        Write-Host 'Verifying checksum'
        Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS"  -OutFile $sumsPath -UseBasicParsing
        $expected = $null
        foreach ($line in Get-Content $sumsPath) {
            $parts = $line -split '\s+', 2
            if ($parts.Length -eq 2) {
                # GNU sha256sum may prefix the filename with '*' in binary mode.
                $name = $parts[1].TrimStart('*').Trim()
                if ($name -eq $Asset) { $expected = $parts[0]; break }
            }
        }
        if (-not $expected) {
            throw "Could not find $Asset in SHA256SUMS."
        }
        $actual = (Get-FileHash -Path $tmpZip -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected.ToLower()) {
            throw "Checksum mismatch for ${Asset}: expected $expected, got $actual"
        }

        Write-Host "Extracting to $InstallDir"
        Expand-Archive -Path $tmpZip -DestinationPath $InstallDir -Force
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Strip the Mark-of-the-Web (Zone.Identifier ADS) Expand-Archive carries
    # over from the downloaded zip — Windows' equivalent of macOS Gatekeeper
    # quarantine. Without this, SmartScreen may flag the binary on first run.
    Unblock-File -Path $BinPath
}

Write-Host ''
Write-Host "Installed at: $BinPath"
Write-Host ''

# Default: bare binary → interactive picker (TTY). Explicit --serve /
# --connect / --listen are forwarded. Bare --listen (legacy docs) implies
# --serve. Note: `irm | iex` cannot forward args — use download-then-run.
$launchArgs = @($args)
$wantsConnect = $launchArgs -contains '--connect'
$wantsServe = $launchArgs -contains '--serve'
$hasListen = $launchArgs -contains '--listen'
if ($hasListen -and -not $wantsServe -and -not $wantsConnect) {
    $launchArgs = @('--serve') + $launchArgs
    $wantsServe = $true
}

if ($wantsServe) {
    Write-Host 'Starting the LemurPouch relay (Ctrl-C to stop)...'
    Write-Host ''
} elseif ($wantsConnect) {
    Write-Host 'Starting LemurPouch client (Ctrl-C to stop)...'
    Write-Host ''
} else {
    Write-Host 'Starting LemurPouch (choose relay or client)...'
    Write-Host ''
}

& $BinPath @launchArgs
exit $LASTEXITCODE
