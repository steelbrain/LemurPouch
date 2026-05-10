<p align="center">
  <a href="https://lemurpouch.com">
    <img src="web/public/logo.png" alt="LemurPouch" width="160" height="160">
  </a>
</p>

# [LemurPouch](https://lemurpouch.com)

LAN file sharing that works on the most restrictive networks — corporate firewalls, aggressive NAT — by asking the network for the one thing it nearly always allows: outbound TCP.

You run a single relay binary on the LAN. Everyone else opens its URL in a browser. No app to install, no inbound ports, no WebRTC, no STUN/ICE/TURN, no UDP. Two browsers connect outbound to the relay, verify each other by a six-word fingerprint, and exchange end-to-end encrypted files that the relay routes byte-for-byte without ever decrypting.

## Install

Downloads the latest release, verifies its SHA256 against the release's `SHA256SUMS`, drops it into your platform's per-user data directory, and runs it.

**macOS / Linux:**

```sh
curl -fsSL https://lemurpouch.com/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://lemurpouch.com/install.ps1 | iex
```

See [One-line install](#one-line-install) below for the install path, idempotency, and how to pass relay flags.

## Why

Existing sharing tools assume a permissive network. AirDrop wants peer discovery the corporate Wi-Fi has filtered. WebRTC wants a STUN server, a TURN fallback, and ports the firewall isn't going to open. WeTransfer wants to leave the building.

LemurPouch assumes nothing except outbound TCP, which is the lowest common denominator. If your browser can load the relay's page, file transfer works.

## How it works

- **One relay, two clients.** Run the relay on any host reachable on the LAN. Both browsers open the relay's URL.
- **Identity is a six-word fingerprint.** Each browser session generates an Ed25519 keypair, rendered as `abandon-ladder-quantum-tribe-yellow-velvet`. Humans verify it out of band (read it aloud, compare on screen) — that's what roots the trust chain.
- **End-to-end encrypted, relay-opaque.** X25519 + HKDF-SHA256 derives per-friendship session keys; XChaCha20-Poly1305 seals every payload. The relay verifies signatures on connect, then routes opaque ciphertext envelopes it cannot read.
- **Two-tier consent.** First a friendship invite (per-IP rate-limited to defeat invite spam), then a per-transfer accept on every individual file.
- **Session-only state.** Identities, friendships, transfers — all in relay memory. Restart = clean slate. No persistence, no payload logs, no metrics.

The full protocol, threat model, and wire format live in the [Protocol Reference appendix of AGENTS.md](AGENTS.md#protocol-reference).

## Run it

### One-line install

The binary lives at:

| Platform | Path                                                         |
|----------|--------------------------------------------------------------|
| Linux    | `${XDG_DATA_HOME:-$HOME/.local/share}/lemur-pouch/lemur-pouch` |
| macOS    | `~/Library/Application Support/lemur-pouch/lemur-pouch`      |
| Windows  | `%LOCALAPPDATA%\lemur-pouch\lemur-pouch.exe`                 |

Re-running the script is idempotent — the download is skipped if the binary is already there. Set `LP_FORCE=1` (or `$env:LP_FORCE='1'`) to overwrite.

To pass relay flags ([see Bind address](#bind-address)), append them after `sh -s --`:

```sh
curl -fsSL https://lemurpouch.com/install.sh | sh -s -- --listen 0.0.0.0:9000
```

To pass flags on Windows, save the script first:

```powershell
irm https://lemurpouch.com/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 --listen 0.0.0.0:9000
```

### Docker

```sh
docker run --rm -p 8080:8080 ghcr.io/steelbrain/lemur-pouch:latest
```

Then open `http://<your-LAN-IP>:8080/` on each device. (The image sets `LEMURPOUCH_IN_CONTAINER=1`, so the relay knows to print a hint that the IPs it enumerates are container-internal and you should use the host's LAN IP instead.)

The image is a unified multi-platform manifest spanning `linux/amd64`, `linux/arm64`, and `windows/amd64` — one tag, three OS+arch images, Docker picks the right one for the host. (No `windows/arm64` because Windows Server containers don't ship arm64 base images.) Published on every push to `main` and on every `vX.Y.Z` tag.

### Pre-built binary

Each tagged release publishes a static binary for every common platform on the [Releases page](https://github.com/steelbrain/lemur-pouch/releases). The frontend is embedded in the binary; no separate install needed.

| Platform      | Archive                              |
|---------------|--------------------------------------|
| macOS amd64   | `lemur-pouch-darwin-amd64.tar.gz`    |
| macOS arm64   | `lemur-pouch-darwin-arm64.tar.gz`    |
| Linux amd64   | `lemur-pouch-linux-amd64.tar.gz`     |
| Linux arm64   | `lemur-pouch-linux-arm64.tar.gz`     |
| Windows amd64 | `lemur-pouch-windows-amd64.zip`      |
| Windows arm64 | `lemur-pouch-windows-arm64.zip`      |

Verify a download with `sha256sum --ignore-missing -c SHA256SUMS` (or `shasum -a 256 --ignore-missing -c` on macOS) against the `SHA256SUMS` file from the same release — `--ignore-missing` skips entries for archives you didn't download. Then unpack and run `./lemur-pouch` (`lemur-pouch.exe` on Windows).

### From source

Requirements: Go 1.25+, Node 24+, npm.

```sh
./scripts/build.sh        # bundle frontend + compile relay → ./lemur-pouch
./lemur-pouch             # listens on :8080 by default
```

`build.sh` forwards positional args to `go build`, so cross-compiling is straightforward:

```sh
GOOS=linux   GOARCH=arm64 ./scripts/build.sh -o lemur-pouch-linux-arm64
GOOS=darwin  GOARCH=arm64 ./scripts/build.sh -o lemur-pouch-darwin-arm64
GOOS=windows GOARCH=amd64 ./scripts/build.sh -o lemur-pouch-windows-amd64.exe
```

### Bind address

```sh
./lemur-pouch --listen :8080             # all interfaces (default)
./lemur-pouch --listen 127.0.0.1:8080    # localhost only
./lemur-pouch --listen 192.168.1.5:80    # one specific NIC
```

On startup the relay enumerates and prints every URL it's reachable at, so you can paste one into a chat without digging through `ifconfig`.

## Troubleshooting

### Docker container is unreachable from other LAN devices on OrbStack (macOS)

OrbStack does not expose Docker-published ports on the Mac's LAN interface. Regardless of `-p 0.0.0.0:8080:8080` or `--net=host`, OrbStack's port proxy binds only to `127.0.0.1` on the host, so other devices on the Wi-Fi can't reach `http://<your-mac-LAN-IP>:8080/`. This is by design — see [orbstack/orbstack#291](https://github.com/orbstack/orbstack/issues/291) — and there is no setting to change it.

Workarounds:

- **Run the binary directly** (`./lemur-pouch` or `./scripts/dev.sh`) instead of in Docker. The relay binds dual-stack on `:8080` and is reachable on every LAN interface. This is the right shape for actual LAN use; Docker is for deployment, not local sharing.
- **Use Docker Desktop or `colima`** instead of OrbStack — both publish ports on `0.0.0.0` of the host, so LAN devices can hit the Mac's IP.

Linux Docker hosts are unaffected.

## Develop

```sh
./scripts/dev.sh
```

Runs the Go relay on `:8080` and Vite on `:5173` with HMR. Vite proxies `/ws` to the Go relay, so the browser sees a single origin. Ctrl-C tears both down.

Manual equivalents:

```sh
go run .                    # relay on :8080
cd web && npm install       # first time only
cd web && npm run dev       # vite on :5173
```

### Tests & checks

```sh
go test ./internal/... . -race -count=1
go vet ./internal/... .
cd web && npm test
cd web && npx tsc --noEmit
cd web && npm run build
cd web && npm run lint
```

(`./...` is avoided because npm packages can ship Go source under `web/node_modules/`, and `./internal/... .` keeps the tooling scoped to our actual packages.)

The relay is heavily concurrent — always run Go tests under `-race`.

## Layout

```
.
├── AGENTS.md              ← agent conventions + Protocol Reference appendix (the deep dive)
├── main.go                ← relay entry point
├── internal/
│   ├── cryptoid/          ← Ed25519 + X25519 identity, BIP-39 fingerprint
│   ├── wireproto/         ← cleartext JSON message types + binary envelope layout
│   └── relay/             ← Hub, friendship state machine, envelope routing
└── web/
    └── src/
        ├── crypto/        ← TS mirror of cryptoid + envelope wire + AEAD + HKDF
        ├── relay/         ← WebSocket client + cleartext wire types
        ├── transfer/      ← envelope messenger + transfer control + chunks + UI state
        └── App.tsx        ← React UI
```

## What the relay is not

- **Not a peer.** It never decrypts a payload. It verifies signatures on connect, gates friendship consent, then forwards opaque ciphertext.
- **Not a logger.** Connection lifecycle and structural errors only — no payload content, no metrics.
- **Not persistent.** Restart wipes every identity, friendship, and queued invite. By design.
- **Not WebRTC, not P2P, not UDP.** See [AGENTS.md § Non-Goals](AGENTS.md#non-goals) for why.

## License

[MIT](LICENSE.md) © 2026 Anees Iqbal
