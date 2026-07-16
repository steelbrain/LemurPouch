# AGENTS.md

Conventions for AI agents (Claude Code, Codex, etc.) working in this repository. The Protocol Reference appendix at the bottom of this file is the source of truth for the wire format, threat model, and consent semantics — humans wanting the deep dive should read that section.

## What this is

LemurPouch ([lemurpouch.com](https://lemurpouch.com)) — a LAN file-sharing relay. Two clients open outbound WebSocket connections to a Go relay; the relay routes opaque encrypted ciphertext between them. Designed to work on the most restrictive networks (corporate firewalls, aggressive NAT) — the only thing it asks of the network is "outbound TCP works."

The Go module path is `github.com/steelbrain/LemurPouch`. The local working-directory name may still be `file-sharing/` on some checkouts (a leftover from before the project rename); leave that alone unless explicitly asked to rename it — every tool path that encodes the directory (e.g. the Claude memory directory under `~/.claude/projects/`) would also have to move.

The Protocol Reference appendix below is the source of truth for the protocol, threat model, and consent model. Any change to wire format, crypto construction, or consent semantics must cite a section there.

## Layout

```
.
├── README.md              ← user-facing pitch + run/develop instructions
├── AGENTS.md              ← this file (includes Protocol Reference appendix)
├── CLAUDE.md              ← imports AGENTS.md
├── LICENSE.md             ← MIT
├── Dockerfile             ← Linux multi-stage build → distroless runtime (see "Docker / ghcr.io")
├── Dockerfile.windows     ← Windows nanoserver image; consumes prebuilt LemurPouch.exe
├── .github/workflows/
│   ├── docker.yml         ← multi-OS manifest (linux/amd64+arm64 + windows/amd64) build/push to ghcr.io
│   └── release.yml        ← 6-cell binary matrix → workflow artifacts on main, GitHub Release on tags
├── scripts/
│   ├── dev.sh             ← runs `go run .` + `npm run dev` together with HMR
│   ├── build.sh           ← bundles frontend, then `go build` (cross-compile via GOOS/GOARCH)
│   ├── install.sh         ← curl|sh installer: downloads latest release, verifies SHA256, exec's relay
│   └── install.ps1        ← irm|iex installer for native Windows (mirrors install.sh)
├── main.go                ← CLI entry: dispatch to --serve / --connect / interactive picker / help
├── internal/
│   ├── cryptoid/          ← Ed25519 + X25519 identity, BIP-39 fingerprint
│   ├── wireproto/         ← cleartext JSON message types + binary envelope layout
│   │                        + transfer-control (transfer.go) + file-chunk (chunk.go)
│   ├── relay/             ← Hub, HandleWebSocket, friendship state machine,
│   │                        envelope routing — the relay's behavior
│   ├── client/            ← native Go protocol client: the browser-side half
│   │                        (handshake, discovery, friendship keys, messenger,
│   │                        transfer state machine), mirrored from portal/src
│   └── tui/               ← full-screen bubbletea terminal client over internal/client
└── portal/
    └── src/
        ├── crypto/        ← TS mirror of cryptoid + envelope wire + session keys + AEAD
        ├── relay/         ← WebSocket connection client + cleartext wire types
        ├── transfer/      ← envelope messenger + transfer-control + chunks + UI state
        └── App.tsx        ← React UI; everything wires together here
```

## Build & test commands

**This repo uses npm, not pnpm.** `portal/package-lock.json` is committed; there is no `pnpm-lock.yaml`. Using pnpm creates a divergent `node_modules` tree and an untracked lockfile.

```
# Go side — scoped to OUR packages (root + internal/...). Never use
# `./...`: the module root is the repo root, so `./...` descends into
# portal/node_modules/ and picks up Go source shipped by npm packages
# (e.g. `flatted/golang/pkg/flatted`), running our test/vet on
# arbitrary transitive npm code. If you ever add a new top-level Go
# directory (e.g. `cmd/foo/`, `pkg/bar/`), list it here too.
go build ./internal/... .
go test ./internal/... . -race -count=1     ← always under -race; the relay is heavily concurrent
go vet ./internal/... .

# TS side (from portal/)
npm install                       ← first time only
npm test                          ← vitest
npx tsc --noEmit                  ← strict typecheck (separate from build)
npm run build                     ← tsc -b && vite build (slower; produces dist/)
npm run lint                      ← eslint
```

`portal/dist/.gitkeep` is committed so `//go:embed` can compile against an empty dist when no production build has run. `vite build` deletes it on each run — restore with `git checkout HEAD -- portal/dist/.gitkeep` before committing.

`portal/dist/` itself is gitignored. Don't stage built assets.

The relay's `SetReadLimit` is 4 MiB (`wireproto.ReadLimit`) to fit a negotiated raw chunk up to 1 MiB plus envelope/chunk header overhead. The legacy floor remains 64 KiB. Tests that exercise the limit must send strictly more than `ReadLimit`.

## Verification before commit

For any non-trivial change, run the full triad:
1. `go test ./internal/... . -race -count=1`
2. `cd portal && npm test && npx tsc --noEmit && npm run build`
3. `go vet ./internal/... . && (cd portal && npm run lint)`

`npm run lint` is clean (exit 0, no warnings). Keep it that way — don't introduce new `no-explicit-any` or other rule violations as part of unrelated work.

## Code conventions

- **Comments:** default to none. Add one only when the WHY is non-obvious — a hidden invariant, a workaround for a bug, behavior that would surprise a reader. Don't restate WHAT the code does; well-named identifiers do that. Don't reference the current PR/task ("added for X") — that belongs in the commit message and rots in the source.
- **Error handling:** validate at system boundaries (parsers, public APIs). Don't add fallbacks for "shouldn't happen" cases inside trusted internal code. Throw / return errors at the boundary; don't silently degrade.
- **Backward-compat hacks:** none unless explicitly asked. No `_ = unused` placeholders, no re-exports for removed symbols, no `// removed` comments.
- **TypeScript gotchas:**
  - `tsconfig` has `erasableSyntaxOnly: true` — **no parameter properties** in constructors. Declare fields explicitly and assign in the body.
  - `Uint8Array` defaults to `Uint8Array<ArrayBufferLike>` (broader). DOM `BufferSource` wants `Uint8Array<ArrayBuffer>` (narrower; excludes `SharedArrayBuffer`). When passing `Uint8Array` returned from our own helpers (which are always `ArrayBuffer`-backed at runtime) to a DOM API like `WebSocket.send`, you'll need a cast.
  - Discriminated-union dispatchers must be exhaustive. The pattern in this repo is a typed `Record<Union['type'], (json: string) => Union>` dispatch table — adding a new variant without a parser entry is a TS error.
  - For switches over union types, end with `default: assertNever(x)` to make missing cases a compile error.

## Wire-protocol invariants (Go-TS interop)

The Go relay and the TS frontend share a wire format. Drift breaks interop silently. Always ensure both sides update in lockstep:

- **JSON field names** are `snake_case` (Go's `json:"…"` struct tags). TS uses snake_case on the wire and camelCase in TS interfaces; the parsers in `portal/src/relay/wire.ts` and `portal/src/transfer/control.ts` translate at the boundary.
- **`type` discriminator strings** must be byte-identical across sides. Each layer has a pinning test (e.g. `TestFriendshipJSONFieldNames` on the Go side) — add one when you add a new message type.
- **Base64** for byte fields uses RFC 4648 standard (with padding) — that's what Go's `encoding/json` does for `[]byte`. TS uses `bytesToBase64` / `base64ToBytes` from `portal/src/relay/wire.ts`.
- **Nil byte fields**: Go marshals nil `[]byte` as JSON `null`. The TS parsers must reject `null` (treat as malformed); there's a pinning test (`TestNilByteFieldsMarshalAsNull` Go-side, mirror tests TS-side).
- **Binary envelope layout** (`internal/wireproto/envelope.go` ↔ `portal/src/crypto/envelope.ts`): `[1 byte inner-type][32 byte peer key][24 byte XChaCha nonce][N byte ciphertext+tag]`. The inner-type byte is the AEAD's AAD — DO NOT include the peer field in AAD because the relay legitimately rewrites it on forward.
- **Domain separators**: `LemurPouch/v1/bind-x25519:` (binding signature) and `LemurPouch/v1/session:` (HKDF info prefix). Defined as `BIND_CONTEXT` / `SESSION_INFO` in TS and as Go constants. Changing either is a flag-day v2 bump.
- **HKDF salt**: byte-wise lex-sorted concatenation of the two raw 32-byte ed25519 pubs (`min(a,b) || max(a,b)`). Direction string is `"a-to-b"` if the lex-smaller identity is the sender, else `"b-to-a"`. Both peers compute both keys.

## What the relay does NOT do

- **Never decrypts.** The relay verifies signatures on connect; everything post-handshake on the encrypted side is opaque ciphertext. It rewrites the 32-byte peer field destination → source on forward, then ships the bytes.
- **Never replies inline to envelope frames.** Drop silently on parse / friendship-gate / write failure. Inline errors would leak routing/keying state to a probing attacker.
- **No metrics, no logs of payload content.** Connection lifecycle + structural error logs only.
- **No persistence.** All state — identities, friendships, queued invites, transfers — is in-memory and session-scoped per "Session Lifetime" (Protocol Reference, below). Restart = clean slate.

## Things never to use

- **WebRTC / RTCDataChannel / STUN / ICE / TURN** — direct peer connections fail unpredictably on restrictive networks.
- **WebTransport / HTTP/3 / QUIC / raw UDP** — UDP is blocked or broken in many enterprise environments.
- **pnpm** — see "Build & test commands" above.
- **`--no-verify`, `--no-gpg-sign`, or any other commit-hook bypass** — fix the underlying issue.

The transport is outbound TCP/WebSocket from each client to a known relay URL. That's the lowest-common-denominator thing that nearly always works.

## Branch + commit conventions

- **Branch names**: `steelbrain/<descriptive-kebab-case>`. e.g. `steelbrain/encrypted-envelopes`, `steelbrain/fix-handshake-ctx-leak`.
- **Commit subject**: ≤72 chars, present-tense imperative, optional emoji prefix from the table in the user's global `~/.claude/CLAUDE.md`. Examples: `:new:` (new feature), `:bug:` (fix), `:lock:` (review-fix-verify pass), `:art:` (refactor / structure), `:racehorse:` (perf). Omit emoji rather than force one that doesn't fit.
- **Commit body**: explain the WHY, not the WHAT. The diff shows the what.
- **Doc-only commits** include `[ci skip]` in the subject.
- **PR titles** drop the emoji prefix.
- Use HEREDOC for multi-line `git commit -m` to preserve formatting:
  ```
  git commit -m "$(cat <<'EOF'
  :new: Subject line

  Body explaining why.
  EOF
  )"
  ```

## Build-and-verify-in-small-chunks

Per the user's global instructions, the workflow is:
1. **Plan** the change as a sequence of small, independently-reviewable chunks. Validate assumptions against the actual code BEFORE writing implementation — read the files you plan to modify and their callers, confirm signatures and types exist as you expect.
2. For each chunk: write → spawn a code-review subagent → fix what the review surfaces → repeat the review at least twice (up to five rounds) → commit only after the chunk is clean.
3. Move to the next chunk.

In practice in this repo, the established pattern is one round-1 review per chunk for the foundation layers, with round-2 for layers that hit real bugs in round-1. The user has been explicit when they want to skip review rounds (e.g. "two loops instead of three"); ask if it's not clear.

## Worktrees for parallel feature work

Long-running changes (e.g. the friendship layer, the encrypted-envelope layer) live in a sibling git worktree branched off `main`:

```
git worktree add -b steelbrain/<feature-name> ../<repo-name>-<feature> main
```

The worktree gets its own checked-out branch so background subagents can work in it without disturbing the main checkout. When done:

```
git -C <main repo> merge --no-ff steelbrain/<feature-name>     # or fast-forward if linear
git -C <main repo> worktree remove ../<repo-name>-<feature>
git -C <main repo> branch -d steelbrain/<feature-name>
```

If you spawn background subagents in a worktree, do not rebase the worktree branch while they're running — it'll invalidate their working tree.

`portal/node_modules` and `portal/pnpm-lock.yaml` (if pnpm was accidentally used) are not committed, so a fresh worktree needs `npm install` in `portal/` before TS commands work.

## Background subagents for review-fix-verify

Spawn opus subagents for review-fix-verify rounds. They run in the background; you'll get a completion notification.

Brief them as if they walked into the room cold:
- which branch / worktree to work in (absolute path)
- what just landed (commit SHA + summary)
- which files to read and what specifically to look for
- explicit out-of-scope items (so they don't scope-creep)
- the verify commands they must run before committing (`go test ./internal/... . -race -count=2 -v`, `npm test`, `npx tsc --noEmit`, `npm run build`)
- the constraint to use **npm**, not pnpm
- the constraint to NEVER skip git hooks
- the request format for their final report: findings list with severity, fixed-vs-deferred, last 15 lines of each verify command, commit SHA + subject, under ~600 words

Don't auto-spawn subsequent rounds — let the human decide between rounds.

## Binary releases

`.github/workflows/release.yml` builds a 6-cell binary matrix on every push to `main`, every tag push, and every PR:

- darwin/amd64, darwin/arm64
- linux/amd64, linux/arm64
- windows/amd64, windows/arm64

All six cross-compile from `ubuntu-latest` runners with `CGO_ENABLED=0` (none of our deps need cgo). The frontend is built once in a leading `build-frontend` job and shared across all six binary cells via an artifact, so the matrix doesn't repeat npm install / vite build.

Outputs:
- **PR or push to main** → archives upload as workflow artifacts (`.tar.gz` for unix, `.zip` for windows), 90-day retention. Useful for smoke-testing before tagging.
- **Tag push (`v*`)** → the `release` job downloads all six artifacts, aggregates the per-archive `.sha256` sidecars into one `SHA256SUMS`, and publishes everything to a GitHub Release with auto-generated notes.

Archive naming: `LemurPouch-<goos>-<goarch>.{tar.gz,zip}`. Inside, the binary is just `LemurPouch` (or `LemurPouch.exe`) — the OS/arch lives in the archive name, not the binary name.

## Docker / ghcr.io

The repo ships two Dockerfiles — `Dockerfile` (Linux multi-stage: Node → Go → distroless/static) and `Dockerfile.windows` (windows/amd64, nanoserver) — and one workflow `.github/workflows/docker.yml` that publishes them as a **single unified multi-platform manifest** at `ghcr.io/<owner>/lemurpouch` (always lowercase — GHCR rejects mixed-case image names even when the GitHub repo is `LemurPouch`). `docker pull ghcr.io/<owner>/lemurpouch:latest` resolves to the right image for the host's OS+arch automatically; there is no Windows-specific tag suffix. (No windows/arm64 — Windows Server containers don't ship arm64 base images.)

Triggers and tags (same scheme for every platform under one tag):
- pushes to `main` → `:main`, `:sha-<short>`, `:latest`
- semver tags `v*` → `:X.Y.Z`, `:X.Y`, `:X`, `:latest`, `:sha-<short>`
- PRs → build-only validation; no push

Workflow shape (4 jobs):
1. `build-linux` (matrix linux/amd64 + linux/arm64, ubuntu-latest) — buildx with `outputs: type=image,push-by-digest=true,push=true`. Each cell uploads its digest as an artifact.
2. `build-windows-binary` (ubuntu-latest) — npm install + vite build + cross-compile a windows/amd64 `LemurPouch.exe`. Uploaded as artifact.
3. `build-windows-image` (windows-2022) — downloads the .exe, builds `Dockerfile.windows` with plain `docker build`, pushes to a clearly-internal `_stage-windows-amd64-<run-id>` tag, then captures the resulting digest from `docker push` output. Native Windows runner is unavoidable: Linux runners can't build Windows-base images (the Docker daemon must be in Windows-container mode, which requires a Windows host). We deliberately do NOT use `docker/setup-buildx-action` here — its default `docker-container` driver tries to boot `moby/buildkit:buildx-stable-1`, which is Linux-only and fails on a Windows host with "no matching manifest for windows/amd64". The `docker` driver would work but doesn't support `outputs: type=image,push-by-digest=true` anyway, so we'd lose the buildx benefit; plain docker + parse-digest-from-push-output is the smallest reliable shape. The `_stage-*` tags accumulate on GHCR (the merge job references the image by digest, not by this tag); delete them periodically via the GHCR package settings page.
4. `merge` (ubuntu-latest) — downloads all per-platform digests and runs `docker buildx imagetools create -t <public-tag> @sha256:linux-amd64 @sha256:linux-arm64 @sha256:windows-amd64` once per public tag. **Atomicity**: if any platform build fails, `merge` doesn't run and existing public tags keep pointing at the previous good manifest — tag updates are all-or-nothing across platforms.

The windows/amd64 cross-compile in step 2 duplicates work the `release.yml` binary matrix already does (its windows/amd64 cell ships the standalone .zip). The duplication is the price of keeping `docker.yml` self-contained; cross-workflow artifact sharing is more cost than the ~40 s of build time saved.

Local sanity test: `docker build -t LemurPouch . && docker run --rm -p 8080:8080 LemurPouch`. The relay detects containerization via the `LEMURPOUCH_IN_CONTAINER` env var, which the project's `Dockerfile` sets explicitly (`ENV LEMURPOUCH_IN_CONTAINER=1`); when set, the startup banner prints an extra hint that the enumerated interface IPs are container-internal bridge addresses, not host LAN IPs. We deliberately do NOT probe `/.dockerenv` — that would also fire for users who built a custom image around the binary or `docker cp`-ed it out and re-ran it elsewhere.

After the first GitHub Actions push, the package on ghcr.io is private by default. Make it public via the package settings page so anonymous `docker pull` works.

When changing the Linux `Dockerfile`:
- Keep the `--platform=$BUILDPLATFORM` annotations on builder stages — they keep Node and the Go toolchain native, with cross-compile via `GOOS`/`GOARCH`. Dropping them forces qemu emulation and triples build times.
- The runtime stage should stay distroless/static. It's the smallest base that gives us CA certs + a nonroot user without a shell. If you find yourself wanting `apk add` something at runtime, you're solving the wrong problem.
- `portal/dist/` in the host repo is a `.gitkeep`-only stub. The Dockerfile's `RUN rm -rf portal/dist` before `COPY --from=portal-build` is intentional — it keeps host build output (if any) from leaking into the image.

When changing `Dockerfile.windows`:
- Keep it tiny — `FROM nanoserver:ltsc2022` + `COPY LemurPouch.exe` + `ENTRYPOINT`. The .exe is cross-compiled on Linux upstream; don't try to compile Go inside a Windows container build (slow, fragile).
- Stick with `nanoserver:ltsc2022` to match the `windows-2022` runner family. Don't reach for `windowsservercore` unless we actually need Windows shared libraries — nanoserver is much smaller and our static binary doesn't need anything more.

## Browser testing

UI changes that depend on the live relay (the whole post-handshake half of the stack) need human verification. Vitest covers pure functions and the messenger / state helpers; the friendship UI and the transfer UI's two-tab click-through is exercised against a running `go run .` + `npm run dev`, not in CI. When you can't verify the UI yourself, **say so explicitly** in the commit body rather than implying it works.

## Protocol Reference

This appendix was the standalone `DESIGN.md` until 2026-05-10. The protocol is now built; the spec is preserved here as the canonical reference for the wire format, threat model, and consent semantics. In-source citations of the form `AGENTS.md "Encrypted Envelopes"` or `AGENTS.md "Wire Protocol > Domain Separators"` refer to the section headings below.

### Goal

File sharing across operating systems that works on the most restrictive networks — corporate firewalls, aggressive NATs. The transport is a LAN-resident relay server. Both clients open *outbound* WebSocket connections to the relay; no client ever needs an inbound port. The relay is also the consent gatekeeper.

### Non-Goals

- **No WebRTC, no peer-to-peer, no direct peer sockets.** Every byte of every transfer flows through the relay. Reason: P2P and STUN/ICE/TURN handshakes fail in subtle ways on restrictive networks; relay-only is the lowest-common-denominator transport that works wherever outbound TCP works.
- **No cross-session identity.** Identity is scoped to a single relay-process session — keys are generated client-side at page load and discarded on disconnect. A peer that reconnects within the same session (e.g. wifi → ethernet, brief network drop, tab refresh that re-uses the same keypair) is recognized as the same peer; a peer that re-launches and generates a fresh keypair is a different peer.
- **No persistent friendship state.** Everything is session-only.
- **No display names.** The six-word fingerprint is the only human-readable name for a peer. Local nicknames (if a client wants them) are pure client-side state, never transmitted to anyone.

### High-Level Architecture

- **Relay server**: a single deployable that runs on the LAN. Serves a static website over HTTP and exposes a WebSocket endpoint for clients. Enforces all consent gates and rate limits. After friendship is established, the relay forwards opaque ciphertext envelopes it cannot read.
- **Browser clients**: each device opens the relay's URL; the page *is* the daemon. This is still the default client.
- **Native TUI client** (`internal/client` + `internal/tui`, launched via `LemurPouch --connect URL`): a full-screen terminal client that speaks the identical protocol with far less memory/CPU than the browser. `internal/client` is a Go mirror of the `portal/src` client logic; any wire-format change must update both. It is not a background daemon — it runs only while the TUI is open, and identity is still session-scoped.
- **Transport**: outbound WebSocket from each client to the relay. JSON for unencrypted control messages; binary frames for encrypted peer-to-peer payloads.

### Identity

A peer's identity = `ed25519_pub`.

The relay also observes each peer's source IP and ephemeral port and surfaces them in the discovery row, but those are *metadata*, not identity. They drive UI display (so two daemons sharing one LAN-IP are visually distinguishable) and per-IP rate limiting (see [Anti-Abuse](#anti-abuse-per-ip-rate-limiting)). They do NOT participate in identity comparisons: a single Ed25519 key reconnecting from a new IP is still the same peer.

Each peer holds two session-lifetime keypairs, generated client-side once per session and never rotated:

- **Ed25519 identity keypair** — authenticates the peer to the relay and binds its X25519 key to the identity. Renders as the six-word fingerprint that humans verify out-of-band.
- **X25519 key-agreement keypair** — used for end-to-end encryption with other peers. Reused across every friendship in the session; ECDH gives a unique shared secret per peer pair, so reuse doesn't leak across friendships. See [End-to-End Encryption](#end-to-end-encryption).

#### Connection Handshake

On WebSocket connect:

1. Relay sends a random nonce.
2. Client sends `{ed25519_pub, x25519_pub, sig_liveness, sig_binding}`, where:
   - `sig_liveness = sign_ed25519(nonce)` — proves possession of `ed25519_priv` for this connection.
   - `sig_binding = sign_ed25519(<bind-context>, x25519_pub)` — binds `x25519_pub` to the Ed25519 identity. The `<bind-context>` is a fixed domain-separator string (exact value finalized in the wire-protocol pass) so the signature can't be replayed in a different protocol context. Because `sig_binding` doesn't depend on a per-connection nonce, the relay can forward it to other peers via discovery, and they can verify the binding locally.
3. Relay verifies both signatures and either registers a fresh identity or matches the connection back to an existing identity from this session.

#### Reconnect Rules

- Same `ed25519_pub` (proven via `sig_liveness`) → same identity, regardless of source IP or port. The newer connection wins; the relay closes the older one with a policy-violation close-frame so the displaced client can surface a "session replaced" notice. This is what lets a peer disappear (network drop, wifi → ethernet roam, tab refresh) and come back as the same peer to everyone they've befriended.
- Different `ed25519_pub` → different identity by definition.

The trust root is the six-word fingerprint of `ed25519_pub`, verified out-of-band (see [MITM Resistance](#mitm-resistance)). Anyone who possesses the Ed25519 private key *is* the identity, by construction; pinning identity to source IP would not strengthen this — an attacker who has the key can also be on any network — and would break the legitimate roam/reconnect case.

All identities are session-scoped; cleared when the relay restarts or the peer disconnects (and no other connection holds the same key).

#### Fingerprint (Friendly Name)

The Ed25519 public key renders as a six-word fingerprint for human verification:

```
hash    = SHA-256(ed25519_pub)
bits    = first 66 bits of hash
indices = split bits into 6 × 11-bit chunks
words   = [BIP39_LIST[i] for i in indices]
display = "abandon-ladder-quantum-tribe-yellow-velvet"
```

- 66 bits of fingerprint entropy → preimage attack is computationally prohibitive.
- BIP-39 wordlist (2048 words of common English). Chosen over PGP wordlist (8 bits/word — would need 9 words for equivalent strength) and Diceware (vocabulary slightly rougher).
- Both peers see and read each other's fingerprint to verify they're talking to the device they think they are. This human verification is what roots the entire end-to-end trust chain.

#### Pre-Friendship Visibility

Before any friendship is established, a peer's discovery row contains:

- **IP**
- **Ephemeral source port** (disambiguates two daemons on the same IP)
- **`ed25519_pub`** (rendered as the six-word fingerprint in the UI)
- **`x25519_pub`**
- **`sig_binding`** (lets recipients verify the X25519 key belongs to the Ed25519 identity, locally)

No other metadata, no other signals.

### End-to-End Encryption

Once a friendship is established, all peer-to-peer messages — transfer offers, accept/reject decisions, file bytes, and any future messaging — are encrypted end-to-end. The relay routes opaque ciphertext envelopes; it never sees content or application-level metadata.

#### Threat Model

**Encrypted from the relay (opaque):**

- Transfer offers (filename, size, hashes, any other metadata)
- Accept/reject of transfer offers
- File bytes
- Any future peer-to-peer messaging

**Necessarily visible to the relay:**

- Source and destination *identities* — routing requires them.
- Approximate traffic volume and timing — bytes through the relay are bytes the relay sees.
- Friendship-handshake control bits (invite, accept, reject) — the relay enforces consent and rate-limit semantics on these and so must distinguish them.

Volume/timing analysis is not defended against in v0; traffic padding could be layered on later if needed.

#### Per-Friendship Shared Secret

When a friendship is mutually established, both peers already have everything they need — the X25519 keys were exchanged via discovery and bound to identities by `sig_binding`, so no separate key-exchange step is required:

- `shared = X25519(my_x25519_priv, their_x25519_pub)` — a unique value per peer pair, even though each peer's X25519 key is reused across all of its friendships.
- Per-friendship session keys derived via **HKDF-SHA256** from `shared`, with directional keys (one for A→B, one for B→A) to avoid nonce collision.
- Exact info-string and salt construction is deferred to the wire-protocol pass.

There is no in-session ratcheting. One derived key pair per friendship, used until the friendship ends.

#### Encrypted Envelope

Every post-friendship payload is wrapped:

```
{
  from: <identity>,
  to:   <identity>,
  ciphertext: XChaCha20-Poly1305(payload, key=..., nonce=random_24_bytes)
}
```

The relay routes by `(from, to)` and forwards `ciphertext` byte-for-byte.

**Cipher choice: XChaCha20-Poly1305.** The 192-bit nonce makes random nonces safe with no birthday-bound concerns, simplifying the protocol. Fast in pure JS via `@noble/ciphers`, well-vetted, and the server doesn't need any cipher implementation because it never decrypts.

#### MITM Resistance

The trust chain ends at human eyeballs:

1. Humans verify the six-word fingerprint of `ed25519_pub` out-of-band (visually on screen, or read aloud).
2. The fingerprint authenticates the Ed25519 identity key.
3. `sig_binding` proves the X25519 key belongs to that same identity.
4. ECDH on those X25519 keys derives the per-friendship session secret.

A malicious or compromised relay cannot break this chain without forging an Ed25519 signature, which is computationally infeasible. The only failure mode is humans skipping the fingerprint check.

### Consent Model

Two tiers of consent before any file bytes flow.

#### Tier 1: Friendship

- Sender selects a target peer from the discovery list (recognizing them by fingerprint) and sends an *invite*. The invite carries no payload — it is pure consent: `{type: "invite", to: <recipient_identity>}`.
- Recipient accepts → friendship is established for the session. Both peers immediately compute the shared secret and derive session keys (the X25519 keys were already bound to identities at discovery time, so no separate key-exchange step is needed).
- Friendship is symmetric: either side can subsequently send transfer offers.
- Friendship is session-only and not persisted across relay restarts or disconnects.

#### Tier 2: Per-Transfer

- Even between friends, every individual transfer offer must be explicitly accepted by the recipient.
- A transfer offer carries `(filename, size)` — encrypted to the recipient. The relay forwards an opaque ciphertext envelope. Bytes only start flowing after the recipient sends an (also encrypted) accept.

### Anti-Abuse: Per-IP Rate Limiting

The IP, not the socket and not the identity, is the abuse-budget anchor. Identity is session-scoped and easy to churn, but a bad actor can't easily change their LAN IP. Per-IP limits:

- **At most one pending friendship invite per `(sender_IP, recipient)` pair.**
- Further invites from that IP to that recipient *queue*.
- If the first invite is **accepted** → the next queued invite surfaces to the recipient normally.
- If the first invite is **rejected** → the next queued invite is **auto-rejected** and dropped into a per-recipient log. The recipient can review the log and opt-in to accept invites from that IP, which unblocks subsequent invites.
- Multiple daemons on the same IP each get their own keypair, identity, and fingerprint. They share the IP's abuse budget but operate independently — legitimate multi-device households are not punished, but identity churn buys an attacker nothing.

### Transfer Flow (Sequence)

1. Both clients open the relay URL → outbound WebSocket connection.
2. Relay sends nonce; clients send `(ed25519_pub, x25519_pub, sig_liveness, sig_binding)`. Relay verifies and registers `ed25519_pub` → identity (with source IP/port observed for display and rate-limiting metadata only — see [Identity](#identity)).
3. Each client appears in the other's discovery list (IP, port, `ed25519_pub`, `x25519_pub`, `sig_binding`). Clients verify `sig_binding` locally on receipt.
4. Sender → relay → recipient: friendship invite (consent only, no payload).
5. Recipient → relay → sender: friendship accept. Both sides immediately derive `shared = X25519(...)` and session keys via HKDF.
6. Sender encrypts a transfer offer `(filename, size)` and sends it inside an envelope. Relay forwards ciphertext byte-for-byte.
7. Recipient decrypts, accepts (or rejects), encrypts the response, sends it back through the relay.
8. On accept, the sender streams encrypted file chunks; the relay forwards opaque ciphertext frames.
9. Either side can disconnect; transfer state and friendship are torn down.

### Session Lifetime

All state — identities, friendships, queued invites, rejection logs, in-flight transfers — is held in relay memory and cleared when the relay restarts or when the relevant peer disconnects.

### Tech Stack

#### Server (the relay)

- **Language**: Go.
- **WebSocket library**: `coder/websocket` — modern API, actively maintained, better than the older `gorilla/websocket`.
- **Crypto**: `crypto/ed25519` from the standard library for signature verification only. The relay never decrypts payload ciphertext, so no symmetric or KEM crypto is needed server-side.
- **Static asset serving**: Go's `embed` package — the built frontend is compiled directly into the binary at release time.
- **Deployment**: a single static binary, cross-compiled to macOS / Linux / Windows. No runtime dependencies, no separate web server.

#### Frontend (the browser client)

- **Framework**: React + TypeScript.
- **Build tool**: Vite.
- **Crypto libraries** (all from the `@noble/*` family — small, audited, pure JS, same author):
  - `@noble/ed25519` — Ed25519 keygen + signing.
  - `@noble/curves` — X25519 keygen + ECDH.
  - `@noble/ciphers` — XChaCha20-Poly1305 + HKDF-SHA256.
- **Wordlist**: BIP-39 English, used to render six-word fingerprints from `SHA-256(ed25519_pub)`.

#### Development Workflow

- The Go relay runs on `localhost:8080` (HTTP for any control endpoints + WebSocket at `/ws` on the same port).
- Vite's dev server runs on its default port (5173) with HMR.
- Vite is configured to proxy `/ws` (and any future API paths) to `localhost:8080`, so the browser sees a single origin while we keep HMR.

#### Production Workflow

- `vite build` produces a static `dist/` directory.
- The Go binary embeds `dist/` via `//go:embed` and serves it at `/`.
- The WebSocket endpoint lives at `/ws` on the same port.
- Result: one binary, no separate frontend deploy.

### Wire Protocol

The relay-client wire uses two WebSocket frame types:

- **Text frames (JSON)** for *cleartext* control: handshake, discovery, friendship, errors. Easy to debug and evolve.
- **Binary frames** for *encrypted* peer-to-peer envelopes — file bytes especially. Avoids the ~33% base64 tax on transfer throughput.

All `<base64>` fields are RFC 4648 standard base64 (with padding) of the raw bytes.

#### Domain Separators

To prevent signatures and derived keys from being misused across protocol contexts, fixed string prefixes are used:

- **Binding signature**: `sig_ed25519("LemurPouch/v1/bind-x25519:" || x25519_pub)` — included in every peer's discovery row so others can verify the X25519 key is bound to the Ed25519 identity.
- **HKDF salt**: `min(ed25519_pub_A, ed25519_pub_B) || max(ed25519_pub_A, ed25519_pub_B)` — byte-wise lex order of the two raw 32-byte keys. Both peers derive the same salt independently from public keys they already know.
- **HKDF info**: `"LemurPouch/v1/session:" || direction`, where `direction` is `"a-to-b"` if the lex-smaller identity is the sender, else `"b-to-a"`. Each friendship has two 32-byte directional session keys; both peers compute both.

#### Cleartext Control (text frames, JSON)

A `<peer-record>` is shorthand for:

```json
{
  "ed25519_pub": "<base64-32>",
  "x25519_pub":  "<base64-32>",
  "sig_binding": "<base64-64>",
  "ip":          "192.168.1.42",
  "port":        54321
}
```

##### Connection handshake

```json
// Server → Client on connect
{ "type": "challenge", "nonce": "<base64-32>" }

// Client → Server
{
  "type":         "identify",
  "ed25519_pub":  "<base64-32>",
  "x25519_pub":   "<base64-32>",
  "sig_liveness": "<base64-64>",
  "sig_binding":  "<base64-64>"
}

// Server → Client on success
{ "type": "welcome", "you": <peer-record> }

// Server → Client on failure (any cleartext exchange)
{ "type": "error", "code": "<...>", "message": "<...>" }
```

##### Discovery

```json
{ "type": "peer-list",   "peers": [<peer-record>, ...] }
{ "type": "peer-joined", "peer":  <peer-record> }
{ "type": "peer-left",   "ed25519_pub": "<base64-32>" }
```

##### Friendship handshake

Pure consent — no payload beyond the target identity. Recipients identify the sender by matching `from` against their discovery list (where the fingerprint is rendered).

```json
// Client → Server
{ "type": "invite", "to": "<base64-32>" }
{ "type": "accept", "to": "<base64-32>" }
{ "type": "reject", "to": "<base64-32>" }

// Server → Client (forwarding to the recipient)
{ "type": "invite-from", "from": "<base64-32>" }
{ "type": "accept-from", "from": "<base64-32>" }
{ "type": "reject-from", "from": "<base64-32>" }

// Server → Client (queue/log signals back to the sender or recipient)
{ "type": "invite-deferred",      "from": "<base64-32>" }   // your queued invite is now active
{ "type": "invite-auto-rejected", "from": "<base64-32>" }   // first invite was rejected; this one logged
```

#### Encrypted Envelopes (binary frames)

Every binary frame has the layout:

```
[ 1 byte  ] inner type        (0x01 = JSON control, 0x02 = file chunk)
[ 32 bytes] peer ed25519_pub  (destination on c2s; relay rewrites to source on s2c)
[ 24 bytes] XChaCha20-Poly1305 nonce  (random per frame)
[ N bytes ] ciphertext + 16-byte Poly1305 tag
```

Each frame carries a fresh random 24-byte nonce — XChaCha20's 192-bit nonce makes random nonces safe (no birthday-bound bookkeeping). The relay never decrypts, only rewrites the 32-byte peer field from "destination" to "source" before forwarding to the recipient.

The AEAD's additional authenticated data (AAD) is the single inner-type byte that prefixes the frame. This binds the type to the ciphertext: a tampering relay (or anything else in the path) cannot flip `0x01` ↔ `0x02` to confuse the recipient about how to interpret the plaintext without breaking the auth tag. The 32-byte peer field is *not* in the AAD because the relay legitimately rewrites it on forward; tampering there is detected indirectly via per-pair session keys (a wrongly-routed envelope decrypts under a key the recipient doesn't share with the supposed sender, so the AEAD fails).

The plaintext is interpreted based on the leading inner-type byte:

##### Inner type `0x01` — JSON control (UTF-8)

```json
{
  "type":        "transfer-offer",
  "transfer_id": "<base64-16>",
  "filename":    "...",
  "size":        <bytes>
}

{ "type": "transfer-accept", "transfer_id": "<base64-16>" }
{ "type": "transfer-reject", "transfer_id": "<base64-16>", "reason": "<optional>" }
{ "type": "transfer-end",    "transfer_id": "<base64-16>", "sha256": "<base64-32>" }
```

The `sha256` rides on `transfer-end`, not `transfer-offer`: both peers hash
the payload incrementally as it streams (sender as it sends, recipient as it
receives), so the digest only exists once the last chunk has gone out. This
lets the sender ship the offer without first reading and hashing the whole
file, and lets the recipient verify with a cheap `digest()` finalize the
moment the last byte lands instead of a second full pass over the assembled
bytes. The check is still end-to-end integrity only — per-chunk Poly1305
already authenticates each frame against a tampering relay.

##### Inner type `0x02` — file chunk (binary)

```
[ 16 bytes] transfer_id
[ 4 bytes ] seq (uint32 big-endian)
[ 1 byte  ] flags  (bit 0 = last chunk)
[ N bytes ] raw file data       (negotiated size, floor 64 KiB)
```

The receiver writes chunks in `seq` order, buffering out-of-order arrivals. Multiple concurrent transfers between the same pair are supported by distinct `transfer_id`s; the relay never inspects them.

Receivers bound `seq` by `ceil(totalBytes / 64 KiB)` so larger negotiated chunks always validate. The negotiated raw chunk size never goes below 64 KiB.

#### Flow Control & Negotiated Limits

Additive, negotiated capabilities so multi-gig transfers stay reliable without breaking older clients:

- **`welcome.limits.max_chunk_bytes`** (optional): largest raw chunk-data size the relay will forward (default advertise: 1 MiB). Absent on old relays ⇒ clients treat as 64 KiB. The relay's `SetReadLimit` is larger (4 MiB) to cover envelope overhead.
- **`transfer-accept` optional fields** `max_chunk_bytes` and `window_bytes`: receiver capacity. Absent ⇒ legacy 64 KiB chunks, unwindowed streaming (status quo).
- **Effective chunk size**: `min(sender preference, relay max ?? 64Ki, accept max ?? 64Ki)`, floored at 64 KiB. Any advertised value below 65536 is treated as 65536.
- **Effective window**: when `window_bytes` is present, `max(window_bytes, 2 × chunk)` so one outstanding chunk cannot deadlock. Default window: 8 MiB.
- **`transfer-ack`** (new inner-0x01 type): `{type:"transfer-ack", transfer_id, received_bytes}` — cumulative, monotonic receiver→sender progress. Receiver emits when `received − lastAcked ≥ window/4`. Old senders drop unknown 0x01 types silently.
- **Windowed sender**: only when accept carried `window_bytes`, block while `sent − lastAck ≥ window`; abort with reason `"flow-control stall"` after 30 s without ack progress. Unwindowed (old accept) never waits on acks.
- **Version mixes**: new↔new = windowed + negotiated chunks; any side missing the new fields degrades to 64 KiB unwindowed streaming.

Cipher, hash, envelope layout, and domain separators are unchanged (no v2).

#### Transfer Lifecycle

1. Sender mints `transfer_id = random(16 bytes)`.
2. Sender sends `transfer-offer` (inner 0x01) inside an encrypted envelope.
3. Recipient sends `transfer-accept` or `transfer-reject` (inner 0x01).
4. On accept: sender streams chunks (inner 0x02) with monotonic `seq` from 0, folding each chunk into a running SHA-256; the chunk with `flags & 1` is the last.
5. Sender sends `transfer-end` (inner 0x01), carrying the finalized SHA-256, after the last chunk. The recipient compares it against its own incremental digest of the received bytes.
6. If the connection drops or the recipient detects gaps, the partial file is discarded.

#### What the Relay Enforces

- **Connect**: signature verification of `identify` (`sig_liveness` over the challenge nonce; `sig_binding` over `bind-x25519:` + `x25519_pub`).
- **Discovery**: pushes the live peer list, including each peer's `sig_binding` so clients can locally verify the X25519 binding without trusting the relay.
- **Friendship**: per-(sender_IP, recipient) invite gate — at most one active pending invite, others queue or land in the rejection log per the consent model.
- **Envelope routing**: rewrites the 32-byte peer field (destination → source) and forwards. Drops envelopes for which the (sender, recipient) pair has no active friendship.

#### v0 Non-Goals (Wire Protocol)

- **Protocol version negotiation.** Strings are pinned to `v1`; future incompatible changes will be a `v2` flag day.
- **Compression.**
- **Replay protection.** The threat model treats the relay as honest-but-curious on a LAN; defending against an active replay attacker is deferred until we leave LAN.

### Open Questions

The following are not yet decided and need a separate pass:

- **Resumable transfers** — out of scope for v0; revisit if needed.
- **TLS** — out of scope for v0 since the relay is LAN-only; revisit when the project grows beyond LAN.
- **Native background daemons** — a native *interactive* client now exists (the `--connect` TUI, see "High-Level Architecture"), but a headless/background daemon with OS integration and presence remains out of scope for v0.
