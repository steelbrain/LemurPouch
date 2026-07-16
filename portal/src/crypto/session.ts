// Per-friendship key derivation — AGENTS.md "End-to-End Encryption >
// Per-Friendship Shared Secret" and "Wire Protocol > Domain Separators".
//
// Once a friendship is mutually established, both peers already have
// each other's X25519 public keys (via discovery, bound to the Ed25519
// identity by sig_binding) and can derive a shared secret + a pair of
// directional 32-byte session keys without an extra round trip.
//
// Construction (both sides compute the same pair, independently):
//   shared    = X25519(my_x25519_priv, their_x25519_pub)
//   salt      = min(myEd, theirEd) || max(myEd, theirEd)        (byte-wise lex)
//   info(dir) = "LemurPouch/v1/session:" || dir                (dir = "a-to-b" or "b-to-a")
//   key(dir)  = HKDF-SHA256(shared, salt, info(dir), 32 bytes)
//
// "a-to-b" means the lex-smaller identity is the sender; "b-to-a" means
// the lex-larger identity is. Each friendship has TWO 32-byte
// directional keys so neither side has to share a nonce space with the
// other (XChaCha20-Poly1305 with random 24-byte nonces is collision-safe
// even on a single key, but separate directions are cheap insurance and
// simplify key rotation if it's ever added).

import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { SESSION_INFO } from './index'

const X25519_KEY_LEN = 32
const ED25519_KEY_LEN = 32
const SESSION_KEY_LEN = 32

export interface SessionKeys {
  // Used to encrypt frames *I* send to the peer (and to decrypt frames
  // the peer purports to have sent to me — but those are decrypted with
  // recvKey on the receiving side; see usage docs).
  sendKey: Uint8Array
  // Used to decrypt frames the peer sends to me.
  recvKey: Uint8Array
}

// deriveSessionKeys computes both directional 32-byte session keys for
// a friendship between {me, peer}. Symmetric by construction: the peer
// running the same function with their inputs gets a pair where their
// sendKey === my recvKey and vice versa.
//
// All four inputs must be exactly 32 bytes. Throws if myEd === peerEd
// (a self-friendship is not a valid construct on this protocol).
//
// Identity-key arguments (myEdPub, peerEdPub) are used only to build
// the lex-deterministic salt + direction; they are not signed and not
// fed into the ECDH itself. The X25519 keys carry the actual
// key-agreement material.
export function deriveSessionKeys(
  myX25519Priv: Uint8Array,
  peerX25519Pub: Uint8Array,
  myEd25519Pub: Uint8Array,
  peerEd25519Pub: Uint8Array,
): SessionKeys {
  requireLen('myX25519Priv', myX25519Priv, X25519_KEY_LEN)
  requireLen('peerX25519Pub', peerX25519Pub, X25519_KEY_LEN)
  requireLen('myEd25519Pub', myEd25519Pub, ED25519_KEY_LEN)
  requireLen('peerEd25519Pub', peerEd25519Pub, ED25519_KEY_LEN)

  const cmp = compareBytes(myEd25519Pub, peerEd25519Pub)
  if (cmp === 0) {
    throw new Error('session: cannot derive keys with self — myEd25519Pub === peerEd25519Pub')
  }

  // ECDH gives the per-pair shared secret. @noble/curves accepts the
  // raw 32-byte private scalar; the X25519 key clamping per RFC 7748
  // is applied internally on each call so callers can keep using the
  // unclamped raw private bytes (matches the rest of the codebase).
  const shared = x25519.getSharedSecret(myX25519Priv, peerX25519Pub)
  // Per RFC 7748, X25519 with a low-order peer point produces an
  // all-zero shared secret. sig_binding only proves the peer's Ed25519
  // signed the X25519 — it can't tell us the X25519 is actually
  // ECDH-usable. Reject here so the caller (registerFriend) can refuse
  // the friendship rather than caching keys derived from a constant.
  if (isAllZero(shared)) {
    throw new Error('session: peer X25519 is low-order; ECDH yields zero shared secret')
  }

  // Lex-deterministic salt: both peers compute the same 64-byte string
  // independently from public keys they already know.
  const lexMinFirst = cmp < 0
  const salt = new Uint8Array(ED25519_KEY_LEN * 2)
  salt.set(lexMinFirst ? myEd25519Pub : peerEd25519Pub, 0)
  salt.set(lexMinFirst ? peerEd25519Pub : myEd25519Pub, ED25519_KEY_LEN)

  // Direction string: "a-to-b" = lex-min sender, "b-to-a" = lex-max sender.
  // I am the lex-min iff cmp < 0, so my outbound direction is "a-to-b" then.
  const myOutbound = lexMinFirst ? 'a-to-b' : 'b-to-a'
  const peerOutbound = lexMinFirst ? 'b-to-a' : 'a-to-b'

  const enc = new TextEncoder()
  const sendInfo = enc.encode(SESSION_INFO + myOutbound)
  const recvInfo = enc.encode(SESSION_INFO + peerOutbound)

  return {
    sendKey: hkdf(sha256, shared, salt, sendInfo, SESSION_KEY_LEN),
    recvKey: hkdf(sha256, shared, salt, recvInfo, SESSION_KEY_LEN),
  }
}

function requireLen(name: string, b: Uint8Array, want: number): void {
  if (b.length !== want) {
    throw new Error(`session: ${name} must be ${want} bytes, got ${b.length}`)
  }
}

function isAllZero(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false
  return true
}

// compareBytes returns negative / 0 / positive a-vs-b lex comparison,
// matching what bytes.Compare does on the Go side. Equal-length inputs
// only — callers ensure that via requireLen.
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i]
  }
  return 0
}
