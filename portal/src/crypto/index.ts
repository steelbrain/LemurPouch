// Identity and end-to-end encryption primitives for the LemurPouch relay's
// wire protocol. See AGENTS.md "Identity", "End-to-End Encryption", and
// "Wire Protocol". The TypeScript-side mirror of internal/cryptoid in Go;
// shared test vectors in *.test.ts ensure both sides stay in lock-step.

import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { wordlist } from '@scure/bip39/wordlists/english.js'

// Domain-separator strings — must be byte-identical to the Go side.
// See AGENTS.md "Wire Protocol > Domain Separators".
export const BIND_CONTEXT = 'LemurPouch/v1/bind-x25519:'
export const SESSION_INFO = 'LemurPouch/v1/session:'

// Sentinel-check the BIP-39 English wordlist at module load. If a future
// build mishap or import substitutes a different list, fingerprints would
// silently drift; better to fail loudly here.
if (
  wordlist.length !== 2048 ||
  wordlist[0] !== 'abandon' ||
  wordlist[2047] !== 'zoo'
) {
  throw new Error(
    'cryptoid: BIP-39 wordlist is not the canonical English list — fingerprints depend on it',
  )
}

export interface Identity {
  ed25519Priv: Uint8Array // 32-byte seed (matches @noble's representation)
  ed25519Pub: Uint8Array // 32 bytes
  x25519Priv: Uint8Array // 32 bytes
  x25519Pub: Uint8Array // 32 bytes
}

export function generateIdentity(): Identity {
  // @noble/curves v2 dropped utils.randomPrivateKey(); generate raw bytes
  // and let getPublicKey handle RFC 7748 clamping internally for X25519.
  const ed25519Priv = randomBytes(32)
  const x25519Priv = randomBytes(32)
  return {
    ed25519Priv,
    ed25519Pub: ed25519.getPublicKey(ed25519Priv),
    x25519Priv,
    x25519Pub: x25519.getPublicKey(x25519Priv),
  }
}

// SignLiveness signs the relay's connection-time nonce, proving possession
// of the Ed25519 private key for this connection.
export function signLiveness(id: Identity, nonce: Uint8Array): Uint8Array {
  requireUint8Array('id.ed25519Priv', id.ed25519Priv)
  requireUint8Array('nonce', nonce)
  if (nonce.length === 0) throw new Error('cryptoid: nonce must be non-empty')
  return ed25519.sign(nonce, id.ed25519Priv)
}

// VerifyLiveness checks a peer's nonce signature against their Ed25519 pub.
// Returns false (without throwing) on malformed inputs.
export function verifyLiveness(
  ed25519Pub: Uint8Array,
  nonce: Uint8Array,
  sig: Uint8Array,
): boolean {
  if (ed25519Pub.length !== 32) return false
  try {
    // zip215:false matches Go's stdlib ed25519.Verify, which follows strict
    // RFC 8032. @noble/curves defaults to zip215:true, which would accept
    // non-canonical signatures the Go side rejects — letting a malicious
    // peer wedge the two implementations into a split view. Pinning the
    // option explicitly also defends against a future @noble minor that
    // flips the default.
    return ed25519.verify(sig, nonce, ed25519Pub, { zip215: false })
  } catch {
    return false
  }
}

const TEXT_ENCODER = new TextEncoder()

// SignBinding produces the signature that ties this identity's X25519 pub
// to its Ed25519 identity. Forwarded to other peers via discovery so they
// can verify the binding locally.
export function signBinding(id: Identity): Uint8Array {
  requireUint8Array('id.ed25519Priv', id.ed25519Priv)
  requireUint8Array('id.x25519Pub', id.x25519Pub)
  const msg = concat(TEXT_ENCODER.encode(BIND_CONTEXT), id.x25519Pub)
  return ed25519.sign(msg, id.ed25519Priv)
}

// VerifyBinding checks that x25519Pub is bound to ed25519Pub by sig.
// Returns false on malformed inputs (lengths must be 32 bytes each).
export function verifyBinding(
  ed25519Pub: Uint8Array,
  x25519Pub: Uint8Array,
  sig: Uint8Array,
): boolean {
  if (ed25519Pub.length !== 32 || x25519Pub.length !== 32) return false
  const msg = concat(TEXT_ENCODER.encode(BIND_CONTEXT), x25519Pub)
  try {
    // See verifyLiveness for the rationale on zip215:false.
    return ed25519.verify(sig, msg, ed25519Pub, { zip215: false })
  } catch {
    return false
  }
}

// SharedSecret computes X25519(my_priv, peer_pub).
export function sharedSecret(
  id: Identity,
  peerX25519Pub: Uint8Array,
): Uint8Array {
  requireUint8Array('id.x25519Priv', id.x25519Priv)
  requireUint8Array('peerX25519Pub', peerX25519Pub)
  return x25519.getSharedSecret(id.x25519Priv, peerX25519Pub)
}

// Thrown by friendshipKeys when peer == self. Friending self is a
// programming bug; failing loudly is better than silently producing
// degenerate keys.
export class SelfFriendshipError extends Error {
  constructor() {
    super('cryptoid: cannot derive friendship keys with self')
    this.name = 'SelfFriendshipError'
  }
}

// Thrown by friendshipKeys when peerEd25519Pub is not exactly 32 bytes.
// Mirrors Go's ErrInvalidEd25519PubKey: catching the malformed input at
// the API boundary surfaces a clear error here, rather than letting the
// wrong-length bytes flow into HKDF and producing keys the peer's correct
// implementation can't reproduce — which would surface much later as an
// inscrutable AEAD authentication failure at decrypt time.
export class InvalidEd25519PubKeyError extends Error {
  constructor() {
    super('cryptoid: peer ed25519 pub must be 32 bytes')
    this.name = 'InvalidEd25519PubKeyError'
  }
}

// Thrown by friendshipKeys when peerX25519Pub is malformed: not 32 bytes,
// or a low-order point that @noble's x25519.getSharedSecret rejects with
// "invalid private or public key received". Surfaces a typed boundary
// error callers can `instanceof`-discriminate, instead of leaking
// noble's RangeError / generic Error from deep inside the call stack.
export class InvalidX25519PubKeyError extends Error {
  constructor() {
    super('cryptoid: peer x25519 pub is malformed')
    this.name = 'InvalidX25519PubKeyError'
  }
}

export interface FriendshipKeyPair {
  sendKey: Uint8Array // 32 bytes — used to encrypt to peer
  recvKey: Uint8Array // 32 bytes — used to decrypt from peer
}

// FriendshipKeys derives the two directional session keys for the friendship
// between this identity and peer. Both peers compute the same pair; whichever
// is "send" or "recv" from each side's perspective is determined by the lex
// order of the two Ed25519 public keys (AGENTS.md "Wire Protocol > Domain
// Separators").
//
// Throws:
//   - InvalidEd25519PubKeyError if peerEd25519Pub is not exactly 32 bytes.
//   - InvalidX25519PubKeyError if peerX25519Pub is not 32 bytes, or is a
//     low-order point that @noble's x25519 rejects.
//   - SelfFriendshipError if peerEd25519Pub equals id.ed25519Pub.
//   - Error("cryptoid: <field> must be a Uint8Array") if any byte-array
//     argument or required Identity field is not a Uint8Array (e.g. a
//     JSON-deserialized Identity).
export function friendshipKeys(
  id: Identity,
  peerEd25519Pub: Uint8Array,
  peerX25519Pub: Uint8Array,
): FriendshipKeyPair {
  requireUint8Array('id.ed25519Pub', id.ed25519Pub)
  requireUint8Array('id.x25519Priv', id.x25519Priv)
  requireUint8Array('peerEd25519Pub', peerEd25519Pub)
  requireUint8Array('peerX25519Pub', peerX25519Pub)
  if (peerEd25519Pub.length !== 32) throw new InvalidEd25519PubKeyError()
  if (peerX25519Pub.length !== 32) throw new InvalidX25519PubKeyError()
  if (bytesEqual(id.ed25519Pub, peerEd25519Pub)) throw new SelfFriendshipError()

  let shared: Uint8Array
  try {
    shared = sharedSecret(id, peerX25519Pub)
  } catch (err) {
    // Translate noble's "invalid private or public key received" (low-order
    // point case) into our typed boundary error so callers can branch on
    // it without instanceof-checking noble internals.
    if (
      err instanceof Error &&
      err.message.includes('invalid private or public key received')
    ) {
      throw new InvalidX25519PubKeyError()
    }
    throw err
  }
  const salt = lexSortedConcat(id.ed25519Pub, peerEd25519Pub)
  const aToBInfo = TEXT_ENCODER.encode(SESSION_INFO + 'a-to-b')
  const bToAInfo = TEXT_ENCODER.encode(SESSION_INFO + 'b-to-a')
  const keyAtoB = hkdf(sha256, shared, salt, aToBInfo, 32)
  const keyBtoA = hkdf(sha256, shared, salt, bToAInfo, 32)

  if (bytesCompare(id.ed25519Pub, peerEd25519Pub) < 0) {
    // I am 'a': I send a-to-b, I receive b-to-a.
    return { sendKey: keyAtoB, recvKey: keyBtoA }
  }
  return { sendKey: keyBtoA, recvKey: keyAtoB }
}

export interface Envelope {
  nonce: Uint8Array // 24 bytes
  ciphertext: Uint8Array // includes 16-byte Poly1305 tag
}

// EncryptEnvelope returns (nonce, ciphertext) for the given plaintext, with
// the inner-type byte bound into the AEAD tag. XChaCha20-Poly1305's 192-bit
// nonce makes the random nonce safe with negligible birthday-bound risk.
//
// innerType is the wire-protocol's inner-type byte (0x01 for JSON control,
// 0x02 for file chunk; see AGENTS.md "Encrypted Envelopes"). A single byte
// rather than Uint8Array AAD because the spec is unambiguous: the AAD is
// always exactly the inner-type byte.
//
// Asymmetry note: this throws on malformed inputs, while the Go counterpart
// (cryptoid.EncryptEnvelope) returns an error. Each side follows the idiom
// of its host language; the wire output is identical.
export function encryptEnvelope(
  key: Uint8Array,
  plaintext: Uint8Array,
  innerType: number,
): Envelope {
  requireUint8Array('key', key)
  requireUint8Array('plaintext', plaintext)
  if (key.length !== 32) throw new Error('key must be 32 bytes')
  if (!Number.isInteger(innerType) || innerType < 0 || innerType > 255) {
    throw new Error('innerType must be a single byte (0..255)')
  }
  const nonce = randomBytes(24)
  const aead = xchacha20poly1305(key, nonce, new Uint8Array([innerType]))
  // We return the same nonce buffer the AEAD instance borrowed internally.
  // Safe today because the AEAD is constructed, used once, and discarded
  // synchronously here — there's no live reference into the nonce after
  // this returns. A future refactor that caches AEAD instances or reuses
  // the returned nonce in long-lived state must reconsider (clone the
  // nonce, or treat the returned Envelope.nonce as read-only).
  return { nonce, ciphertext: aead.encrypt(plaintext) }
}

// DecryptEnvelope reverses EncryptEnvelope. Throws if the AEAD tag fails
// (tampered ciphertext, tampered nonce, mismatched innerType, or wrong key).
//
// Asymmetry note: this throws on malformed inputs / tag failure, while the
// Go counterpart (cryptoid.DecryptEnvelope) returns an error. Each side
// follows the idiom of its host language.
export function decryptEnvelope(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  innerType: number,
): Uint8Array {
  requireUint8Array('key', key)
  requireUint8Array('nonce', nonce)
  requireUint8Array('ciphertext', ciphertext)
  if (key.length !== 32) throw new Error('key must be 32 bytes')
  if (nonce.length !== 24) throw new Error('nonce must be 24 bytes')
  if (!Number.isInteger(innerType) || innerType < 0 || innerType > 255) {
    throw new Error('innerType must be a single byte (0..255)')
  }
  const aead = xchacha20poly1305(key, nonce, new Uint8Array([innerType]))
  return aead.decrypt(ciphertext)
}

// Fingerprint renders an Ed25519 public key as the six-word BIP-39 fingerprint
// described in AGENTS.md: the first 66 bits of SHA-256(ed25519_pub) split
// into six 11-bit chunks, each indexing the BIP-39 English wordlist, joined
// by hyphens (e.g. "abandon-ladder-quantum-tribe-yellow-velvet").
export function fingerprint(ed25519Pub: Uint8Array): string {
  const hash = sha256(ed25519Pub)
  // 66 bits don't fit in a JS Number (which has 53 bits of integer precision)
  // and we want bit-exact behaviour with the Go side, so use BigInt.
  let hi = 0n
  for (let i = 0; i < 8; i++) hi = (hi << 8n) | BigInt(hash[i])
  const lo = BigInt(hash[8])

  const words: string[] = []
  // Words 0..4 cover hash bits 0..54 — entirely within hi. In hi (big-endian
  // packed), hash bit p sits at position (63 - p), so word i's lowest bit
  // (hash bit 11i+10) sits at position 53 - 11i.
  for (let i = 0; i < 5; i++) {
    const shift = BigInt(53 - 11 * i)
    words.push(wordlist[Number((hi >> shift) & 0x7ffn)])
  }
  // Word 5 covers hash bits 55..65: bottom 9 bits of hi (hash bits 55..63)
  // followed by top 2 bits of lo (hash bits 64..65).
  const word5 = ((hi & 0x1ffn) << 2n) | (lo >> 6n)
  words.push(wordlist[Number(word5 & 0x7ffn)])

  return words.join('-')
}

// --- internal helpers ---

// isUint8Array narrows runtime values to Uint8Array. Guards the entry
// points of helpers that JSON-deserialized Identity objects would
// otherwise crash deep in @noble with "offset is out of bounds": after
// JSON.parse(JSON.stringify(identity)) the byte fields come back as
// plain {0:..., 1:..., ...} objects, not Uint8Arrays.
function isUint8Array(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array
}

function requireUint8Array(name: string, v: unknown): asserts v is Uint8Array {
  if (!isUint8Array(v)) {
    throw new Error(`cryptoid: ${name} must be a Uint8Array`)
  }
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrs) {
    out.set(a, off)
    off += a.length
  }
  return out
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function bytesCompare(a: Uint8Array, b: Uint8Array): number {
  const minLen = Math.min(a.length, b.length)
  for (let i = 0; i < minLen; i++) {
    if (a[i] !== b[i]) return a[i] - b[i]
  }
  return a.length - b.length
}

function lexSortedConcat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (bytesCompare(a, b) < 0) return concat(a, b)
  return concat(b, a)
}
