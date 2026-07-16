// Binary envelope wire format — AGENTS.md "Wire Protocol > Encrypted
// Envelopes (binary frames)". Mirrors internal/wireproto/envelope.go;
// any drift in offsets, lengths, or inner-type discriminators silently
// breaks Go-TS interop on the post-friendship side.
//
//   [ 1 byte  ] inner type        (0x01 = JSON control, 0x02 = file chunk)
//   [ 32 bytes] peer ed25519_pub  (destination on c2s; relay rewrites to source on s2c)
//   [ 24 bytes] XChaCha20-Poly1305 nonce
//   [ N bytes ] ciphertext + 16-byte Poly1305 tag (N >= 16)
//
// This module is pure bytes — no AEAD, no key derivation. The encrypted
// side is layered on top in adjacent modules. Slice-aliasing semantics
// follow the Go side's contract: parseEnvelopeHeader returns subarray
// views into the source frame, so callers must treat those views as
// invalidated by any subsequent mutation of the frame buffer.

// --- length / offset constants ---

export const ENVELOPE_PEER_KEY_LEN = 32
export const ENVELOPE_NONCE_LEN = 24
export const ENVELOPE_HEADER_LEN =
  1 + ENVELOPE_PEER_KEY_LEN + ENVELOPE_NONCE_LEN // = 57
export const ENVELOPE_MIN_SEALED_LEN = 16 // Poly1305 tag — XChaCha20-Poly1305 always emits at least this
export const ENVELOPE_MIN_FRAME_LEN =
  ENVELOPE_HEADER_LEN + ENVELOPE_MIN_SEALED_LEN // = 73

// --- inner-type discriminators ---
//
// The relay does NOT enforce this set (forward-compat: unknown inner
// types are forwarded by the relay and dropped by recipients that
// don't recognize them).

export const INNER_TYPE_JSON_CONTROL = 0x01
export const INNER_TYPE_FILE_CHUNK = 0x02

// --- types ---

export interface EnvelopeHeader {
  innerType: number
  // 32-byte view aliasing frame[1..33]. On c2s frames this is the
  // sender's intended destination; on s2c frames it's the source the
  // relay rewrote in.
  peerKey: Uint8Array
  // 24-byte view aliasing frame[33..57]. Random per frame on the
  // sender side — XChaCha20-Poly1305's 192-bit nonce makes random
  // nonces collision-safe.
  nonce: Uint8Array
}

// EnvelopeError is the typed error every parse/marshal/rewrite path
// throws. Callers can `instanceof EnvelopeError`-discriminate to tell
// "we got bad bytes off the wire" apart from upstream JS errors.
export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvelopeError'
  }
}

// --- functions ---

// parseEnvelopeHeader extracts the fixed prefix of a binary envelope
// frame and returns the header view + the sealed payload tail. Both
// returned slices alias subarray views of the source frame — no copies.
//
// Length-only validation: this function does NOT enforce the
// inner-type set, mirroring the Go relay's forward-compat policy.
//
// Throws EnvelopeError if frame.length < ENVELOPE_MIN_FRAME_LEN.
export function parseEnvelopeHeader(frame: Uint8Array): {
  header: EnvelopeHeader
  sealed: Uint8Array
} {
  if (frame.length < ENVELOPE_MIN_FRAME_LEN) {
    throw new EnvelopeError(
      `envelope: frame too short: ${frame.length} bytes (min ${ENVELOPE_MIN_FRAME_LEN})`,
    )
  }
  return {
    header: {
      innerType: frame[0],
      // subarray returns a Uint8Array view (no copy) — same aliasing
      // contract as Go's `frame[1:33]` slicing.
      peerKey: frame.subarray(1, 33),
      nonce: frame.subarray(33, 57),
    },
    sealed: frame.subarray(ENVELOPE_HEADER_LEN),
  }
}

// rewriteDestinationToSource overwrites the 32-byte peer-identity
// field (bytes 1..33) of an envelope frame in place. Used by the
// sender when reusing a buffer it constructed; the relay does the
// same in Go via wireproto.RewriteDestinationToSource.
//
// On the TS side this is mostly useful for tests / re-encoding paths;
// real clients construct fresh frames per send. Provided for symmetry
// with the Go API.
//
// Throws EnvelopeError if frame is too short for the header or
// sourceKey is not exactly ENVELOPE_PEER_KEY_LEN bytes.
export function rewriteDestinationToSource(
  frame: Uint8Array,
  sourceKey: Uint8Array,
): void {
  if (frame.length < ENVELOPE_HEADER_LEN) {
    throw new EnvelopeError(
      `envelope: frame too short for peer-key rewrite: ${frame.length} bytes (need ${ENVELOPE_HEADER_LEN})`,
    )
  }
  if (sourceKey.length !== ENVELOPE_PEER_KEY_LEN) {
    throw new EnvelopeError(
      `envelope: source key must be ${ENVELOPE_PEER_KEY_LEN} bytes, got ${sourceKey.length}`,
    )
  }
  frame.set(sourceKey, 1)
}

// marshalEnvelope concatenates the header parts and sealed payload
// into a single fresh Uint8Array ready to send as a binary WebSocket
// frame.
//
// Validates that peerKey is ENVELOPE_PEER_KEY_LEN bytes, nonce is
// ENVELOPE_NONCE_LEN bytes, and sealed is at least
// ENVELOPE_MIN_SEALED_LEN bytes (the Poly1305 tag — every well-formed
// AEAD output has it). Throws EnvelopeError otherwise.
export function marshalEnvelope(
  innerType: number,
  peerKey: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
): Uint8Array {
  if (peerKey.length !== ENVELOPE_PEER_KEY_LEN) {
    throw new EnvelopeError(
      `envelope: peer key must be ${ENVELOPE_PEER_KEY_LEN} bytes, got ${peerKey.length}`,
    )
  }
  if (nonce.length !== ENVELOPE_NONCE_LEN) {
    throw new EnvelopeError(
      `envelope: nonce must be ${ENVELOPE_NONCE_LEN} bytes, got ${nonce.length}`,
    )
  }
  if (sealed.length < ENVELOPE_MIN_SEALED_LEN) {
    throw new EnvelopeError(
      `envelope: sealed payload must be at least ${ENVELOPE_MIN_SEALED_LEN} bytes (Poly1305 tag), got ${sealed.length}`,
    )
  }
  // innerType isn't validated here for the same forward-compat reason
  // the Go side doesn't enforce it: future inner-type extensions
  // shouldn't require a relay+wire redeploy.
  const out = new Uint8Array(ENVELOPE_HEADER_LEN + sealed.length)
  out[0] = innerType & 0xff
  out.set(peerKey, 1)
  out.set(nonce, 33)
  out.set(sealed, ENVELOPE_HEADER_LEN)
  return out
}
