// XChaCha20-Poly1305 AEAD wrap/unwrap — AGENTS.md "End-to-End Encryption
// > Encrypted Envelope". The 192-bit (24-byte) nonce makes random nonces
// collision-safe with no birthday-bound bookkeeping; every frame draws a
// fresh random nonce.
//
// AAD design (AGENTS.md): the single inner-type byte that prefixes the
// envelope frame is the AAD. This binds the type discriminator to the
// ciphertext — a tampering relay cannot flip 0x01 ↔ 0x02 to confuse the
// recipient about how to interpret plaintext without breaking the auth
// tag. The 32-byte peer field is NOT in the AAD because the relay
// legitimately rewrites it; tampering there is detected indirectly via
// per-pair session keys (a wrongly-routed envelope decrypts under a key
// the recipient doesn't share with the supposed sender).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/hashes/utils.js'

export const AEAD_KEY_LEN = 32
export const AEAD_NONCE_LEN = 24
export const AEAD_TAG_LEN = 16

// AeadError is the typed error every encrypt/decrypt path throws on
// validation or auth failure. Lets callers `instanceof AeadError`-
// discriminate "ciphertext was tampered with" from upstream JS errors.
export class AeadError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AeadError'
  }
}

// aeadEncrypt seals plaintext with a fresh random 24-byte nonce. Returns
// the nonce alongside the sealed ciphertext (ciphertext || 16-byte tag).
// The caller is expected to transmit both — for envelopes, both the
// nonce and the sealed bytes are written into the binary frame header
// and tail.
//
// AAD is bound into the auth tag: a recipient must pass the same AAD to
// aeadDecrypt or the verification fails. For envelope use, AAD is the
// 1-byte inner-type discriminator.
//
// Throws AeadError if key is not AEAD_KEY_LEN bytes.
export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): { nonce: Uint8Array; sealed: Uint8Array } {
  if (key.length !== AEAD_KEY_LEN) {
    throw new AeadError(
      `aead: key must be ${AEAD_KEY_LEN} bytes, got ${key.length}`,
    )
  }
  const nonce = randomBytes(AEAD_NONCE_LEN)
  const cipher = xchacha20poly1305(key, nonce, aad)
  const sealed = cipher.encrypt(plaintext)
  return { nonce, sealed }
}

// aeadDecrypt verifies + decrypts a sealed payload. AAD must byte-match
// what the sender passed to aeadEncrypt. Throws AeadError on any
// validation failure — wrong key length, wrong nonce length, sealed too
// short to contain even a tag, or auth-tag mismatch (which is the
// catch-all for ciphertext / nonce / AAD / key tampering).
//
// Auth failure is thrown rather than returning null because every
// failure path here is semantically "this frame is forged or corrupt"
// and callers should not be tempted to recover with partial data.
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== AEAD_KEY_LEN) {
    throw new AeadError(
      `aead: key must be ${AEAD_KEY_LEN} bytes, got ${key.length}`,
    )
  }
  if (nonce.length !== AEAD_NONCE_LEN) {
    throw new AeadError(
      `aead: nonce must be ${AEAD_NONCE_LEN} bytes, got ${nonce.length}`,
    )
  }
  if (sealed.length < AEAD_TAG_LEN) {
    throw new AeadError(
      `aead: sealed too short to contain a ${AEAD_TAG_LEN}-byte tag: ${sealed.length} bytes`,
    )
  }
  const cipher = xchacha20poly1305(key, nonce, aad)
  try {
    return cipher.decrypt(sealed)
  } catch (err) {
    throw new AeadError(
      `aead: decrypt failed (auth tag mismatch or malformed): ${(err as Error).message}`,
    )
  }
}
