import { describe, expect, it } from 'vitest'

import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  AEAD_TAG_LEN,
  AeadError,
  aeadDecrypt,
  aeadEncrypt,
} from './aead'

const key = new Uint8Array(AEAD_KEY_LEN).fill(0x42)
const aad = new Uint8Array([0x01]) // typical envelope AAD: 1-byte inner type

describe('aead constants', () => {
  it('match the XChaCha20-Poly1305 spec', () => {
    expect(AEAD_KEY_LEN).toBe(32)
    expect(AEAD_NONCE_LEN).toBe(24)
    expect(AEAD_TAG_LEN).toBe(16)
  })
})

describe('aeadEncrypt + aeadDecrypt round-trip', () => {
  it('round-trips arbitrary plaintext', () => {
    const plaintext = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50])
    const { nonce, sealed } = aeadEncrypt(key, plaintext, aad)
    expect(nonce.length).toBe(AEAD_NONCE_LEN)
    expect(sealed.length).toBe(plaintext.length + AEAD_TAG_LEN)
    const decrypted = aeadDecrypt(key, nonce, sealed, aad)
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext))
  })

  it('round-trips empty plaintext (sealed is exactly the tag)', () => {
    const { nonce, sealed } = aeadEncrypt(key, new Uint8Array(0), aad)
    expect(sealed.length).toBe(AEAD_TAG_LEN)
    const decrypted = aeadDecrypt(key, nonce, sealed, aad)
    expect(decrypted.length).toBe(0)
  })

  it('round-trips a 64 KiB chunk-sized plaintext', () => {
    // The AGENTS.md target chunk size is 64 KiB raw — this is the
    // largest plaintext the AEAD will see in normal use.
    const plaintext = new Uint8Array(64 * 1024)
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = i & 0xff
    const { nonce, sealed } = aeadEncrypt(key, plaintext, aad)
    const decrypted = aeadDecrypt(key, nonce, sealed, aad)
    expect(decrypted.length).toBe(plaintext.length)
    // Spot-check first / middle / last byte (full equality compare on a
    // 64 KB array would be slow in test reporting on failure).
    expect(decrypted[0]).toBe(plaintext[0])
    expect(decrypted[32 * 1024]).toBe(plaintext[32 * 1024])
    expect(decrypted[plaintext.length - 1]).toBe(plaintext[plaintext.length - 1])
  })
})

describe('aeadEncrypt produces fresh nonces', () => {
  it('two encrypts of the same plaintext produce different nonces and sealed payloads', () => {
    const plaintext = new Uint8Array([0xaa, 0xbb, 0xcc])
    const e1 = aeadEncrypt(key, plaintext, aad)
    const e2 = aeadEncrypt(key, plaintext, aad)
    expect(Array.from(e1.nonce)).not.toEqual(Array.from(e2.nonce))
    expect(Array.from(e1.sealed)).not.toEqual(Array.from(e2.sealed))
  })
})

describe('aeadDecrypt rejects tampering', () => {
  // The whole point of AEAD: any single bit flipped in the ciphertext,
  // tag, nonce, key, or AAD should cause auth failure.
  function freshSealed() {
    const plaintext = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])
    return { plaintext, ...aeadEncrypt(key, plaintext, aad) }
  }

  it('rejects a flipped bit in the ciphertext', () => {
    const { nonce, sealed } = freshSealed()
    const tampered = new Uint8Array(sealed)
    tampered[0] ^= 0x01
    expect(() => aeadDecrypt(key, nonce, tampered, aad)).toThrow(AeadError)
  })

  it('rejects a flipped bit in the tag', () => {
    const { nonce, sealed } = freshSealed()
    const tampered = new Uint8Array(sealed)
    tampered[tampered.length - 1] ^= 0x01
    expect(() => aeadDecrypt(key, nonce, tampered, aad)).toThrow(AeadError)
  })

  it('rejects a flipped bit in the nonce', () => {
    const { nonce, sealed } = freshSealed()
    const tampered = new Uint8Array(nonce)
    tampered[0] ^= 0x01
    expect(() => aeadDecrypt(key, tampered, sealed, aad)).toThrow(AeadError)
  })

  it('rejects a different AAD (e.g. inner type 0x02 instead of 0x01)', () => {
    const { nonce, sealed } = freshSealed()
    const wrongAad = new Uint8Array([0x02])
    expect(() => aeadDecrypt(key, nonce, sealed, wrongAad)).toThrow(AeadError)
  })

  it('rejects empty AAD when sender used a 1-byte AAD', () => {
    const { nonce, sealed } = freshSealed()
    expect(() => aeadDecrypt(key, nonce, sealed, new Uint8Array(0))).toThrow(AeadError)
  })

  it('rejects a different key', () => {
    const { nonce, sealed } = freshSealed()
    const wrongKey = new Uint8Array(AEAD_KEY_LEN).fill(0x99)
    expect(() => aeadDecrypt(wrongKey, nonce, sealed, aad)).toThrow(AeadError)
  })
})

describe('aeadEncrypt / aeadDecrypt input validation', () => {
  it('aeadEncrypt rejects a wrong-length key', () => {
    const shortKey = new Uint8Array(31)
    expect(() => aeadEncrypt(shortKey, new Uint8Array(0), aad)).toThrow(AeadError)
    const longKey = new Uint8Array(33)
    expect(() => aeadEncrypt(longKey, new Uint8Array(0), aad)).toThrow(AeadError)
  })

  it('aeadDecrypt rejects a wrong-length key', () => {
    const { nonce, sealed } = aeadEncrypt(key, new Uint8Array(0), aad)
    const shortKey = new Uint8Array(31)
    expect(() => aeadDecrypt(shortKey, nonce, sealed, aad)).toThrow(AeadError)
  })

  it('aeadDecrypt rejects a wrong-length nonce', () => {
    const { sealed } = aeadEncrypt(key, new Uint8Array(0), aad)
    const shortNonce = new Uint8Array(23)
    expect(() => aeadDecrypt(key, shortNonce, sealed, aad)).toThrow(AeadError)
    const longNonce = new Uint8Array(25)
    expect(() => aeadDecrypt(key, longNonce, sealed, aad)).toThrow(AeadError)
  })

  it('aeadDecrypt rejects sealed too short to contain a tag', () => {
    const { nonce } = aeadEncrypt(key, new Uint8Array(0), aad)
    const tooShort = new Uint8Array(AEAD_TAG_LEN - 1)
    expect(() => aeadDecrypt(key, nonce, tooShort, aad)).toThrow(AeadError)
  })
})
