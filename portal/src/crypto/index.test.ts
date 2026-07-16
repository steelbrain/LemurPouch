// TS-side tests for the cryptoid module. The "knownVectors" test pins the
// same canonical outputs as Go's TestKnownVectors so both implementations
// stay byte-for-byte in lock-step.

import { describe, it, expect } from 'vitest'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  type Identity,
  decryptEnvelope,
  encryptEnvelope,
  fingerprint,
  friendshipKeys,
  generateIdentity,
  InvalidEd25519PubKeyError,
  InvalidX25519PubKeyError,
  SelfFriendshipError,
  sharedSecret,
  signBinding,
  signLiveness,
  verifyBinding,
  verifyLiveness,
} from './index'

const TEXT = new TextEncoder()

describe('signLiveness / verifyLiveness', () => {
  it('round-trips', () => {
    const id = generateIdentity()
    const nonce = new Uint8Array(32).fill(0x01)
    const sig = signLiveness(id, nonce)
    expect(verifyLiveness(id.ed25519Pub, nonce, sig)).toBe(true)
  })

  it('rejects tampered nonce', () => {
    const id = generateIdentity()
    const nonce = new Uint8Array(32).fill(0x01)
    const sig = signLiveness(id, nonce)
    const tampered = new Uint8Array(nonce)
    tampered[0] ^= 0x01
    expect(verifyLiveness(id.ed25519Pub, tampered, sig)).toBe(false)
  })

  it('rejects foreign public key', () => {
    const id = generateIdentity()
    const other = generateIdentity()
    const nonce = new Uint8Array(32).fill(0x01)
    const sig = signLiveness(id, nonce)
    expect(verifyLiveness(other.ed25519Pub, nonce, sig)).toBe(false)
  })

  it('returns false on malformed pubkey lengths', () => {
    const id = generateIdentity()
    const nonce = new Uint8Array(32).fill(0x01)
    const sig = signLiveness(id, nonce)
    for (const n of [0, 31, 33]) {
      expect(verifyLiveness(new Uint8Array(n), nonce, sig)).toBe(false)
    }
  })

  it('returns false on malformed signature lengths', () => {
    // Confirms the try/catch swallow path: noble would throw on a wrong-
    // length signature, but verify* must surface that as a clean false.
    const id = generateIdentity()
    const nonce = new Uint8Array(32).fill(0x01)
    for (const n of [0, 63, 65]) {
      expect(verifyLiveness(id.ed25519Pub, nonce, new Uint8Array(n))).toBe(false)
    }
  })
})

describe('signBinding / verifyBinding', () => {
  it('round-trips', () => {
    const id = generateIdentity()
    const sig = signBinding(id)
    expect(verifyBinding(id.ed25519Pub, id.x25519Pub, sig)).toBe(true)
  })

  it('rejects tampered X25519 pub', () => {
    const id = generateIdentity()
    const sig = signBinding(id)
    const tampered = new Uint8Array(id.x25519Pub)
    tampered[0] ^= 0x01
    expect(verifyBinding(id.ed25519Pub, tampered, sig)).toBe(false)
  })

  it('rejects a signature lacking the bind-x25519 domain separator', () => {
    // Forge a "raw" signature over the X25519 pub without the BIND_CONTEXT
    // prefix; verifyBinding should still reject it because it reconstructs
    // the message with the prefix and the signature won't match.
    const id = generateIdentity()
    const rawSig = ed25519.sign(id.x25519Pub, id.ed25519Priv)
    expect(verifyBinding(id.ed25519Pub, id.x25519Pub, rawSig)).toBe(false)
  })

  it('returns false on malformed key lengths', () => {
    const id = generateIdentity()
    const sig = signBinding(id)
    for (const n of [0, 31, 33]) {
      expect(verifyBinding(new Uint8Array(n), id.x25519Pub, sig)).toBe(false)
      expect(verifyBinding(id.ed25519Pub, new Uint8Array(n), sig)).toBe(false)
    }
  })

  it('returns false on malformed signature lengths', () => {
    // See verifyLiveness's matching test: confirms the try/catch swallow
    // path turns noble's throw on bad sig length into a clean false.
    const id = generateIdentity()
    for (const n of [0, 63, 65]) {
      expect(
        verifyBinding(id.ed25519Pub, id.x25519Pub, new Uint8Array(n)),
      ).toBe(false)
    }
  })
})

describe('sharedSecret / friendshipKeys', () => {
  it('shared secrets are symmetric', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const secretA = sharedSecret(a, b.x25519Pub)
    const secretB = sharedSecret(b, a.x25519Pub)
    expect(bytesToHex(secretA)).toBe(bytesToHex(secretB))
  })

  it('friendship keys are symmetric (A.send == B.recv, A.recv == B.send)', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const aKeys = friendshipKeys(a, b.ed25519Pub, b.x25519Pub)
    const bKeys = friendshipKeys(b, a.ed25519Pub, a.x25519Pub)
    expect(bytesToHex(aKeys.sendKey)).toBe(bytesToHex(bKeys.recvKey))
    expect(bytesToHex(aKeys.recvKey)).toBe(bytesToHex(bKeys.sendKey))
    // The two directional keys for one peer should differ.
    expect(bytesToHex(aKeys.sendKey)).not.toBe(bytesToHex(aKeys.recvKey))
  })

  it('friending self throws SelfFriendshipError', () => {
    const id = generateIdentity()
    expect(() => friendshipKeys(id, id.ed25519Pub, id.x25519Pub)).toThrow(
      SelfFriendshipError,
    )
  })

  it('rejects bad peerEd25519Pub length with InvalidEd25519PubKeyError', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    for (const n of [0, 31, 33]) {
      expect(() =>
        friendshipKeys(a, new Uint8Array(n), b.x25519Pub),
      ).toThrow(InvalidEd25519PubKeyError)
    }
  })

  it('rejects bad peerX25519Pub length with InvalidX25519PubKeyError', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    for (const n of [0, 31, 33]) {
      expect(() =>
        friendshipKeys(a, b.ed25519Pub, new Uint8Array(n)),
      ).toThrow(InvalidX25519PubKeyError)
    }
  })

  it('friendship keys are distinct across peer-pairs', () => {
    // Mirrors Go's TestFriendshipKeysDistinctAcrossPeers: guards against a
    // regression that drops the X25519 shared secret from the derivation,
    // which would produce the same key for every friendship in a session
    // and pass every other test.
    const a = generateIdentity()
    const b = generateIdentity()
    const c = generateIdentity()

    const ab = friendshipKeys(a, b.ed25519Pub, b.x25519Pub)
    const ac = friendshipKeys(a, c.ed25519Pub, c.x25519Pub)
    const bc = friendshipKeys(b, c.ed25519Pub, c.x25519Pub)

    const pairs: { name: string; x: Uint8Array; y: Uint8Array }[] = [
      { name: 'a→b send vs a→c send', x: ab.sendKey, y: ac.sendKey },
      { name: 'a→b send vs a→c recv', x: ab.sendKey, y: ac.recvKey },
      { name: 'a→b recv vs a→c send', x: ab.recvKey, y: ac.sendKey },
      { name: 'a→b recv vs a→c recv', x: ab.recvKey, y: ac.recvKey },
      { name: 'a→b send vs b→c send', x: ab.sendKey, y: bc.sendKey },
      { name: 'a→b send vs b→c recv', x: ab.sendKey, y: bc.recvKey },
      { name: 'a→b recv vs b→c send', x: ab.recvKey, y: bc.sendKey },
      { name: 'a→b recv vs b→c recv', x: ab.recvKey, y: bc.recvKey },
      { name: 'a→c send vs b→c send', x: ac.sendKey, y: bc.sendKey },
      { name: 'a→c send vs b→c recv', x: ac.sendKey, y: bc.recvKey },
      { name: 'a→c recv vs b→c send', x: ac.recvKey, y: bc.sendKey },
      { name: 'a→c recv vs b→c recv', x: ac.recvKey, y: bc.recvKey },
    ]
    for (const p of pairs) {
      expect(bytesToHex(p.x)).not.toBe(bytesToHex(p.y))
    }
  })

  it('decrypting with wrong-direction key fails', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const aKeys = friendshipKeys(a, b.ed25519Pub, b.x25519Pub)
    const bKeys = friendshipKeys(b, a.ed25519Pub, a.x25519Pub)
    const { nonce, ciphertext } = encryptEnvelope(
      aKeys.sendKey,
      TEXT.encode('A->B'),
      0x01,
    )
    // bRecv (correct) succeeds.
    expect(() => decryptEnvelope(bKeys.recvKey, nonce, ciphertext, 0x01)).not.toThrow()
    // bSend (wrong direction) fails.
    expect(() => decryptEnvelope(bKeys.sendKey, nonce, ciphertext, 0x01)).toThrow()
  })
})

describe('encryptEnvelope / decryptEnvelope', () => {
  it('round-trips', () => {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    const plaintext = TEXT.encode('the quick brown fox jumps over the lazy dog')
    const { nonce, ciphertext } = encryptEnvelope(key, plaintext, 0x01)
    expect(nonce.length).toBe(24)
    expect(bytesToHex(ciphertext)).not.toBe(bytesToHex(plaintext))

    const decoded = decryptEnvelope(key, nonce, ciphertext, 0x01)
    expect(bytesToHex(decoded)).toBe(bytesToHex(plaintext))
  })

  it('rejects tampered ciphertext, nonce, key, or innerType', () => {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    const { nonce, ciphertext } = encryptEnvelope(key, TEXT.encode('x'), 0x01)

    const tCt = new Uint8Array(ciphertext)
    tCt[0] ^= 0x01
    expect(() => decryptEnvelope(key, nonce, tCt, 0x01)).toThrow()

    const tNonce = new Uint8Array(nonce)
    tNonce[0] ^= 0x01
    expect(() => decryptEnvelope(key, tNonce, ciphertext, 0x01)).toThrow()

    const wrongKey = new Uint8Array(32)
    crypto.getRandomValues(wrongKey)
    expect(() => decryptEnvelope(wrongKey, nonce, ciphertext, 0x01)).toThrow()

    // Inner-type flip: the AAD-binding spec defends against this exact attack.
    expect(() => decryptEnvelope(key, nonce, ciphertext, 0x02)).toThrow()
  })

  it('emits a fresh random nonce per call', () => {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    const a = encryptEnvelope(key, TEXT.encode('same'), 0x01)
    const b = encryptEnvelope(key, TEXT.encode('same'), 0x01)
    expect(bytesToHex(a.nonce)).not.toBe(bytesToHex(b.nonce))
    expect(bytesToHex(a.ciphertext)).not.toBe(bytesToHex(b.ciphertext))
  })

  it('rejects malformed nonce length', () => {
    const key = new Uint8Array(32)
    crypto.getRandomValues(key)
    const { ciphertext } = encryptEnvelope(key, TEXT.encode('x'), 0x01)
    for (const n of [0, 23, 25]) {
      expect(() => decryptEnvelope(key, new Uint8Array(n), ciphertext, 0x01)).toThrow()
    }
  })
})

describe('requireUint8Array enforcement', () => {
  // After JSON.parse(JSON.stringify(identity)) the byte fields come back as
  // plain {0:..., 1:..., ...} objects, not Uint8Arrays. Without the
  // requireUint8Array guards, those would crash deep in @noble with an
  // inscrutable "offset is out of bounds". Each call below pins one of the
  // exported helpers' guard paths.

  it('signBinding rejects non-Uint8Array fields', () => {
    const id = generateIdentity()
    const jsonId = JSON.parse(JSON.stringify(id)) as Identity
    expect(() => signBinding(jsonId)).toThrow(/must be a Uint8Array/)
  })

  it('signLiveness rejects non-Uint8Array nonce', () => {
    const id = generateIdentity()
    const jsonId = JSON.parse(JSON.stringify(id)) as Identity
    expect(() =>
      signLiveness(id, jsonId.ed25519Pub as unknown as Uint8Array),
    ).toThrow(/must be a Uint8Array/)
  })

  it('friendshipKeys rejects non-Uint8Array peer keys', () => {
    const id = generateIdentity()
    const jsonId = JSON.parse(JSON.stringify(id)) as Identity
    expect(() =>
      friendshipKeys(id, jsonId.ed25519Pub, id.x25519Pub),
    ).toThrow(/must be a Uint8Array/)
  })

  it('sharedSecret rejects non-Uint8Array peer pub', () => {
    const id = generateIdentity()
    const jsonId = JSON.parse(JSON.stringify(id)) as Identity
    expect(() => sharedSecret(id, jsonId.x25519Pub)).toThrow(
      /must be a Uint8Array/,
    )
  })

  it('encryptEnvelope rejects non-Uint8Array key/plaintext', () => {
    const key = new Uint8Array(32)
    const plaintext = new Uint8Array([1, 2, 3])
    const jsonKey = JSON.parse(JSON.stringify(key))
    const jsonPt = JSON.parse(JSON.stringify(plaintext))
    expect(() => encryptEnvelope(jsonKey, plaintext, 0x01)).toThrow(
      /must be a Uint8Array/,
    )
    expect(() => encryptEnvelope(key, jsonPt, 0x01)).toThrow(
      /must be a Uint8Array/,
    )
  })

  it('decryptEnvelope rejects non-Uint8Array key/nonce/ciphertext', () => {
    const key = new Uint8Array(32)
    const nonce = new Uint8Array(24)
    const ct = new Uint8Array(16)
    const jsonKey = JSON.parse(JSON.stringify(key))
    const jsonNonce = JSON.parse(JSON.stringify(nonce))
    const jsonCt = JSON.parse(JSON.stringify(ct))
    expect(() => decryptEnvelope(jsonKey, nonce, ct, 0x01)).toThrow(
      /must be a Uint8Array/,
    )
    expect(() => decryptEnvelope(key, jsonNonce, ct, 0x01)).toThrow(
      /must be a Uint8Array/,
    )
    expect(() => decryptEnvelope(key, nonce, jsonCt, 0x01)).toThrow(
      /must be a Uint8Array/,
    )
  })
})

describe('low-order-point translation', () => {
  // Pins that an all-zero peer X25519 pub (a known low-order point that
  // noble's x25519.getSharedSecret rejects with "invalid private or public
  // key received") is translated into our typed InvalidX25519PubKeyError.
  // A future @noble release that changes the substring would silently leak
  // the raw noble error — this test fails loudly if that happens.
  it('translates noble low-order-point error into InvalidX25519PubKeyError', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    expect(() =>
      friendshipKeys(a, b.ed25519Pub, new Uint8Array(32)),
    ).toThrow(InvalidX25519PubKeyError)
  })
})

describe('signLiveness empty-nonce rejection', () => {
  // Signing an empty nonce would let a relay replay a fixed signature across
  // reconnects (the liveness handshake re-uses the signature as freshness
  // proof); the guard at the top of signLiveness stops that footgun.
  it('rejects empty nonce', () => {
    const id = generateIdentity()
    expect(() => signLiveness(id, new Uint8Array(0))).toThrow(
      /nonce must be non-empty/,
    )
  })
})

describe('fingerprint', () => {
  it('returns six hyphenated words', () => {
    const id = generateIdentity()
    const fp = fingerprint(id.ed25519Pub)
    const parts = fp.split('-')
    expect(parts.length).toBe(6)
    for (const p of parts) expect(p.length).toBeGreaterThan(0)
  })

  it('is deterministic', () => {
    const id = generateIdentity()
    expect(fingerprint(id.ed25519Pub)).toBe(fingerprint(id.ed25519Pub))
  })

  it('distinct identities yield distinct fingerprints', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    expect(fingerprint(a.ed25519Pub)).not.toBe(fingerprint(b.ed25519Pub))
  })
})

// TestKnownVectors mirrors the Go test of the same name. Any drift in
// domain-separator strings, HKDF inputs, signing/binding construction, or
// fingerprint bit math will fail this test on either side.
describe('TestKnownVectors (lock-step with Go internal/cryptoid)', () => {
  it('reproduces the canonical pinned outputs from the Go side', () => {
    const seedA = new Uint8Array(32).fill(0x01)
    const seedB = new Uint8Array(32).fill(0x02)
    const xPrivA = new Uint8Array(32).fill(0x11)
    const xPrivB = new Uint8Array(32).fill(0x22)

    const idA: Identity = {
      ed25519Priv: seedA,
      ed25519Pub: ed25519.getPublicKey(seedA),
      x25519Priv: xPrivA,
      x25519Pub: x25519.getPublicKey(xPrivA),
    }
    const idB: Identity = {
      ed25519Priv: seedB,
      ed25519Pub: ed25519.getPublicKey(seedB),
      x25519Priv: xPrivB,
      x25519Pub: x25519.getPublicKey(xPrivB),
    }

    expect(bytesToHex(idA.ed25519Pub)).toBe(
      '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
    )
    expect(bytesToHex(idB.ed25519Pub)).toBe(
      '8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394',
    )
    expect(bytesToHex(idA.x25519Pub)).toBe(
      '7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13',
    )
    expect(bytesToHex(idB.x25519Pub)).toBe(
      '0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20',
    )

    // Re-pinned after project rename (BIND_CONTEXT / SESSION_INFO use
    // "LemurPouch/v1/…"); pub keys and fingerprints are unchanged.
    expect(bytesToHex(signBinding(idA))).toBe(
      'ab139c475be82663df061235f90ba673fc2bd03d538fdc1abbac7f389ea004155e859b2101245ba5c517f4042575ed60f8b7807bd4d6f31116b0b6bfe95b620e',
    )
    expect(bytesToHex(signBinding(idB))).toBe(
      '8d7dd65774c7b9a634bcf9c587d59b310fc32010f27700c06f9ddb4222591daba719a68d04abc5ff559f3bbc29d19dae59219144606befdc484a0be5f2a56b0e',
    )

    // Pin the raw X25519 shared-secret bytes too. The friendshipKeys check
    // below transitively covers the secret, but a compensating-error
    // regression (wrong shared secret + compensating salt) could still
    // pass that test. Pinning the secret directly closes that gap.
    expect(bytesToHex(sharedSecret(idA, idB.x25519Pub))).toBe(
      '9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056',
    )

    const aKeys = friendshipKeys(idA, idB.ed25519Pub, idB.x25519Pub)
    expect(bytesToHex(aKeys.sendKey)).toBe(
      '11182abd48889b89121dd5a5ebcacb5909d61b1af54ddb52de58c0b196a16d92',
    )
    expect(bytesToHex(aKeys.recvKey)).toBe(
      '23e9e976c36df982e2f05f997c47ee698f1e4f2a6253716f53380bc184f2253b',
    )

    expect(fingerprint(idA.ed25519Pub)).toBe(
      'crucial-position-tower-kingdom-panther-layer',
    )
    expect(fingerprint(idB.ed25519Pub)).toBe(
      'health-scale-voice-thing-october-bench',
    )

    // Pin a fixed-nonce ciphertext for byte-equality cross-check with the
    // Go side. EncryptEnvelope uses random nonces internally, so we call
    // the underlying AEAD directly with a known nonce.
    const fixedNonce = new Uint8Array(24).fill(0x33)
    const aead = xchacha20poly1305(
      aKeys.sendKey,
      fixedNonce,
      new Uint8Array([0x01]),
    )
    const ct = aead.encrypt(TEXT.encode('hello, fixed nonce'))
    expect(bytesToHex(ct)).toBe(
      '8cf5b924f35a2da205a24834a118a1ea9230e71f8a8f306db1d65bdc651ad80524bc',
    )
  })
})
