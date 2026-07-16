import { describe, expect, it } from 'vitest'

import { generateIdentity } from './index'
import { deriveSessionKeys } from './session'

describe('deriveSessionKeys', () => {
  it('is symmetric — A.sendKey === B.recvKey and A.recvKey === B.sendKey', () => {
    // The most important invariant: both peers compute the same key
    // pair independently from their respective inputs. This is what
    // makes the protocol work without an explicit key-exchange step.
    const a = generateIdentity()
    const b = generateIdentity()

    const fromA = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const fromB = deriveSessionKeys(b.x25519Priv, a.x25519Pub, b.ed25519Pub, a.ed25519Pub)

    expect(Array.from(fromA.sendKey)).toEqual(Array.from(fromB.recvKey))
    expect(Array.from(fromA.recvKey)).toEqual(Array.from(fromB.sendKey))
  })

  it('produces two distinct directional keys (sendKey !== recvKey)', () => {
    // Otherwise nonce reuse across directions would turn the random-
    // 24-byte nonce safety net into a same-key collision.
    const a = generateIdentity()
    const b = generateIdentity()

    const keys = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    expect(Array.from(keys.sendKey)).not.toEqual(Array.from(keys.recvKey))
  })

  it('returns 32-byte session keys', () => {
    const a = generateIdentity()
    const b = generateIdentity()

    const keys = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    expect(keys.sendKey.length).toBe(32)
    expect(keys.recvKey.length).toBe(32)
  })

  it('different friendships produce different key pairs', () => {
    // A↔B and A↔C must derive disjoint session keys despite A reusing
    // the same X25519 keypair across both — AGENTS.md "Per-Friendship
    // Shared Secret": ECDH gives a unique value per peer pair, so the
    // X25519 reuse doesn't leak across friendships.
    const a = generateIdentity()
    const b = generateIdentity()
    const c = generateIdentity()

    const ab = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const ac = deriveSessionKeys(a.x25519Priv, c.x25519Pub, a.ed25519Pub, c.ed25519Pub)

    expect(Array.from(ab.sendKey)).not.toEqual(Array.from(ac.sendKey))
    expect(Array.from(ab.recvKey)).not.toEqual(Array.from(ac.recvKey))
  })

  it('refuses self-friendship', () => {
    const a = generateIdentity()
    expect(() =>
      deriveSessionKeys(a.x25519Priv, a.x25519Pub, a.ed25519Pub, a.ed25519Pub),
    ).toThrow(/cannot derive keys with self/)
  })

  it.each<['myX25519Priv' | 'peerX25519Pub' | 'myEd25519Pub' | 'peerEd25519Pub', number]>([
    ['myX25519Priv', 31],
    ['peerX25519Pub', 33],
    ['myEd25519Pub', 0],
    ['peerEd25519Pub', 64],
  ])('rejects %s of length %i', (badField, len) => {
    const a = generateIdentity()
    const b = generateIdentity()
    const args = {
      myX25519Priv: a.x25519Priv,
      peerX25519Pub: b.x25519Pub,
      myEd25519Pub: a.ed25519Pub,
      peerEd25519Pub: b.ed25519Pub,
    }
    args[badField] = new Uint8Array(len)
    expect(() =>
      deriveSessionKeys(
        args.myX25519Priv,
        args.peerX25519Pub,
        args.myEd25519Pub,
        args.peerEd25519Pub,
      ),
    ).toThrow(new RegExp(`${badField} must be 32 bytes`))
  })

  it('is deterministic for a fixed input', () => {
    // Same inputs -> same output, twice. Pins that the function is
    // pure; a refactor that accidentally introduces nondeterminism
    // (e.g. random salt) would break Go-TS interop catastrophically.
    const a = generateIdentity()
    const b = generateIdentity()

    const k1 = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const k2 = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)

    expect(Array.from(k1.sendKey)).toEqual(Array.from(k2.sendKey))
    expect(Array.from(k1.recvKey)).toEqual(Array.from(k2.recvKey))
  })

  it('uses lex-deterministic direction so swapping endpoints flips send and recv', () => {
    // If A's view derives sendKey=K1, recvKey=K2, and we swap which
    // identity we call "me" in the helper, we should get the directional
    // strings reversed — sendKey=K2, recvKey=K1 from A's perspective
    // is the same as B's perspective in the symmetry test. This is
    // really a restatement of symmetry from a different angle, but it
    // catches a class of bug where direction strings are swapped.
    const a = generateIdentity()
    const b = generateIdentity()

    const aView = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const bView = deriveSessionKeys(b.x25519Priv, a.x25519Pub, b.ed25519Pub, a.ed25519Pub)

    expect(Array.from(aView.sendKey)).toEqual(Array.from(bView.recvKey))
    expect(Array.from(bView.sendKey)).toEqual(Array.from(aView.recvKey))
  })
})
