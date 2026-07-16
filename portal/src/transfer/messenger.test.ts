import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { generateIdentity, type Identity } from '../crypto/index'
import {
  ENVELOPE_PEER_KEY_LEN,
  EnvelopeError,
  INNER_TYPE_JSON_CONTROL,
  rewriteDestinationToSource,
} from '../crypto/envelope'
import { deriveSessionKeys } from '../crypto/session'
import { type PeerRecord } from '../relay/wire'

import {
  EnvelopeMessenger,
  type EnvelopeSocket,
  type IncomingEnvelope,
  openEnvelope,
  sealEnvelope,
} from './messenger'

// peerRecordOf builds a PeerRecord from an Identity. The discovery-
// originated `sig_binding` and `ip`/`port` fields aren't checked by
// the messenger (they're verified at the discovery layer), so the
// values here are just placeholders.
function peerRecordOf(id: Identity): PeerRecord {
  return {
    ed25519Pub: id.ed25519Pub,
    x25519Pub: id.x25519Pub,
    sigBinding: new Uint8Array(64),
    ip: '127.0.0.1',
    port: 0,
  }
}

// Fake WebSocket pair backed by a fake relay — `send` on one socket
// dispatches to the paired socket's listeners after rewriting the
// envelope frame's peer field from destination to source (mirroring
// what internal/relay/envelope.go does on the real path). Without
// the rewrite, the receiver would look up session keys under its own
// identity (the unmodified destination) and silently drop, masking
// every cross-side test.
//
// myIdentity is the ed25519_pub of the peer "behind" this socket —
// the same identity the real relay would substitute on forward.
// MessageEvent is constructed via a plain-object cast because the
// vitest default node environment may not expose MessageEvent.
class FakeSocket {
  paired?: FakeSocket
  myIdentity!: Uint8Array
  // Optional pre-dispatch hook: lets tests tamper with the wire bytes
  // between send (mA's side) and the listener fan-out (mB's side).
  // Used by the decryption-fail test.
  beforeDispatch?: (frame: Uint8Array) => void
  // Listeners exposed for tests that want to dispatch a synthetic
  // event directly (e.g. the text-frame-ignored test).
  listeners = new Set<(ev: MessageEvent) => void>()

  send(data: ArrayBufferView | ArrayBuffer): void {
    if (!this.paired) return
    // Copy out of the source buffer so we don't alias caller's frame
    // through the rewrite.
    const frame =
      data instanceof ArrayBuffer
        ? new Uint8Array(data.slice(0))
        : new Uint8Array(
            data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
          )
    rewriteDestinationToSource(frame, this.myIdentity)
    this.beforeDispatch?.(frame)
    const ev = { data: frame.buffer } as unknown as MessageEvent
    for (const l of this.paired.listeners) l(ev)
  }

  addEventListener(_type: 'message', listener: (ev: MessageEvent) => void): void {
    this.listeners.add(listener)
  }

  removeEventListener(_type: 'message', listener: (ev: MessageEvent) => void): void {
    this.listeners.delete(listener)
  }
}

function createFakeSocketPair(idA: Uint8Array, idB: Uint8Array): [FakeSocket, FakeSocket] {
  const a = new FakeSocket()
  const b = new FakeSocket()
  a.myIdentity = idA
  b.myIdentity = idB
  a.paired = b
  b.paired = a
  return [a, b]
}

describe('sealEnvelope + openEnvelope round-trip', () => {
  it('seals then opens with peer-derived directional keys', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const ka = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const kb = deriveSessionKeys(b.x25519Priv, a.x25519Pub, b.ed25519Pub, a.ed25519Pub)

    const plaintext = new TextEncoder().encode('hello envelope')
    const frame = sealEnvelope(ka.sendKey, b.ed25519Pub, INNER_TYPE_JSON_CONTROL, plaintext)

    const env = openEnvelope(kb.recvKey, frame)
    expect(env.innerType).toBe(INNER_TYPE_JSON_CONTROL)
    expect(new TextDecoder().decode(env.plaintext)).toBe('hello envelope')
    // The peer field as parsed is what the SENDER wrote — i.e. the
    // destination key. In production the relay rewrites it to the
    // source before forwarding, but openEnvelope itself doesn't
    // reverse the rewrite; we assert against the destination here.
    expect(Array.from(env.from)).toEqual(Array.from(b.ed25519Pub))
  })

  it('openEnvelope returns a freshly-allocated `from` (not a view into frame)', () => {
    // Pin the snapshot semantics — receivers can stash the from key
    // past the next socket-message processing without aliasing.
    const a = generateIdentity()
    const b = generateIdentity()
    const ka = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const kb = deriveSessionKeys(b.x25519Priv, a.x25519Pub, b.ed25519Pub, a.ed25519Pub)

    const frame = sealEnvelope(ka.sendKey, b.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array([0x01]))
    const env = openEnvelope(kb.recvKey, frame)
    frame[1] = 0xff // mutate the source frame's peer-key region
    expect(env.from[0]).not.toBe(0xff) // stored copy is unaffected
  })

  it('sealEnvelope rejects wrong-size peer key', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const ka = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    expect(() =>
      sealEnvelope(ka.sendKey, new Uint8Array(31), INNER_TYPE_JSON_CONTROL, new Uint8Array(0)),
    ).toThrow(`peerEd25519Pub must be ${ENVELOPE_PEER_KEY_LEN} bytes`)
  })

  it('openEnvelope throws on tampered ciphertext', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const ka = deriveSessionKeys(a.x25519Priv, b.x25519Pub, a.ed25519Pub, b.ed25519Pub)
    const kb = deriveSessionKeys(b.x25519Priv, a.x25519Pub, b.ed25519Pub, a.ed25519Pub)

    const frame = sealEnvelope(ka.sendKey, b.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array([0x42]))
    // Flip a bit in the sealed region (after the 57-byte header).
    frame[60] ^= 0x01
    expect(() => openEnvelope(kb.recvKey, frame)).toThrow(/aead/)
  })

  it('openEnvelope throws on a frame too short to be an envelope', () => {
    const fakeKey = new Uint8Array(32).fill(0xaa)
    expect(() => openEnvelope(fakeKey, new Uint8Array(50))).toThrow(EnvelopeError)
  })
})

describe('EnvelopeMessenger', () => {
  // Two connected peers backed by a fake socket pair. Each test gets
  // a fresh setup so suite ordering doesn't leak state.
  let sockA: FakeSocket
  let sockB: FakeSocket
  let idA: Identity
  let idB: Identity
  let mA: EnvelopeMessenger
  let mB: EnvelopeMessenger

  beforeEach(() => {
    idA = generateIdentity()
    idB = generateIdentity()
    ;[sockA, sockB] = createFakeSocketPair(idA.ed25519Pub, idB.ed25519Pub)
    mA = new EnvelopeMessenger(sockA as unknown as EnvelopeSocket, idA)
    mB = new EnvelopeMessenger(sockB as unknown as EnvelopeSocket, idB)
  })

  afterEach(() => {
    mA.close()
    mB.close()
  })

  it('happy path: register friends both sides, send -> receive', () => {
    mA.registerFriend(peerRecordOf(idB))
    mB.registerFriend(peerRecordOf(idA))

    const received: IncomingEnvelope[] = []
    mB.onEnvelope((env) => received.push(env))

    const payload = new TextEncoder().encode('hi')
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, payload)

    expect(received).toHaveLength(1)
    expect(received[0].innerType).toBe(INNER_TYPE_JSON_CONTROL)
    expect(new TextDecoder().decode(received[0].plaintext)).toBe('hi')
    expect(Array.from(received[0].from)).toEqual(Array.from(idA.ed25519Pub))
  })

  it('send throws when no session keys are cached for the destination', () => {
    // mA doesn't know about mB yet.
    expect(() =>
      mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0)),
    ).toThrow(/no session keys/)
  })

  it('send works without the recipient registering as a friend (sender-only register)', () => {
    // Sender has the keys → the frame goes out. Recipient can't decrypt
    // because they haven't registered, so they drop silently. This
    // pins the asymmetric "registration is a per-side concern" model.
    mA.registerFriend(peerRecordOf(idB))
    const received: IncomingEnvelope[] = []
    mB.onEnvelope((env) => received.push(env))
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array([0x42]))
    expect(received).toHaveLength(0)
  })

  it('removeFriend evicts the cache; subsequent send throws', () => {
    mA.registerFriend(peerRecordOf(idB))
    expect(mA.hasFriend(idB.ed25519Pub)).toBe(true)
    mA.removeFriend(idB.ed25519Pub)
    expect(mA.hasFriend(idB.ed25519Pub)).toBe(false)
    expect(() =>
      mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0)),
    ).toThrow(/no session keys/)
  })

  it('multi-subscriber: every onEnvelope handler sees the message', () => {
    mA.registerFriend(peerRecordOf(idB))
    mB.registerFriend(peerRecordOf(idA))
    const received1: number[] = []
    const received2: number[] = []
    mB.onEnvelope(() => received1.push(1))
    mB.onEnvelope(() => received2.push(2))
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0))
    expect(received1).toEqual([1])
    expect(received2).toEqual([2])
  })

  it('unsubscribe stops delivery to the unsubscribed handler only', () => {
    mA.registerFriend(peerRecordOf(idB))
    mB.registerFriend(peerRecordOf(idA))
    let count1 = 0
    let count2 = 0
    const unsub1 = mB.onEnvelope(() => count1++)
    mB.onEnvelope(() => count2++)

    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0))
    unsub1()
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0))

    expect(count1).toBe(1)
    expect(count2).toBe(2)
  })

  it('a throwing handler does not block other handlers', () => {
    mA.registerFriend(peerRecordOf(idB))
    mB.registerFriend(peerRecordOf(idA))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    let secondCalled = false
    mB.onEnvelope(() => {
      throw new Error('boom')
    })
    mB.onEnvelope(() => {
      secondCalled = true
    })

    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0))
    expect(secondCalled).toBe(true)
    expect(warnSpy).toHaveBeenCalled()
    warnSpy.mockRestore()
  })

  it('close() unsubscribes the socket and is idempotent', () => {
    mA.registerFriend(peerRecordOf(idB))
    mB.registerFriend(peerRecordOf(idA))
    let received = 0
    mB.onEnvelope(() => received++)

    mB.close()
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0))
    expect(received).toBe(0)

    // Second close is a no-op (no throw).
    expect(() => mB.close()).not.toThrow()
  })

  it('close() prevents subsequent send', () => {
    mA.registerFriend(peerRecordOf(idB))
    mA.close()
    expect(() =>
      mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0)),
    ).toThrow(/closed/)
  })

  it('text frames on the socket are ignored (binaryType filter)', () => {
    mB.registerFriend(peerRecordOf(idA))
    let received = 0
    mB.onEnvelope(() => received++)
    // Synthesize a string MessageEvent directly into mB's listeners —
    // the messenger should ignore it because cleartext-control frames
    // are handled elsewhere.
    const stringEvent = { data: 'hello' } as unknown as MessageEvent
    for (const l of sockB.listeners) l(stringEvent)
    expect(received).toBe(0)
  })

  it('frames from unknown senders are silently dropped (no warn)', () => {
    // mB hasn't registered mA → A's frame arrives but openEnvelope
    // never runs (no key) so there's no warn. Pins the silent-drop
    // policy.
    mA.registerFriend(peerRecordOf(idB))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    let received = 0
    mB.onEnvelope(() => received++)
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array(0))
    expect(received).toBe(0)
    expect(warnSpy).not.toHaveBeenCalled()
    warnSpy.mockRestore()
  })

  it('decryption-fail frames trigger console.warn (not silent)', () => {
    // mB knows mA but the frame is corrupted before mB sees it.
    // openEnvelope throws, which the messenger logs as a warning.
    mA.registerFriend(peerRecordOf(idB))
    mB.registerFriend(peerRecordOf(idA))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    let received = 0
    mB.onEnvelope(() => received++)

    // Tamper the frame in the FakeSocket's pre-dispatch hook —
    // simulates a man-in-the-middle bit flip on the wire after the
    // relay rewrites the peer field but before the recipient sees it.
    sockA.beforeDispatch = (frame) => {
      frame[60] ^= 0x01 // bit-flip in the sealed-payload region
    }
    mA.send(idB.ed25519Pub, INNER_TYPE_JSON_CONTROL, new Uint8Array([0x42]))

    expect(received).toBe(0)
    expect(warnSpy).toHaveBeenCalled()
    warnSpy.mockRestore()
  })
})
