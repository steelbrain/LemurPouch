// Tests for the wire-protocol parsing/encoding helpers. The connection
// client (./client.ts) is exercised end-to-end against the live relay
// from App.tsx; pure-function tests live here.

import { describe, expect, it } from 'vitest'
import {
  ERR_INVALID_SIGNATURE,
  RelayRejectedError,
  TYPE_ACCEPT,
  TYPE_ACCEPT_FROM,
  TYPE_CHALLENGE,
  TYPE_ERROR,
  TYPE_IDENTIFY,
  TYPE_INVITE,
  TYPE_INVITE_AUTO_REJECTED,
  TYPE_INVITE_DEFERRED,
  TYPE_INVITE_FROM,
  TYPE_PEER_JOINED,
  TYPE_PEER_LEFT,
  TYPE_PEER_LIST,
  TYPE_REJECT,
  TYPE_REJECT_FROM,
  TYPE_WELCOME,
  WireProtocolError,
  base64ToBytes,
  buildAcceptMsg,
  buildIdentifyMsg,
  buildInviteMsg,
  buildRejectMsg,
  bytesToBase64,
  parseAcceptFrom,
  parseChallenge,
  parseDiscovery,
  parseError,
  parseFriendshipNotification,
  parseInviteAutoRejected,
  parseInviteDeferred,
  parseInviteFrom,
  parsePeerJoined,
  parsePeerLeft,
  parsePeerList,
  parsePeerRecord,
  parseRejectFrom,
  parseWelcome,
  peekType,
} from './wire'

describe('base64 helpers', () => {
  it('round-trip preserves bytes including 0 and 0xff', () => {
    const b = new Uint8Array([0, 1, 2, 0x7f, 0x80, 0xfe, 0xff])
    expect(base64ToBytes(bytesToBase64(b))).toEqual(b)
  })

  it('handles empty input', () => {
    expect(bytesToBase64(new Uint8Array(0))).toBe('')
    expect(base64ToBytes('')).toEqual(new Uint8Array(0))
  })

  it('produces standard base64 with padding (matches Go encoding/json)', () => {
    // 32 bytes of 0xAA → known base64 with padding. encoding/json uses
    // RFC 4648 standard alphabet with padding by default.
    const b = new Uint8Array(32).fill(0xaa)
    const enc = bytesToBase64(b)
    expect(enc.endsWith('=') || enc.length % 4 === 0).toBe(true)
    expect(base64ToBytes(enc)).toEqual(b)
  })
})

describe('peekType', () => {
  it('extracts type from a valid frame', () => {
    expect(peekType('{"type":"challenge","nonce":"AA=="}')).toBe(TYPE_CHALLENGE)
    expect(peekType('{"type":"welcome"}')).toBe(TYPE_WELCOME)
  })

  it('returns null on malformed JSON', () => {
    expect(peekType('{not json')).toBeNull()
    expect(peekType('')).toBeNull()
  })

  it('returns null when the type field is missing or non-string', () => {
    expect(peekType('{}')).toBeNull()
    expect(peekType('{"type":42}')).toBeNull()
    expect(peekType('{"type":null}')).toBeNull()
  })

  it('returns null for non-object JSON', () => {
    expect(peekType('"a string"')).toBeNull()
    expect(peekType('42')).toBeNull()
    expect(peekType('null')).toBeNull()
    expect(peekType('[1,2,3]')).toBeNull()
  })
})

describe('parseChallenge', () => {
  it('parses a valid challenge', () => {
    const nonceBytes = new Uint8Array(32).fill(0x42)
    const json = JSON.stringify({ type: TYPE_CHALLENGE, nonce: bytesToBase64(nonceBytes) })
    const c = parseChallenge(json)
    expect(c.type).toBe(TYPE_CHALLENGE)
    expect(c.nonce).toEqual(nonceBytes)
  })

  it('throws WireProtocolError on wrong type', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, nonce: 'AA==' })
    expect(() => parseChallenge(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on missing nonce', () => {
    expect(() => parseChallenge(JSON.stringify({ type: TYPE_CHALLENGE }))).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on malformed JSON', () => {
    expect(() => parseChallenge('{not json')).toThrow(WireProtocolError)
  })
})

describe('parsePeerRecord / parseWelcome', () => {
  const sampleYou = {
    ed25519_pub: bytesToBase64(new Uint8Array(32).fill(0xaa)),
    x25519_pub: bytesToBase64(new Uint8Array(32).fill(0xbb)),
    sig_binding: bytesToBase64(new Uint8Array(64).fill(0xcc)),
    ip: '192.168.1.42',
    port: 54321,
  }

  it('parses a peer record', () => {
    const r = parsePeerRecord(sampleYou)
    expect(r.ed25519Pub.length).toBe(32)
    expect(r.x25519Pub.length).toBe(32)
    expect(r.sigBinding.length).toBe(64)
    expect(r.ed25519Pub[0]).toBe(0xaa)
    expect(r.ip).toBe('192.168.1.42')
    expect(r.port).toBe(54321)
  })

  it('parses welcome limits when present', () => {
    const you = {
      ed25519_pub: bytesToBase64(new Uint8Array(32).fill(1)),
      x25519_pub: bytesToBase64(new Uint8Array(32).fill(2)),
      sig_binding: bytesToBase64(new Uint8Array(64).fill(3)),
      ip: '10.0.0.1',
      port: 9,
    }
    const w = parseWelcome(
      JSON.stringify({
        type: TYPE_WELCOME,
        you,
        limits: { max_chunk_bytes: 1_048_576 },
      }),
    )
    expect(w.limits?.maxChunkBytes).toBe(1_048_576)
  })

  it('welcome without limits is valid (old relay)', () => {
    const you = {
      ed25519_pub: bytesToBase64(new Uint8Array(32).fill(1)),
      x25519_pub: bytesToBase64(new Uint8Array(32).fill(2)),
      sig_binding: bytesToBase64(new Uint8Array(64).fill(3)),
      ip: '10.0.0.1',
      port: 9,
    }
    const w = parseWelcome(JSON.stringify({ type: TYPE_WELCOME, you }))
    expect(w.limits).toBeUndefined()
  })

  it('floors welcome max_chunk_bytes below 64 KiB', () => {
    const you = {
      ed25519_pub: bytesToBase64(new Uint8Array(32).fill(1)),
      x25519_pub: bytesToBase64(new Uint8Array(32).fill(2)),
      sig_binding: bytesToBase64(new Uint8Array(64).fill(3)),
      ip: '10.0.0.1',
      port: 9,
    }
    const w = parseWelcome(
      JSON.stringify({
        type: TYPE_WELCOME,
        you,
        limits: { max_chunk_bytes: 1000 },
      }),
    )
    expect(w.limits?.maxChunkBytes).toBe(64 * 1024)
  })

  it('parses a welcome containing a peer record', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, you: sampleYou })
    const w = parseWelcome(json)
    expect(w.type).toBe(TYPE_WELCOME)
    expect(w.you.ip).toBe('192.168.1.42')
    expect(w.you.port).toBe(54321)
  })

  it('rejects a welcome with malformed peer record', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, you: { ip: 'x', port: 1 } }) // missing keys
    expect(() => parseWelcome(json)).toThrow(WireProtocolError)
  })

  it('rejects port that is not an integer', () => {
    const bad = { ...sampleYou, port: '54321' as unknown as number }
    expect(() => parsePeerRecord(bad)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on wrong type discriminator', () => {
    const json = JSON.stringify({ type: TYPE_ERROR, code: 'x', message: 'y' })
    expect(() => parseWelcome(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on malformed JSON', () => {
    expect(() => parseWelcome('{not json')).toThrow(WireProtocolError)
  })

  it('wraps malformed base64 byte fields in WireProtocolError', () => {
    // atob throws DOMException on invalid base64; the parser must surface
    // it as the typed WireProtocolError contract callers rely on.
    const bad = { ...sampleYou, ed25519_pub: '!!not-base64!!' }
    expect(() => parsePeerRecord(bad)).toThrow(WireProtocolError)
  })

  it('rejects a null byte field (dual of Go TestNilByteFieldsMarshalAsNull)', () => {
    // Go marshals nil []byte as JSON null; the TS receiver must reject it
    // with WireProtocolError because expectString refuses non-strings.
    const bad = { ...sampleYou, ed25519_pub: null as unknown as string }
    expect(() => parsePeerRecord(bad)).toThrow(WireProtocolError)
  })
})

describe('parseError', () => {
  it('parses a valid error', () => {
    const json = JSON.stringify({
      type: TYPE_ERROR,
      code: ERR_INVALID_SIGNATURE,
      message: 'sig_liveness verification failed',
    })
    const e = parseError(json)
    expect(e.code).toBe(ERR_INVALID_SIGNATURE)
    expect(e.message).toContain('sig_liveness')
  })

  it('throws WireProtocolError on wrong type discriminator', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, you: {} })
    expect(() => parseError(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on malformed JSON', () => {
    expect(() => parseError('{not json')).toThrow(WireProtocolError)
  })
})

describe('buildIdentifyMsg', () => {
  it('produces JSON with the spec-mandated field names', () => {
    const json = buildIdentifyMsg({
      ed25519Pub: new Uint8Array(32).fill(0x11),
      x25519Pub: new Uint8Array(32).fill(0x22),
      sigLiveness: new Uint8Array(64).fill(0x33),
      sigBinding: new Uint8Array(64).fill(0x44),
    })
    const obj = JSON.parse(json)
    expect(obj.type).toBe(TYPE_IDENTIFY)
    // snake_case names matching internal/wireproto/wireproto.go's struct tags
    expect(typeof obj.ed25519_pub).toBe('string')
    expect(typeof obj.x25519_pub).toBe('string')
    expect(typeof obj.sig_liveness).toBe('string')
    expect(typeof obj.sig_binding).toBe('string')
    // Round-trip back to bytes
    expect(base64ToBytes(obj.ed25519_pub)[0]).toBe(0x11)
    expect(base64ToBytes(obj.x25519_pub)[0]).toBe(0x22)
    expect(base64ToBytes(obj.sig_liveness)[0]).toBe(0x33)
    expect(base64ToBytes(obj.sig_binding)[0]).toBe(0x44)
  })
})

describe('RelayRejectedError', () => {
  it('exposes code, name, and a message including the code', () => {
    const e = new RelayRejectedError({
      type: TYPE_ERROR,
      code: ERR_INVALID_SIGNATURE,
      message: 'oops',
    })
    expect(e.code).toBe(ERR_INVALID_SIGNATURE)
    expect(e.name).toBe('RelayRejectedError')
    expect(e.message).toContain(ERR_INVALID_SIGNATURE)
    expect(e.message).toContain('oops')
  })
})

describe('parsePeerList', () => {
  const samplePeer = {
    ed25519_pub: bytesToBase64(new Uint8Array(32).fill(0xaa)),
    x25519_pub: bytesToBase64(new Uint8Array(32).fill(0xbb)),
    sig_binding: bytesToBase64(new Uint8Array(64).fill(0xcc)),
    ip: '192.168.1.42',
    port: 54321,
  }

  it('parses a peer-list with one entry', () => {
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: [samplePeer] })
    const m = parsePeerList(json)
    expect(m.type).toBe(TYPE_PEER_LIST)
    expect(m.peers.length).toBe(1)
    expect(m.peers[0].ed25519Pub[0]).toBe(0xaa)
    expect(m.peers[0].port).toBe(54321)
  })

  it('parses an empty peer-list (peers: [])', () => {
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: [] })
    const m = parsePeerList(json)
    expect(m.peers).toEqual([])
  })

  it('treats peers: null the same as an empty list (Go nil-slice JSON)', () => {
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: null })
    const m = parsePeerList(json)
    expect(m.peers).toEqual([])
  })

  it('throws WireProtocolError on wrong type discriminator', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, peers: [] })
    expect(() => parsePeerList(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError when peers is not an array', () => {
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: 'oops' })
    expect(() => parsePeerList(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError when a peer entry is malformed', () => {
    const bad = { ...samplePeer, port: 'not-a-number' as unknown as number }
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: [bad] })
    expect(() => parsePeerList(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError when a peer entry is null', () => {
    // expectObject in parsePeerRecord refuses null, so [null] must throw —
    // protects against a Go side that accidentally serializes a nil
    // PeerRecord pointer inside the slice.
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: [null] })
    expect(() => parsePeerList(json)).toThrow(WireProtocolError)
  })
})

describe('parsePeerJoined', () => {
  const samplePeer = {
    ed25519_pub: bytesToBase64(new Uint8Array(32).fill(0x11)),
    x25519_pub: bytesToBase64(new Uint8Array(32).fill(0x22)),
    sig_binding: bytesToBase64(new Uint8Array(64).fill(0x33)),
    ip: '10.0.0.5',
    port: 12345,
  }

  it('parses a peer-joined', () => {
    const json = JSON.stringify({ type: TYPE_PEER_JOINED, peer: samplePeer })
    const m = parsePeerJoined(json)
    expect(m.type).toBe(TYPE_PEER_JOINED)
    expect(m.peer.ed25519Pub[0]).toBe(0x11)
    expect(m.peer.ip).toBe('10.0.0.5')
  })

  it('throws WireProtocolError on wrong type discriminator', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, peer: samplePeer })
    expect(() => parsePeerJoined(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError when peer is missing', () => {
    const json = JSON.stringify({ type: TYPE_PEER_JOINED })
    expect(() => parsePeerJoined(json)).toThrow(WireProtocolError)
  })
})

describe('parsePeerLeft', () => {
  it('parses a peer-left', () => {
    const ed = new Uint8Array(32).fill(0x44)
    const json = JSON.stringify({
      type: TYPE_PEER_LEFT,
      ed25519_pub: bytesToBase64(ed),
    })
    const m = parsePeerLeft(json)
    expect(m.type).toBe(TYPE_PEER_LEFT)
    expect(m.ed25519Pub).toEqual(ed)
  })

  it('throws WireProtocolError on wrong type discriminator', () => {
    const json = JSON.stringify({ type: TYPE_WELCOME, ed25519_pub: 'AA==' })
    expect(() => parsePeerLeft(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on missing ed25519_pub', () => {
    const json = JSON.stringify({ type: TYPE_PEER_LEFT })
    expect(() => parsePeerLeft(json)).toThrow(WireProtocolError)
  })

  it('throws WireProtocolError on null ed25519_pub (Go nil []byte JSON)', () => {
    // Go marshals nil []byte as JSON null; the TS receiver must reject it
    // with WireProtocolError because expectString refuses non-strings.
    const json = JSON.stringify({ type: TYPE_PEER_LEFT, ed25519_pub: null })
    expect(() => parsePeerLeft(json)).toThrow(WireProtocolError)
  })
})

describe('parseDiscovery', () => {
  const samplePeer = {
    ed25519_pub: bytesToBase64(new Uint8Array(32).fill(0x11)),
    x25519_pub: bytesToBase64(new Uint8Array(32).fill(0x22)),
    sig_binding: bytesToBase64(new Uint8Array(64).fill(0x33)),
    ip: '10.0.0.5',
    port: 12345,
  }

  it('dispatches to parsePeerList for peer-list', () => {
    const json = JSON.stringify({ type: TYPE_PEER_LIST, peers: [samplePeer] })
    const m = parseDiscovery(json)
    expect(m).not.toBeNull()
    expect(m!.type).toBe(TYPE_PEER_LIST)
  })

  it('dispatches to parsePeerJoined for peer-joined', () => {
    const json = JSON.stringify({ type: TYPE_PEER_JOINED, peer: samplePeer })
    const m = parseDiscovery(json)
    expect(m).not.toBeNull()
    expect(m!.type).toBe(TYPE_PEER_JOINED)
  })

  it('dispatches to parsePeerLeft for peer-left', () => {
    const json = JSON.stringify({
      type: TYPE_PEER_LEFT,
      ed25519_pub: bytesToBase64(new Uint8Array(32)),
    })
    const m = parseDiscovery(json)
    expect(m).not.toBeNull()
    expect(m!.type).toBe(TYPE_PEER_LEFT)
  })

  it('returns null for non-discovery types (e.g. welcome, error)', () => {
    expect(parseDiscovery(JSON.stringify({ type: TYPE_WELCOME }))).toBeNull()
    expect(parseDiscovery(JSON.stringify({ type: TYPE_ERROR }))).toBeNull()
  })

  it('returns null for friendship-layer types (cross-layer separation)', () => {
    // The two top-level dispatchers must stay disjoint: a friendship
    // notification handed to parseDiscovery returns null (and vice versa,
    // covered by parseFriendshipNotification's own non-friendship test
    // below). Pinning both directions guards against a future refactor
    // accidentally collapsing the two layers' type spaces.
    const sampleFrom = bytesToBase64(new Uint8Array(32).fill(0x99))
    const cases = [
      JSON.stringify({ type: TYPE_INVITE_FROM, from: sampleFrom }),
      JSON.stringify({ type: TYPE_ACCEPT_FROM, from: sampleFrom }),
      JSON.stringify({ type: TYPE_REJECT_FROM, from: sampleFrom }),
      JSON.stringify({ type: TYPE_INVITE_DEFERRED, from: sampleFrom }),
      JSON.stringify({ type: TYPE_INVITE_AUTO_REJECTED, from: sampleFrom }),
    ]
    for (const json of cases) {
      expect(parseDiscovery(json)).toBeNull()
    }
  })

  it('returns null for malformed JSON or missing type', () => {
    expect(parseDiscovery('{not json')).toBeNull()
    expect(parseDiscovery('{}')).toBeNull()
    expect(parseDiscovery('"a string"')).toBeNull()
  })

  it('throws WireProtocolError when discovery type matches but payload is malformed', () => {
    // peer-joined with no peer field — type matches, payload is bad.
    expect(() =>
      parseDiscovery(JSON.stringify({ type: TYPE_PEER_JOINED })),
    ).toThrow(WireProtocolError)
  })
})

// --- friendship layer ---
//
// Mirrors internal/wireproto/friendship.go and Go-side
// internal/wireproto/friendship_test.go's TestFriendshipJSONFieldNames:
// any drift in the `type` discriminators or the `to` / `from` field
// names silently breaks Go-TS interop.

describe('build c2s friendship directives', () => {
  it.each([
    ['invite', buildInviteMsg, TYPE_INVITE],
    ['accept', buildAcceptMsg, TYPE_ACCEPT],
    ['reject', buildRejectMsg, TYPE_REJECT],
  ] as const)('%s pins type and to fields with snake_case names', (_, build, expectedType) => {
    const to = new Uint8Array(32).fill(0x77)
    const obj = JSON.parse(build(to))
    expect(obj.type).toBe(expectedType)
    expect(typeof obj.to).toBe('string')
    expect(base64ToBytes(obj.to)).toEqual(to)
    // Spec invariants: only two top-level keys, no stray fields.
    expect(Object.keys(obj).sort()).toEqual(['to', 'type'])
  })

  it('round-trips via parseFriendshipNotification when the relay echoes back as invite-from', () => {
    // The directive's `to` field becomes the corresponding notification's
    // `from` field on the other peer's wire — different name, same byte
    // identity. This test pins that mental model with an explicit example.
    const target = new Uint8Array(32).fill(0xab)
    const directive = JSON.parse(buildInviteMsg(target))
    const fakeNotification = JSON.stringify({
      type: TYPE_INVITE_FROM,
      from: directive.to,
    })
    const parsed = parseFriendshipNotification(fakeNotification)
    expect(parsed?.type).toBe(TYPE_INVITE_FROM)
    expect(parsed?.from).toEqual(target)
  })
})

describe('parse s2c friendship notifications', () => {
  // Each parser shares a uniform `{type, from}` shape; the table-driven
  // test asserts that every parser pins its expected type discriminator
  // and round-trips a 32-byte ed25519 public key through base64.
  it.each([
    ['invite-from', parseInviteFrom, TYPE_INVITE_FROM],
    ['accept-from', parseAcceptFrom, TYPE_ACCEPT_FROM],
    ['reject-from', parseRejectFrom, TYPE_REJECT_FROM],
    ['invite-deferred', parseInviteDeferred, TYPE_INVITE_DEFERRED],
    ['invite-auto-rejected', parseInviteAutoRejected, TYPE_INVITE_AUTO_REJECTED],
  ] as const)('%s round-trips', (_, parse, expectedType) => {
    const from = new Uint8Array(32).fill(0x55)
    const json = JSON.stringify({ type: expectedType, from: bytesToBase64(from) })
    const m = parse(json)
    expect(m.type).toBe(expectedType)
    expect(m.from).toEqual(from)
  })

  it('rejects a notification with the wrong type discriminator', () => {
    const json = JSON.stringify({ type: TYPE_ACCEPT_FROM, from: 'AA==' })
    expect(() => parseInviteFrom(json)).toThrow(WireProtocolError)
  })

  it('rejects a notification missing `from`', () => {
    const json = JSON.stringify({ type: TYPE_INVITE_FROM })
    expect(() => parseInviteFrom(json)).toThrow(WireProtocolError)
  })

  it('rejects a notification with a non-string `from`', () => {
    // Go marshals a nil []byte as JSON null; the TS receiver must reject
    // it with WireProtocolError because expectString refuses non-strings.
    const json = JSON.stringify({ type: TYPE_INVITE_FROM, from: null })
    expect(() => parseInviteFrom(json)).toThrow(WireProtocolError)
  })

  it('rejects a notification with malformed base64 in `from`', () => {
    const json = JSON.stringify({
      type: TYPE_INVITE_FROM,
      from: '!!not-base64!!',
    })
    expect(() => parseInviteFrom(json)).toThrow(WireProtocolError)
  })

  it('throws on malformed JSON', () => {
    expect(() => parseInviteFrom('{not json')).toThrow(WireProtocolError)
  })
})

describe('parseFriendshipNotification', () => {
  const sampleFrom = bytesToBase64(new Uint8Array(32).fill(0x33))

  it.each([
    [TYPE_INVITE_FROM],
    [TYPE_ACCEPT_FROM],
    [TYPE_REJECT_FROM],
    [TYPE_INVITE_DEFERRED],
    [TYPE_INVITE_AUTO_REJECTED],
  ] as const)('dispatches %s', (typ) => {
    const json = JSON.stringify({ type: typ, from: sampleFrom })
    const parsed = parseFriendshipNotification(json)
    expect(parsed?.type).toBe(typ)
    expect(parsed?.from.length).toBe(32)
  })

  it('returns null for non-friendship types', () => {
    const cases = [
      JSON.stringify({ type: TYPE_PEER_LIST, peers: [] }),
      JSON.stringify({ type: TYPE_PEER_JOINED, peer: {} }),
      JSON.stringify({ type: TYPE_PEER_LEFT, ed25519_pub: 'AA==' }),
      JSON.stringify({ type: TYPE_WELCOME, you: {} }),
      JSON.stringify({ type: 'envelope', any: 'thing' }), // future layer
    ]
    for (const json of cases) {
      expect(parseFriendshipNotification(json)).toBeNull()
    }
  })

  it('returns null for malformed JSON (mirrors peekType)', () => {
    expect(parseFriendshipNotification('{not json')).toBeNull()
    expect(parseFriendshipNotification('')).toBeNull()
  })

  it('returns null when the type field is missing or non-string', () => {
    // peekType returns null for these cases, so the dispatcher must too —
    // pinning the contract directly (not just transitively via peekType's
    // own tests) so a future refactor of the dispatcher can't silently
    // start treating a missing type as an error path.
    expect(parseFriendshipNotification('{}')).toBeNull()
    expect(parseFriendshipNotification('{"type":42}')).toBeNull()
    expect(parseFriendshipNotification('{"type":null}')).toBeNull()
  })

  it('throws WireProtocolError when the type matches but the payload is malformed', () => {
    // Differentiates "not a friendship message" (returns null) from
    // "broken friendship message" (throws). Same contract as
    // parseDiscovery elsewhere in this module.
    const json = JSON.stringify({ type: TYPE_INVITE_FROM }) // missing from
    expect(() => parseFriendshipNotification(json)).toThrow(WireProtocolError)
  })
})
