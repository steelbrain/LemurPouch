import { describe, expect, it } from 'vitest'

import {
  ENVELOPE_HEADER_LEN,
  ENVELOPE_MIN_FRAME_LEN,
  ENVELOPE_MIN_SEALED_LEN,
  ENVELOPE_NONCE_LEN,
  ENVELOPE_PEER_KEY_LEN,
  EnvelopeError,
  INNER_TYPE_FILE_CHUNK,
  INNER_TYPE_JSON_CONTROL,
  marshalEnvelope,
  parseEnvelopeHeader,
  rewriteDestinationToSource,
} from './envelope'

// Helper that mirrors the Go-side envelopeFixture: build a deterministic
// frame with each region filled with a distinct byte so a misaligned
// slice or off-by-one is obvious in the failure output.
function envelopeFixture(innerType: number, sealedLen: number): {
  frame: Uint8Array
  peerKey: Uint8Array
  nonce: Uint8Array
  sealed: Uint8Array
} {
  if (sealedLen < ENVELOPE_MIN_SEALED_LEN) {
    throw new Error(`envelopeFixture: sealedLen ${sealedLen} below minimum`)
  }
  const peerKey = new Uint8Array(ENVELOPE_PEER_KEY_LEN).fill(0xaa)
  const nonce = new Uint8Array(ENVELOPE_NONCE_LEN).fill(0xbb)
  const sealed = new Uint8Array(sealedLen).fill(0xcc)
  const frame = marshalEnvelope(innerType, peerKey, nonce, sealed)
  return { frame, peerKey, nonce, sealed }
}

describe('envelope constants', () => {
  // Pin the wire layout against accidental refactor — this mirrors the
  // Go-side TestEnvelopeHeaderConstants. 1+32+24=57 header, +16 tag = 73 min.
  it('match the spec layout', () => {
    expect(ENVELOPE_PEER_KEY_LEN).toBe(32)
    expect(ENVELOPE_NONCE_LEN).toBe(24)
    expect(ENVELOPE_HEADER_LEN).toBe(57)
    expect(ENVELOPE_MIN_SEALED_LEN).toBe(16)
    expect(ENVELOPE_MIN_FRAME_LEN).toBe(73)
  })
})

describe('marshalEnvelope + parseEnvelopeHeader round-trip', () => {
  it.each([
    ['json-control-min', INNER_TYPE_JSON_CONTROL, ENVELOPE_MIN_SEALED_LEN],
    ['json-control-typical', INNER_TYPE_JSON_CONTROL, 256],
    ['file-chunk-typical', INNER_TYPE_FILE_CHUNK, 64 * 1024],
    // Unknown inner type is allowed at the wire layer (forward-compat).
    ['unknown-inner-type', 0xff, ENVELOPE_MIN_SEALED_LEN],
  ])('%s', (_name, innerType, sealedLen) => {
    const { frame, peerKey, nonce, sealed } = envelopeFixture(innerType, sealedLen)
    expect(frame.length).toBe(ENVELOPE_HEADER_LEN + sealedLen)
    const { header, sealed: gotSealed } = parseEnvelopeHeader(frame)
    expect(header.innerType).toBe(innerType)
    expect(Array.from(header.peerKey)).toEqual(Array.from(peerKey))
    expect(Array.from(header.nonce)).toEqual(Array.from(nonce))
    expect(Array.from(gotSealed)).toEqual(Array.from(sealed))
  })
})

describe('parseEnvelopeHeader aliasing', () => {
  // The header docstring promises peerKey + nonce alias the source
  // frame (zero-copy via subarray). This test pins that contract — a
  // refactor to allocate fresh copies would silently regress callers
  // (notably the receiver code that calls rewriteDestinationToSource
  // on the same buffer in tests / re-encode paths).
  it('peerKey and nonce alias the source frame buffer', () => {
    const { frame } = envelopeFixture(INNER_TYPE_JSON_CONTROL, ENVELOPE_MIN_SEALED_LEN)
    const { header, sealed } = parseEnvelopeHeader(frame)
    frame[1] = 0x99
    frame[33] = 0x88
    frame[57] = 0x77
    expect(header.peerKey[0]).toBe(0x99)
    expect(header.nonce[0]).toBe(0x88)
    expect(sealed[0]).toBe(0x77)
  })
})

describe('parseEnvelopeHeader rejects short frames', () => {
  it.each([0, 1, ENVELOPE_HEADER_LEN, ENVELOPE_MIN_FRAME_LEN - 1])(
    'rejects frame of length %i',
    (n) => {
      const short = new Uint8Array(n)
      expect(() => parseEnvelopeHeader(short)).toThrow(EnvelopeError)
      expect(() => parseEnvelopeHeader(short)).toThrow(/too short/)
    },
  )
})

describe('marshalEnvelope rejects bad component sizes', () => {
  const goodPeerKey = new Uint8Array(ENVELOPE_PEER_KEY_LEN).fill(0x01)
  const goodNonce = new Uint8Array(ENVELOPE_NONCE_LEN).fill(0x02)
  const goodSealed = new Uint8Array(ENVELOPE_MIN_SEALED_LEN).fill(0x03)

  it.each<[string, Uint8Array, Uint8Array, Uint8Array, RegExp]>([
    ['short-peer-key', new Uint8Array(31), goodNonce, goodSealed, /peer key/],
    ['long-peer-key', new Uint8Array(33), goodNonce, goodSealed, /peer key/],
    ['empty-peer-key', new Uint8Array(0), goodNonce, goodSealed, /peer key/],
    ['short-nonce', goodPeerKey, new Uint8Array(23), goodSealed, /nonce/],
    ['long-nonce', goodPeerKey, new Uint8Array(25), goodSealed, /nonce/],
    ['short-sealed', goodPeerKey, goodNonce, new Uint8Array(15), /sealed payload/],
    ['empty-sealed', goodPeerKey, goodNonce, new Uint8Array(0), /sealed payload/],
  ])('%s', (_name, pk, n, s, msg) => {
    expect(() => marshalEnvelope(INNER_TYPE_JSON_CONTROL, pk, n, s)).toThrow(EnvelopeError)
    expect(() => marshalEnvelope(INNER_TYPE_JSON_CONTROL, pk, n, s)).toThrow(msg)
  })
})

describe('rewriteDestinationToSource', () => {
  it('overwrites the peer-key region in place and touches nothing else', () => {
    const { frame, nonce, sealed } = envelopeFixture(INNER_TYPE_JSON_CONTROL, 128)
    const origInnerType = frame[0]
    const newKey = new Uint8Array(ENVELOPE_PEER_KEY_LEN).fill(0x55)

    rewriteDestinationToSource(frame, newKey)

    expect(frame[0]).toBe(origInnerType)
    expect(Array.from(frame.subarray(1, 33))).toEqual(Array.from(newKey))
    expect(Array.from(frame.subarray(33, 57))).toEqual(Array.from(nonce))
    expect(Array.from(frame.subarray(57))).toEqual(Array.from(sealed))
  })

  it('rejects a frame too short for the header', () => {
    const short = new Uint8Array(ENVELOPE_HEADER_LEN - 1)
    const goodKey = new Uint8Array(ENVELOPE_PEER_KEY_LEN).fill(0x55)
    expect(() => rewriteDestinationToSource(short, goodKey)).toThrow(EnvelopeError)
  })

  it.each([31, 33, 0])('rejects a source key of length %i', (n) => {
    const { frame } = envelopeFixture(INNER_TYPE_JSON_CONTROL, ENVELOPE_MIN_SEALED_LEN)
    const badKey = new Uint8Array(n).fill(0x55)
    expect(() => rewriteDestinationToSource(frame, badKey)).toThrow(EnvelopeError)
  })
})
