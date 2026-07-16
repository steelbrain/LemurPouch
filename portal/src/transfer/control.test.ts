import { describe, expect, it } from 'vitest'

import { WireProtocolError, base64ToBytes, bytesToBase64 } from '../relay/wire'

import {
  TRANSFER_ID_LEN,
  TYPE_TRANSFER_ACCEPT,
  TYPE_TRANSFER_ACK,
  TYPE_TRANSFER_END,
  TYPE_TRANSFER_OFFER,
  TYPE_TRANSFER_REJECT,
  buildTransferAccept,
  buildTransferAck,
  buildTransferEnd,
  buildTransferOffer,
  buildTransferReject,
  parseTransferAccept,
  parseTransferAck,
  parseTransferControl,
  parseTransferEnd,
  parseTransferOffer,
  parseTransferReject,
} from './control'

const sampleTransferId = new Uint8Array(TRANSFER_ID_LEN).fill(0x77)
const sampleSha256 = new Uint8Array(32).fill(0x88)

describe('build + parse round-trips', () => {
  it('transfer-offer', () => {
    const json = buildTransferOffer(sampleTransferId, 'photo.jpg', 1_048_576)
    const msg = parseTransferOffer(json)
    expect(msg.type).toBe(TYPE_TRANSFER_OFFER)
    expect(Array.from(msg.transferId)).toEqual(Array.from(sampleTransferId))
    expect(msg.filename).toBe('photo.jpg')
    expect(msg.size).toBe(1_048_576)
  })

  it('transfer-accept', () => {
    const json = buildTransferAccept(sampleTransferId)
    const msg = parseTransferAccept(json)
    expect(msg.type).toBe(TYPE_TRANSFER_ACCEPT)
    expect(Array.from(msg.transferId)).toEqual(Array.from(sampleTransferId))
    expect(msg.maxChunkBytes).toBeUndefined()
    expect(msg.windowBytes).toBeUndefined()
  })

  it('transfer-accept with capacity ads', () => {
    const json = buildTransferAccept(sampleTransferId, {
      maxChunkBytes: 1_048_576,
      windowBytes: 8_388_608,
    })
    const obj = JSON.parse(json) as Record<string, unknown>
    expect(obj.max_chunk_bytes).toBe(1_048_576)
    expect(obj.window_bytes).toBe(8_388_608)
    const msg = parseTransferAccept(json)
    expect(msg.maxChunkBytes).toBe(1_048_576)
    expect(msg.windowBytes).toBe(8_388_608)
  })

  it('transfer-accept floors sub-64Ki max_chunk_bytes', () => {
    const json = buildTransferAccept(sampleTransferId, { maxChunkBytes: 1000 })
    const msg = parseTransferAccept(json)
    expect(msg.maxChunkBytes).toBe(64 * 1024)
  })

  it('transfer-ack round-trip', () => {
    const json = buildTransferAck(sampleTransferId, 123456789)
    const obj = JSON.parse(json) as Record<string, unknown>
    expect(obj.type).toBe(TYPE_TRANSFER_ACK)
    expect(obj.received_bytes).toBe(123456789)
    const msg = parseTransferAck(json)
    expect(msg.receivedBytes).toBe(123456789)
  })

  it('parseTransferControl drops unknown types', () => {
    expect(
      parseTransferControl(
        JSON.stringify({ type: 'transfer-future', transfer_id: bytesToBase64(sampleTransferId) }),
      ),
    ).toBeNull()
  })

  it('parseTransferControl dispatches transfer-ack', () => {
    const json = buildTransferAck(sampleTransferId, 42)
    const msg = parseTransferControl(json)
    expect(msg?.type).toBe(TYPE_TRANSFER_ACK)
  })

  it('unknown JSON fields on accept are ignored', () => {
    const json = JSON.stringify({
      type: TYPE_TRANSFER_ACCEPT,
      transfer_id: bytesToBase64(sampleTransferId),
      future_field: true,
    })
    const msg = parseTransferAccept(json)
    expect(msg.transferId.length).toBe(TRANSFER_ID_LEN)
  })

  it('transfer-reject (no reason)', () => {
    const json = buildTransferReject(sampleTransferId)
    const obj = JSON.parse(json) as Record<string, unknown>
    expect(obj).not.toHaveProperty('reason') // omit field when undefined
    const msg = parseTransferReject(json)
    expect(msg.type).toBe(TYPE_TRANSFER_REJECT)
    expect(msg.reason).toBeUndefined()
  })

  it('transfer-reject (with reason)', () => {
    const json = buildTransferReject(sampleTransferId, 'out of disk space')
    const msg = parseTransferReject(json)
    expect(msg.reason).toBe('out of disk space')
  })

  it('transfer-end', () => {
    const json = buildTransferEnd(sampleTransferId, sampleSha256)
    const msg = parseTransferEnd(json)
    expect(msg.type).toBe(TYPE_TRANSFER_END)
    expect(Array.from(msg.transferId)).toEqual(Array.from(sampleTransferId))
    expect(Array.from(msg.sha256)).toEqual(Array.from(sampleSha256))
  })
})

describe('JSON field-name pinning', () => {
  // Pin the snake_case field names. Drift here silently breaks Go-TS
  // interop — same role as the FriendshipJSONFieldNames pinning test
  // in wire.test.ts.
  it('transfer-offer uses transfer_id, filename, size', () => {
    const json = buildTransferOffer(sampleTransferId, 'a', 1)
    const obj = JSON.parse(json) as Record<string, unknown>
    expect(obj.type).toBe(TYPE_TRANSFER_OFFER)
    expect(typeof obj.transfer_id).toBe('string')
    expect(typeof obj.filename).toBe('string')
    expect(typeof obj.size).toBe('number')
    expect(Object.keys(obj).sort()).toEqual([
      'filename',
      'size',
      'transfer_id',
      'type',
    ])
  })

  it('transfer-end uses transfer_id, sha256', () => {
    const obj = JSON.parse(buildTransferEnd(sampleTransferId, sampleSha256)) as Record<string, unknown>
    expect(obj.type).toBe(TYPE_TRANSFER_END)
    expect(typeof obj.transfer_id).toBe('string')
    expect(typeof obj.sha256).toBe('string')
    expect(Object.keys(obj).sort()).toEqual(['sha256', 'transfer_id', 'type'])
  })

  it('transfer-accept uses transfer_id only (legacy)', () => {
    const obj = JSON.parse(buildTransferAccept(sampleTransferId)) as Record<string, unknown>
    expect(Object.keys(obj).sort()).toEqual(['transfer_id', 'type'])
  })

  it('transfer-ack uses transfer_id + received_bytes', () => {
    const obj = JSON.parse(buildTransferAck(sampleTransferId, 1)) as Record<string, unknown>
    expect(Object.keys(obj).sort()).toEqual(['received_bytes', 'transfer_id', 'type'])
  })

  it('transfer-reject (with reason) uses transfer_id + reason', () => {
    const obj = JSON.parse(buildTransferReject(sampleTransferId, 'no')) as Record<string, unknown>
    expect(Object.keys(obj).sort()).toEqual(['reason', 'transfer_id', 'type'])
  })
})

describe('build helpers reject bad inputs', () => {
  it.each([
    ['short transfer_id', new Uint8Array(15), /transfer_id must be 16 bytes/],
    ['long transfer_id', new Uint8Array(17), /transfer_id must be 16 bytes/],
  ])('transfer-offer: %s', (_name, tid, msg) => {
    expect(() => buildTransferOffer(tid, 'f', 1)).toThrow(msg)
  })

  it.each<[string, number]>([
    ['negative', -1],
    ['fractional', 1.5],
    ['NaN', Number.NaN],
    ['+Infinity', Number.POSITIVE_INFINITY],
  ])('transfer-offer: rejects size = %s', (_name, size) => {
    expect(() => buildTransferOffer(sampleTransferId, 'f', size)).toThrow(
      /size must be a non-negative integer/,
    )
  })

  it.each([
    ['short transfer_id', new Uint8Array(15), sampleSha256, /transfer_id must be 16 bytes/],
    ['long transfer_id', new Uint8Array(17), sampleSha256, /transfer_id must be 16 bytes/],
    ['short sha256', sampleTransferId, new Uint8Array(31), /sha256 must be 32 bytes/],
    ['long sha256', sampleTransferId, new Uint8Array(33), /sha256 must be 32 bytes/],
  ])('transfer-end: %s', (_name, tid, sha, msg) => {
    expect(() => buildTransferEnd(tid, sha)).toThrow(msg)
  })

  it('transfer-accept rejects wrong-size transfer_id', () => {
    expect(() => buildTransferAccept(new Uint8Array(15))).toThrow(WireProtocolError)
  })

  it('transfer-reject rejects wrong-size transfer_id', () => {
    expect(() => buildTransferReject(new Uint8Array(15), 'no')).toThrow(WireProtocolError)
    expect(() => buildTransferReject(new Uint8Array(15))).toThrow(WireProtocolError)
  })

  it('transfer-end rejects wrong-size transfer_id', () => {
    expect(() => buildTransferEnd(new Uint8Array(15), sampleSha256)).toThrow(WireProtocolError)
  })
})

describe('parsers reject bad inputs', () => {
  function offerJson(overrides: Record<string, unknown> = {}): string {
    return JSON.stringify({
      type: TYPE_TRANSFER_OFFER,
      transfer_id: bytesToBase64(sampleTransferId),
      filename: 'photo.jpg',
      size: 1024,
      ...overrides,
    })
  }

  function endJson(overrides: Record<string, unknown> = {}): string {
    return JSON.stringify({
      type: TYPE_TRANSFER_END,
      transfer_id: bytesToBase64(sampleTransferId),
      sha256: bytesToBase64(sampleSha256),
      ...overrides,
    })
  }

  it('rejects malformed JSON', () => {
    expect(() => parseTransferOffer('{not json')).toThrow(WireProtocolError)
  })

  it('rejects wrong type discriminator', () => {
    expect(() => parseTransferOffer(offerJson({ type: TYPE_TRANSFER_END }))).toThrow(
      WireProtocolError,
    )
  })

  it('rejects truncated transfer_id (would-be 12 bytes)', () => {
    const shortId = new Uint8Array(12).fill(0x99)
    expect(() => parseTransferOffer(offerJson({ transfer_id: bytesToBase64(shortId) }))).toThrow(
      /transfer_id.*must decode to 16 bytes/,
    )
  })

  it('rejects transfer-end with truncated sha256', () => {
    const shortHash = new Uint8Array(20).fill(0xab)
    expect(() => parseTransferEnd(endJson({ sha256: bytesToBase64(shortHash) }))).toThrow(
      /sha256.*must decode to 32 bytes/,
    )
  })

  it('rejects transfer-end with missing sha256', () => {
    const obj = {
      type: TYPE_TRANSFER_END,
      transfer_id: bytesToBase64(sampleTransferId),
    }
    expect(() => parseTransferEnd(JSON.stringify(obj))).toThrow(/sha256/)
  })

  it('rejects missing filename', () => {
    const obj = {
      type: TYPE_TRANSFER_OFFER,
      transfer_id: bytesToBase64(sampleTransferId),
      size: 1,
    }
    expect(() => parseTransferOffer(JSON.stringify(obj))).toThrow(/filename/)
  })

  it('rejects negative size', () => {
    expect(() => parseTransferOffer(offerJson({ size: -1 }))).toThrow(/size/)
  })

  it('rejects non-integer size', () => {
    expect(() => parseTransferOffer(offerJson({ size: 1.5 }))).toThrow(/size/)
  })

  it('rejects null transfer_id (Go nil-slice JSON)', () => {
    expect(() => parseTransferOffer(offerJson({ transfer_id: null }))).toThrow(WireProtocolError)
  })

  it('parseTransferReject accepts missing reason as undefined', () => {
    const json = JSON.stringify({
      type: TYPE_TRANSFER_REJECT,
      transfer_id: bytesToBase64(sampleTransferId),
    })
    const msg = parseTransferReject(json)
    expect(msg.reason).toBeUndefined()
  })

  it('parseTransferReject treats reason: null as missing', () => {
    // Forward compat with a hypothetical Go optional pointer-to-string
    // field that marshals null when unset.
    const json = JSON.stringify({
      type: TYPE_TRANSFER_REJECT,
      transfer_id: bytesToBase64(sampleTransferId),
      reason: null,
    })
    const msg = parseTransferReject(json)
    expect(msg.reason).toBeUndefined()
  })
})

describe('parseTransferControl dispatcher', () => {
  it.each([TYPE_TRANSFER_OFFER, TYPE_TRANSFER_ACCEPT, TYPE_TRANSFER_REJECT, TYPE_TRANSFER_END])(
    'dispatches %s',
    (typ) => {
      // Build the right shape for each type so the per-type parser
      // succeeds inside the dispatcher.
      let json: string
      if (typ === TYPE_TRANSFER_OFFER) {
        json = buildTransferOffer(sampleTransferId, 'f', 1)
      } else if (typ === TYPE_TRANSFER_ACCEPT) {
        json = buildTransferAccept(sampleTransferId)
      } else if (typ === TYPE_TRANSFER_REJECT) {
        json = buildTransferReject(sampleTransferId)
      } else {
        json = buildTransferEnd(sampleTransferId, sampleSha256)
      }
      const msg = parseTransferControl(json)
      expect(msg?.type).toBe(typ)
    },
  )

  it('returns null for non-transfer types', () => {
    // Discovery / friendship messages, unknown types, malformed JSON
    // — all should return null (caller treats them as "not for me").
    expect(parseTransferControl(JSON.stringify({ type: 'peer-list', peers: [] }))).toBeNull()
    expect(parseTransferControl(JSON.stringify({ type: 'invite-from', from: 'AA==' }))).toBeNull()
    expect(parseTransferControl('{not json')).toBeNull()
    expect(parseTransferControl('')).toBeNull()
    expect(parseTransferControl('{}')).toBeNull()
  })

  it('throws when the type matches but the payload is malformed', () => {
    // Differentiates "not for me" (null) from "broken transfer message"
    // (throw) — same contract as parseDiscovery / parseFriendshipNotification.
    const broken = JSON.stringify({
      type: TYPE_TRANSFER_OFFER,
      transfer_id: bytesToBase64(sampleTransferId),
      // missing filename + size
    })
    expect(() => parseTransferControl(broken)).toThrow(WireProtocolError)
  })
})

describe('base64 encoding compatibility with Go side', () => {
  it('transfer-offer round-trips through base64ToBytes', () => {
    const json = buildTransferOffer(sampleTransferId, 'f', 1)
    const obj = JSON.parse(json) as Record<string, unknown>
    expect(base64ToBytes(obj.transfer_id as string).length).toBe(TRANSFER_ID_LEN)
  })

  it('transfer-end round-trips through base64ToBytes', () => {
    const json = buildTransferEnd(sampleTransferId, sampleSha256)
    const obj = JSON.parse(json) as Record<string, unknown>
    expect(base64ToBytes(obj.transfer_id as string).length).toBe(TRANSFER_ID_LEN)
    expect(base64ToBytes(obj.sha256 as string).length).toBe(32)
  })
})
