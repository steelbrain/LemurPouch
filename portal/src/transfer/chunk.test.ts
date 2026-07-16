import { describe, expect, it } from 'vitest'

import { TRANSFER_ID_LEN } from './control'
import {
  CHUNK_FLAG_LAST,
  CHUNK_HEADER_LEN,
  ChunkError,
  buildChunk,
  isLastChunk,
  parseChunk,
} from './chunk'

const sampleTransferId = new Uint8Array(TRANSFER_ID_LEN).fill(0x77)

describe('chunk constants', () => {
  it('match the spec layout', () => {
    expect(CHUNK_HEADER_LEN).toBe(21) // 16 (transfer_id) + 4 (seq) + 1 (flags)
    expect(CHUNK_FLAG_LAST).toBe(0x01)
  })
})

describe('buildChunk + parseChunk round-trip', () => {
  it('round-trips a typical chunk', () => {
    const data = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50])
    const wire = buildChunk(sampleTransferId, 42, CHUNK_FLAG_LAST, data)
    expect(wire.length).toBe(CHUNK_HEADER_LEN + data.length)

    const c = parseChunk(wire)
    expect(Array.from(c.transferId)).toEqual(Array.from(sampleTransferId))
    expect(c.seq).toBe(42)
    expect(c.flags).toBe(CHUNK_FLAG_LAST)
    expect(Array.from(c.data)).toEqual(Array.from(data))
    expect(isLastChunk(c.flags)).toBe(true)
  })

  it('round-trips an empty data chunk (header-only signaling)', () => {
    const wire = buildChunk(sampleTransferId, 0, CHUNK_FLAG_LAST, new Uint8Array(0))
    expect(wire.length).toBe(CHUNK_HEADER_LEN)
    const c = parseChunk(wire)
    expect(c.data.length).toBe(0)
    expect(isLastChunk(c.flags)).toBe(true)
  })

  it('round-trips a 64 KiB-data chunk (DESIGN target size)', () => {
    const data = new Uint8Array(64 * 1024)
    for (let i = 0; i < data.length; i++) data[i] = i & 0xff
    const wire = buildChunk(sampleTransferId, 1234, 0, data)
    const c = parseChunk(wire)
    expect(c.seq).toBe(1234)
    expect(c.data.length).toBe(data.length)
    // Spot-check: full equality on 64 KB on failure would dump a huge
    // diff into test output.
    expect(c.data[0]).toBe(0)
    expect(c.data[32 * 1024]).toBe((32 * 1024) & 0xff)
    expect(c.data[data.length - 1]).toBe((data.length - 1) & 0xff)
  })

  it('round-trips a non-last chunk (flags = 0)', () => {
    const wire = buildChunk(sampleTransferId, 5, 0, new Uint8Array([0x99]))
    const c = parseChunk(wire)
    expect(c.flags).toBe(0)
    expect(isLastChunk(c.flags)).toBe(false)
  })
})

describe('seq is encoded big-endian uint32', () => {
  it('seq=0x01020304 produces the expected byte pattern in the header', () => {
    // Pin the on-wire byte order — drift here silently breaks Go-TS
    // interop. 0x01020304 in BE is [0x01, 0x02, 0x03, 0x04].
    const wire = buildChunk(sampleTransferId, 0x01020304, 0, new Uint8Array(0))
    expect(wire[16]).toBe(0x01)
    expect(wire[17]).toBe(0x02)
    expect(wire[18]).toBe(0x03)
    expect(wire[19]).toBe(0x04)
  })

  it('seq=0 round-trips as zero', () => {
    const wire = buildChunk(sampleTransferId, 0, 0, new Uint8Array(0))
    expect(wire[16]).toBe(0)
    expect(wire[17]).toBe(0)
    expect(wire[18]).toBe(0)
    expect(wire[19]).toBe(0)
    expect(parseChunk(wire).seq).toBe(0)
  })

  it('seq=0xffffffff (uint32 max) round-trips correctly', () => {
    // Catches the int32-vs-uint32 sign trap that bit-shift parsing
    // would hit: `(plaintext[16] << 24) | ...` produces a negative
    // number for high bits without a final `>>> 0` to coerce
    // unsigned. DataView.getUint32 sidesteps this entirely.
    const wire = buildChunk(sampleTransferId, 0xffffffff, 0, new Uint8Array(0))
    const c = parseChunk(wire)
    expect(c.seq).toBe(0xffffffff)
  })
})

describe('parseChunk aliasing', () => {
  // transferId and data are zero-copy subarray views — same contract
  // as parseEnvelopeHeader. Pin it so a refactor that allocates fresh
  // copies doesn't silently regress receivers that rely on the alias.
  it('transferId and data alias the source plaintext', () => {
    const data = new Uint8Array([0x10, 0x20])
    const wire = buildChunk(sampleTransferId, 1, 0, data)
    const c = parseChunk(wire)
    wire[0] = 0x99 // first byte of transfer_id
    wire[CHUNK_HEADER_LEN] = 0x88 // first byte of data
    expect(c.transferId[0]).toBe(0x99)
    expect(c.data[0]).toBe(0x88)
  })
})

describe('isLastChunk masks bit 0 of flags', () => {
  // Receivers should mask the last-chunk bit so future flag additions
  // (in higher-order bits) don't break the last-chunk check.
  it('returns true when bit 0 is set, regardless of other bits', () => {
    expect(isLastChunk(0x01)).toBe(true)
    expect(isLastChunk(0x03)).toBe(true) // bit 0 + bit 1 (reserved)
    expect(isLastChunk(0xff)).toBe(true) // all bits set
  })

  it('returns false when bit 0 is unset', () => {
    expect(isLastChunk(0x00)).toBe(false)
    expect(isLastChunk(0x02)).toBe(false) // only a reserved bit set
    expect(isLastChunk(0xfe)).toBe(false) // all bits except bit 0
  })
})

describe('buildChunk rejects bad inputs', () => {
  it('rejects wrong-size transfer_id', () => {
    const data = new Uint8Array(0)
    expect(() => buildChunk(new Uint8Array(15), 0, 0, data)).toThrow(ChunkError)
    expect(() => buildChunk(new Uint8Array(17), 0, 0, data)).toThrow(ChunkError)
    expect(() => buildChunk(new Uint8Array(0), 0, 0, data)).toThrow(ChunkError)
  })

  it.each<[string, number]>([
    ['negative', -1],
    ['fractional', 1.5],
    ['NaN', Number.NaN],
    ['+Infinity', Number.POSITIVE_INFINITY],
    ['above uint32 max', 0x100000000],
  ])('rejects seq = %s', (_name, seq) => {
    expect(() => buildChunk(sampleTransferId, seq, 0, new Uint8Array(0))).toThrow(/seq/)
  })

  it.each<[string, number]>([
    ['negative', -1],
    ['fractional', 1.5],
    ['above byte max', 256],
  ])('rejects flags = %s', (_name, flags) => {
    expect(() => buildChunk(sampleTransferId, 0, flags, new Uint8Array(0))).toThrow(/flags/)
  })
})

describe('parseChunk rejects truncated input', () => {
  it.each([0, 1, CHUNK_HEADER_LEN - 1])('rejects plaintext of length %i', (n) => {
    expect(() => parseChunk(new Uint8Array(n))).toThrow(ChunkError)
    expect(() => parseChunk(new Uint8Array(n))).toThrow(/too short/)
  })
})

describe('parseChunk reads from the plaintext byteOffset correctly', () => {
  // DataView with byteOffset is the gotcha: Uint8Array.subarray returns
  // a view with non-zero byteOffset, and a naive `new DataView(buf)`
  // ignores it. Pin that parseChunk still reads the right bytes when
  // given a subarray that doesn't start at offset 0 of its buffer.
  it('handles a subarray starting at non-zero byteOffset', () => {
    const wire = buildChunk(sampleTransferId, 0xdeadbeef, CHUNK_FLAG_LAST, new Uint8Array([0xab]))
    // Embed `wire` in a larger buffer, then take a subarray view of
    // just the chunk region.
    const bigBuf = new Uint8Array(wire.length + 100)
    bigBuf.set(wire, 50)
    const view = bigBuf.subarray(50, 50 + wire.length)
    const c = parseChunk(view)
    expect(c.seq).toBe(0xdeadbeef)
    expect(c.flags).toBe(CHUNK_FLAG_LAST)
    expect(c.data[0]).toBe(0xab)
  })
})
