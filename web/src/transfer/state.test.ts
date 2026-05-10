import { describe, expect, it } from 'vitest'

import { sha256 } from '@noble/hashes/sha2.js'

import {
  type InboundTransfer,
  type OutboundTransfer,
  finalizeBlobUrl,
  formatBytes,
  markOutboundStreaming,
  tryAssemble,
} from './state'

function makeInbound(
  overrides: Partial<InboundTransfer> = {},
): InboundTransfer {
  return {
    transferIdHex: 'aa'.repeat(16),
    peerHex: 'bb'.repeat(32),
    filename: 'test.bin',
    totalBytes: 0,
    expectedSha256: sha256(new Uint8Array(0)),
    receivedBytes: 0,
    chunks: new Map(),
    lastSeq: null,
    status: 'streaming',
    ...overrides,
  }
}

// inboundFromChunks builds an InboundTransfer whose totalBytes and
// expectedSha256 are derived from the chunks, so the hash/size checks
// in tryAssemble are exercised on data the test actually controls.
function inboundFromChunks(
  ordered: Uint8Array[],
  overrides: Partial<InboundTransfer> = {},
): InboundTransfer {
  const totalLen = ordered.reduce((s, c) => s + c.length, 0)
  const flat = new Uint8Array(totalLen)
  let off = 0
  for (const c of ordered) {
    flat.set(c, off)
    off += c.length
  }
  return makeInbound({
    totalBytes: totalLen,
    expectedSha256: sha256(flat),
    receivedBytes: totalLen,
    ...overrides,
  })
}

describe('tryAssemble', () => {
  it('returns input unchanged when lastSeq is null', () => {
    const t = makeInbound({
      chunks: new Map([
        [0, new Uint8Array([0x10])],
        [1, new Uint8Array([0x20])],
      ]),
      receivedBytes: 2,
    })
    const out = tryAssemble(t)
    expect(out).toBe(t)
    expect(out.status).toBe('streaming')
  })

  it('returns input unchanged when there is a gap below lastSeq', () => {
    const t = makeInbound({
      chunks: new Map([
        [0, new Uint8Array([0x10])],
        // missing seq 1
        [2, new Uint8Array([0x30])],
      ]),
      lastSeq: 2,
      receivedBytes: 2,
    })
    const out = tryAssemble(t)
    expect(out).toBe(t)
    expect(out.status).toBe('streaming')
  })

  it('assembles when all chunks 0..lastSeq are present', () => {
    const c0 = new Uint8Array([0x01, 0x02])
    const c1 = new Uint8Array([0x03, 0x04, 0x05])
    const c2 = new Uint8Array([0x06])
    const t = inboundFromChunks([c0, c1, c2], {
      chunks: new Map([[0, c0], [1, c1], [2, c2]]),
      lastSeq: 2,
    })
    const out = tryAssemble(t)
    expect(out.status).toBe('done')
    expect(out.blobUrl).toBeUndefined() // tryAssemble is pure; URL minted post-commit
    expect(out.assembledBytes).toBeDefined()
    expect(out.chunks.size).toBe(0) // memory freed
    expect(Array.from(out.assembledBytes!)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  })

  it('respects sequence order during assembly (out-of-order arrivals)', () => {
    // Insert chunks in arbitrary order; tryAssemble must walk 0..lastSeq
    // to concat them in the correct order.
    const c0 = new Uint8Array([0x01, 0x02])
    const c1 = new Uint8Array([0x03, 0x04, 0x05])
    const c2 = new Uint8Array([0x06])
    const t = inboundFromChunks([c0, c1, c2], {
      chunks: new Map([[2, c2], [0, c0], [1, c1]]),
      lastSeq: 2,
    })
    const out = tryAssemble(t)
    expect(out.status).toBe('done')
    expect(Array.from(out.assembledBytes!)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  })

  it('handles a single-chunk transfer (lastSeq=0)', () => {
    const c0 = new Uint8Array([0x99])
    const t = inboundFromChunks([c0], {
      chunks: new Map([[0, c0]]),
      lastSeq: 0,
    })
    const out = tryAssemble(t)
    expect(out.status).toBe('done')
    expect(Array.from(out.assembledBytes!)).toEqual([0x99])
  })

  it('handles a zero-data last-chunk-only transfer', () => {
    // Edge case: a sender shipping a 0-byte file with a single empty
    // chunk that just sets the last-flag.
    const t = inboundFromChunks([new Uint8Array(0)], {
      chunks: new Map([[0, new Uint8Array(0)]]),
      lastSeq: 0,
    })
    const out = tryAssemble(t)
    expect(out.status).toBe('done')
    expect(out.assembledBytes!.length).toBe(0)
  })

  it('aborts when assembled length differs from advertised totalBytes', () => {
    const c0 = new Uint8Array([0x10, 0x11, 0x12])
    const t = inboundFromChunks([c0], {
      chunks: new Map([[0, c0]]),
      lastSeq: 0,
      totalBytes: 5, // sender advertised more than actually arrived
    })
    const out = tryAssemble(t)
    expect(out.status).toBe('aborted')
    expect(out.assembledBytes).toBeUndefined()
    expect(out.chunks.size).toBe(0)
  })

  it('aborts when assembled bytes hash to a different SHA-256 than advertised', () => {
    const c0 = new Uint8Array([0xAA, 0xBB])
    const t = inboundFromChunks([c0], {
      chunks: new Map([[0, c0]]),
      lastSeq: 0,
      // Override expectedSha256 with a wrong digest.
      expectedSha256: new Uint8Array(32).fill(0xFF),
    })
    const out = tryAssemble(t)
    expect(out.status).toBe('aborted')
    expect(out.assembledBytes).toBeUndefined()
  })
})

describe('finalizeBlobUrl', () => {
  it('materializes a blob URL from assembledBytes and clears the bytes', async () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    const t: InboundTransfer = {
      transferIdHex: 'aa'.repeat(16),
      peerHex: 'bb'.repeat(32),
      filename: 'test.bin',
      totalBytes: 6,
      expectedSha256: sha256(bytes),
      receivedBytes: 6,
      chunks: new Map(),
      lastSeq: 5,
      status: 'done',
      assembledBytes: bytes,
    }
    const out = finalizeBlobUrl(t)
    expect(out.blobUrl).toMatch(/^blob:/)
    expect(out.assembledBytes).toBeUndefined()
    // Read the Blob back to verify byte content.
    const resp = await fetch(out.blobUrl!)
    const buf = new Uint8Array(await resp.arrayBuffer())
    expect(Array.from(buf)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    URL.revokeObjectURL(out.blobUrl!)
  })

  it('returns input unchanged when assembledBytes is missing', () => {
    const t: InboundTransfer = {
      transferIdHex: 'aa'.repeat(16),
      peerHex: 'bb'.repeat(32),
      filename: 'test.bin',
      totalBytes: 0,
      expectedSha256: sha256(new Uint8Array(0)),
      receivedBytes: 0,
      chunks: new Map(),
      lastSeq: null,
      status: 'streaming',
    }
    const out = finalizeBlobUrl(t)
    expect(out).toBe(t)
  })
})

function makeOutbound(
  overrides: Partial<OutboundTransfer> = {},
): OutboundTransfer {
  return {
    transferIdHex: 'aa'.repeat(16),
    peerHex: 'bb'.repeat(32),
    filename: 'test.bin',
    totalBytes: 100,
    sentBytes: 0,
    status: 'awaiting-decision',
    bytes: new Uint8Array(100),
    ...overrides,
  }
}

describe('markOutboundStreaming', () => {
  it('flips an awaiting-decision transfer to streaming', () => {
    const a = makeOutbound({ transferIdHex: 'A' })
    const next = markOutboundStreaming({ A: a }, 'A')
    expect(next.A.status).toBe('streaming')
    // Other fields preserved.
    expect(next.A.bytes).toBe(a.bytes)
    expect(next.A.totalBytes).toBe(a.totalBytes)
  })

  it('returns prev unchanged when the transfer is missing', () => {
    const prev = { A: makeOutbound({ transferIdHex: 'A' }) }
    expect(markOutboundStreaming(prev, 'B')).toBe(prev)
  })

  it('returns prev unchanged when the transfer is already streaming', () => {
    const prev = {
      A: makeOutbound({ transferIdHex: 'A', status: 'streaming', sentBytes: 50 }),
    }
    expect(markOutboundStreaming(prev, 'A')).toBe(prev)
  })

  it('returns prev unchanged when the transfer is already done / rejected / aborted', () => {
    for (const status of ['done', 'rejected', 'aborted'] as const) {
      const prev = { A: makeOutbound({ transferIdHex: 'A', status, bytes: null }) }
      expect(markOutboundStreaming(prev, 'A')).toBe(prev)
    }
  })

  // Regression: back-to-back transfer-accepts used to clobber an
  // already-streamed transfer's `done` state because startStreaming
  // wrote the React outbound map via a value setter built from a
  // pre-stream snapshot of outboundRef.current. The functional
  // updater this helper replaces must NOT touch other entries — every
  // field of every other transfer (and its referential identity)
  // must round-trip unchanged.
  it('does not clobber other transfers that already finished streaming', () => {
    const t1Done = makeOutbound({
      transferIdHex: 'T1',
      status: 'done',
      sentBytes: 100,
      bytes: null,
    })
    const t2Pending = makeOutbound({
      transferIdHex: 'T2',
      status: 'awaiting-decision',
    })
    const prev = { T1: t1Done, T2: t2Pending }

    const next = markOutboundStreaming(prev, 'T2')

    // T1's entry must be referentially identical — proves no spread,
    // no field-level rewrite, no progress rollback.
    expect(next.T1).toBe(t1Done)
    expect(next.T1.status).toBe('done')
    expect(next.T1.sentBytes).toBe(100)
    // T2 transitioned cleanly.
    expect(next.T2).not.toBe(t2Pending)
    expect(next.T2.status).toBe('streaming')
  })

  // The setOutbound queue under React's batching looks like a sequence
  // of value-setters and functional-updaters folded over the previous
  // state. Replay the realistic queue that the App.tsx code path
  // produces for two back-to-back accepts and verify that — with the
  // functional updater — the earlier transfer's progress and final
  // 'done' state survive the second transfer's startStreaming.
  it('composes through a back-to-back-accepts queue without losing progress', () => {
    const TOTAL = 100
    const initial: Record<string, OutboundTransfer> = {
      T1: makeOutbound({ transferIdHex: 'T1' }),
      T2: makeOutbound({ transferIdHex: 'T2' }),
    }

    type Op =
      | { kind: 'value'; value: Record<string, OutboundTransfer> }
      | { kind: 'fn'; fn: (p: Record<string, OutboundTransfer>) => Record<string, OutboundTransfer> }

    const queue: Op[] = [
      // T1 startStreaming (the fixed call site — functional updater).
      { kind: 'fn', fn: (p) => markOutboundStreaming(p, 'T1') },
      // T1 streamChunks: progress to full + flip to done.
      {
        kind: 'fn',
        fn: (p) => {
          const c = p.T1
          return { ...p, T1: { ...c, sentBytes: TOTAL } }
        },
      },
      {
        kind: 'fn',
        fn: (p) => {
          const c = p.T1
          return { ...p, T1: { ...c, status: 'done', bytes: null } }
        },
      },
      // T2 startStreaming arrives second. The functional updater here
      // is the bug fix — a value-setter built from a stale snapshot
      // {T1: streaming/0, T2: awaiting-decision} would clobber T1.
      { kind: 'fn', fn: (p) => markOutboundStreaming(p, 'T2') },
    ]

    let state = initial
    for (const op of queue) {
      state = op.kind === 'value' ? op.value : op.fn(state)
    }

    expect(state.T1.status).toBe('done')
    expect(state.T1.sentBytes).toBe(TOTAL)
    expect(state.T2.status).toBe('streaming')
  })
})

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [1, '1 B'],
    [1023, '1023 B'],
    [1024, '1.0 KB'],
    [1500, '1.5 KB'],
    [1024 * 1024, '1.0 MB'],
    [1024 * 1024 * 1024, '1.0 GB'],
    [1024 * 1024 * 1024 * 1024, '1.0 TB'],
    [1.5 * 1024 * 1024 * 1024 * 1024, '1.5 TB'],
  ])('%i -> %s', (n, want) => {
    expect(formatBytes(n)).toBe(want)
  })
})
