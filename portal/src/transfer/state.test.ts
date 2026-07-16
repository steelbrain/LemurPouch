import { describe, expect, it } from 'vitest'

import { sha256 } from '@noble/hashes/sha2.js'

import { CHUNK_FLAG_LAST } from './chunk'
import {
  CHUNK_DATA_SIZE,
  type InboundTransfer,
  type OutboundTransfer,
  acceptChunk,
  finalizeBlobUrl,
  formatBytes,
  inboundVerdict,
  markOutboundStreaming,
  newInboundAssembler,
} from './state'

// Non-last chunks on the wire are always exactly CHUNK_DATA_SIZE (the
// sender's chunker emits that), and the receiver bounds seq against
// ceil(totalBytes / CHUNK_DATA_SIZE). Tests that exercise more than one
// chunk must therefore make every non-last chunk full-size, or the seq
// bound rejects seq>=1. `fullChunk` + `tailChunk` keep that honest.
function fullChunk(fill: number): Uint8Array {
  return new Uint8Array(CHUNK_DATA_SIZE).fill(fill)
}
function tailChunk(len: number, fill: number): Uint8Array {
  return new Uint8Array(len).fill(fill)
}
function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

describe('newInboundAssembler', () => {
  it('seeds bookkeeping with a growing memory sink (no up-front alloc)', () => {
    const a = newInboundAssembler(100)
    // Growing sink starts empty; length grows as chunks are accepted.
    expect(a.sink.snapshot()!.length).toBe(0)
    expect(a.writeOffset).toBe(0)
    expect(a.nextSeq).toBe(0)
    expect(a.receivedBytes).toBe(0)
    expect(a.lastSeq).toBeNull()
    expect(a.digest).toBeNull()
    expect(a.expectedSha256).toBeNull()
    // ceil(100 / 65536) = 1.
    expect(a.expectedChunks).toBe(1)
  })

  it('floors expectedChunks at 1 for a 0-byte transfer', () => {
    expect(newInboundAssembler(0).expectedChunks).toBe(1)
  })

  it('computes expectedChunks for a multi-chunk transfer', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE * 2 + 5)
    expect(a.expectedChunks).toBe(3)
  })
})

describe('acceptChunk — happy paths', () => {
  it('assembles a single-chunk transfer and finalizes the digest', () => {
    const c0 = tailChunk(6, 0x42)
    const a = newInboundAssembler(6)
    expect(acceptChunk(a, 0, CHUNK_FLAG_LAST, c0)).toBe('accepted')
    expect(a.receivedBytes).toBe(6)
    expect(Array.from(a.sink.snapshot()!)).toEqual(Array.from(c0))
    // digest is finalized as soon as the last contiguous byte lands.
    expect(a.digest).not.toBeNull()
    expect(Array.from(a.digest!)).toEqual(Array.from(sha256(c0)))
  })

  it('assembles a zero-byte transfer (single empty last chunk)', () => {
    const a = newInboundAssembler(0)
    expect(acceptChunk(a, 0, CHUNK_FLAG_LAST, new Uint8Array(0))).toBe('accepted')
    expect(a.sink.snapshot()!.length).toBe(0)
    expect(Array.from(a.digest!)).toEqual(Array.from(sha256(new Uint8Array(0))))
  })

  it('assembles multiple chunks in order', () => {
    const c0 = fullChunk(0xaa)
    const c1 = tailChunk(10, 0xbb)
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    expect(acceptChunk(a, 0, 0, c0)).toBe('accepted')
    // Digest not ready until the last chunk lands.
    expect(a.digest).toBeNull()
    expect(acceptChunk(a, 1, CHUNK_FLAG_LAST, c1)).toBe('accepted')
    expect(Array.from(a.sink.snapshot()!)).toEqual(Array.from(concat([c0, c1])))
    expect(Array.from(a.digest!)).toEqual(Array.from(sha256(concat([c0, c1]))))
  })

  it('tolerates out-of-order arrival via the reorder buffer', () => {
    const c0 = fullChunk(0xaa)
    const c1 = tailChunk(10, 0xbb)
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    // Last chunk arrives first — stashed in pending, hash not advanced.
    expect(acceptChunk(a, 1, CHUNK_FLAG_LAST, c1)).toBe('accepted')
    expect(a.pending.size).toBe(1)
    expect(a.nextSeq).toBe(0)
    expect(a.digest).toBeNull()
    // The gap fills — seq 0 writes, then seq 1 drains contiguously.
    expect(acceptChunk(a, 0, 0, c0)).toBe('accepted')
    expect(a.pending.size).toBe(0)
    expect(Array.from(a.sink.snapshot()!)).toEqual(Array.from(concat([c0, c1])))
    expect(Array.from(a.digest!)).toEqual(Array.from(sha256(concat([c0, c1]))))
  })

  it('copies out-of-order chunk data (no aliasing of the frame buffer)', () => {
    const c1 = tailChunk(10, 0xbb)
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    acceptChunk(a, 1, CHUNK_FLAG_LAST, c1)
    // Mutate the caller's buffer after stashing; the assembler must hold
    // its own copy.
    c1.fill(0x00)
    acceptChunk(a, 0, 0, fullChunk(0xaa))
    expect(a.sink.snapshot()![CHUNK_DATA_SIZE]).toBe(0xbb)
  })
})

describe('acceptChunk — duplicates and rejections', () => {
  it('reports a re-sent seq as duplicate without mutating', () => {
    const c0 = fullChunk(0xaa)
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    expect(acceptChunk(a, 0, 0, c0)).toBe('accepted')
    const receivedBefore = a.receivedBytes
    expect(acceptChunk(a, 0, 0, fullChunk(0x99))).toBe('duplicate')
    expect(a.receivedBytes).toBe(receivedBefore)
    // The original bytes are untouched.
    expect(a.sink.snapshot()![0]).toBe(0xaa)
  })

  it('reports an already-buffered out-of-order seq as duplicate', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE * 2 + 1)
    expect(acceptChunk(a, 1, 0, fullChunk(0xbb))).toBe('accepted')
    expect(acceptChunk(a, 1, 0, fullChunk(0xcc))).toBe('duplicate')
  })

  it('aborts on a seq at/above expectedChunks', () => {
    const a = newInboundAssembler(6) // expectedChunks = 1
    expect(acceptChunk(a, 1, CHUNK_FLAG_LAST, tailChunk(1, 0x01))).toBe('abort')
  })

  it('aborts on a hostile huge seq', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    expect(acceptChunk(a, 0xffffffff, CHUNK_FLAG_LAST, tailChunk(1, 0x01))).toBe('abort')
  })

  it('aborts on an empty non-last chunk', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    expect(acceptChunk(a, 0, 0, new Uint8Array(0))).toBe('abort')
  })

  it('aborts when the stream overshoots the advertised size', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    expect(acceptChunk(a, 0, 0, fullChunk(0xaa))).toBe('accepted')
    // remaining budget is 10; a 20-byte last chunk overshoots.
    expect(acceptChunk(a, 1, CHUNK_FLAG_LAST, tailChunk(20, 0xbb))).toBe('abort')
  })

  it('aborts when the stream is shorter than the advertised size', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    expect(acceptChunk(a, 0, 0, fullChunk(0xaa))).toBe('accepted')
    // Last chunk is short of the 10 advertised tail bytes — size mismatch.
    expect(acceptChunk(a, 1, CHUNK_FLAG_LAST, tailChunk(5, 0xbb))).toBe('abort')
  })
})

describe('inboundVerdict', () => {
  function completed(): ReturnType<typeof newInboundAssembler> {
    const c0 = tailChunk(6, 0x42)
    const a = newInboundAssembler(6)
    acceptChunk(a, 0, CHUNK_FLAG_LAST, c0)
    return a
  }

  it('is pending until the last byte has landed', () => {
    const a = newInboundAssembler(CHUNK_DATA_SIZE + 10)
    acceptChunk(a, 0, 0, fullChunk(0xaa))
    a.expectedSha256 = new Uint8Array(32)
    expect(inboundVerdict(a)).toBe('pending')
  })

  it('is pending until the transfer-end digest arrives', () => {
    const a = completed()
    expect(a.digest).not.toBeNull()
    expect(inboundVerdict(a)).toBe('pending') // expectedSha256 still null
  })

  it('is verified when the digests match', () => {
    const a = completed()
    a.expectedSha256 = sha256(tailChunk(6, 0x42))
    expect(inboundVerdict(a)).toBe('verified')
  })

  it('is corrupt when the advertised digest differs', () => {
    const a = completed()
    a.expectedSha256 = new Uint8Array(32).fill(0xff)
    expect(inboundVerdict(a)).toBe('corrupt')
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
      receivedBytes: 6,
      status: 'done',
      assembledBytes: bytes,
    }
    const out = finalizeBlobUrl(t)
    expect(out.blobUrl).toMatch(/^blob:/)
    expect(out.assembledBytes).toBeUndefined()
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
      receivedBytes: 0,
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
    file: new File([new Uint8Array(100)], "f.bin"),
    ...overrides,
  }
}

describe('markOutboundStreaming', () => {
  it('flips an awaiting-decision transfer to streaming', () => {
    const a = makeOutbound({ transferIdHex: 'A' })
    const next = markOutboundStreaming({ A: a }, 'A')
    expect(next.A.status).toBe('streaming')
    // Other fields preserved.
    expect(next.A.file).toBe(a.file)
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
      const prev = { A: makeOutbound({ transferIdHex: 'A', status, file: null }) }
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
      file: null,
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
          return { ...p, T1: { ...c, status: 'done', file: null } }
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
