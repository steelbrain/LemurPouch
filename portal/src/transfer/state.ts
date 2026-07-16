// Transfer-state types + pure helpers for assembly and progress
// formatting. The App owns the React state that holds these records;
// this module just defines the shapes and the side-effect-free
// reassembly logic. AGENTS.md "Transfer Lifecycle" is the spec.

import { sha256 } from '@noble/hashes/sha2.js'

import { isLastChunk } from './chunk'

// Re-export the floor constant so existing importers keep working.
// Prefer negotiate.ts for new code (preferred/max/window live there too).
import { CHUNK_DATA_SIZE as NEGOTIATED_FLOOR } from './negotiate'
export const CHUNK_DATA_SIZE = NEGOTIATED_FLOOR

// OutboundTransfer is the sender-side state for a file we're trying
// to (or are currently) shipping to a friend.
export interface OutboundTransfer {
  transferIdHex: string
  peerHex: string // recipient's hex(ed25519_pub)
  filename: string
  totalBytes: number
  sentBytes: number
  status: 'awaiting-decision' | 'streaming' | 'done' | 'rejected' | 'aborted'
  // Filled when status='rejected' if the recipient included one.
  rejectReason?: string
  // File handle for incremental reads (no whole-file arrayBuffer pin).
  // Cleared when status becomes terminal so the GC can reclaim.
  file: File | null
  // Negotiated send parameters (set on accept).
  chunkSize?: number
  windowBytes?: number
  lastAck?: number
  // Optional rate for UI (bytes/sec EMA).
  rateBps?: number
}

// InboundTransfer is the receiver-side React state for a file someone is
// (or wants to be) sending us. It holds only the UI-facing scalars; the
// payload buffer, running hash, and reorder bookkeeping live in a
// separate mutable InboundAssembler held in a ref (see below) — they
// can't sit in React state because the hasher is stateful and must be
// driven exactly once per frame, not from a (possibly double-invoked)
// setState updater.
export interface InboundTransfer {
  transferIdHex: string
  peerHex: string // sender's hex(ed25519_pub)
  filename: string
  totalBytes: number
  receivedBytes: number
  status: 'offered' | 'streaming' | 'done' | 'rejected' | 'aborted'
  // Assembled bytes (memory sink only), set on the same setState pass
  // that flips status to 'done'. A separate post-commit step materializes
  // these into a Blob + object URL. Cleared once `blobUrl` has been minted.
  assembledBytes?: Uint8Array
  // Object URL for downloading. Materialized from assembledBytes (memory)
  // or from an OPFS File (disk). Caller revokes on dismiss.
  blobUrl?: string
  // True when the receive path is in-memory (no OPFS); UI may warn.
  memoryFallback?: boolean
  // Non-fatal advisory shown while streaming (e.g. large receive in RAM).
  receiveWarning?: string
  rateBps?: number
  // Human-readable failure detail (e.g. OOM / OPFS unavailable).
  rejectReason?: string
  // Alternative to assembledBytes: multi-part Blob (growing memory sink).
  assembledBlob?: Blob
}

/** Sink for contiguous in-order writes from the assembler. */
export interface TransferSink {
  write(data: Uint8Array): void
  /** Memory sink: full buffer when cheap. OPFS/other: null. */
  snapshot(): Uint8Array | null
  /** Prefer for finalize — growing sinks can avoid a second full copy. */
  toBlob?(): Blob | null
}

// InboundAssembler accumulates a streaming inbound transfer into a single
// preallocated buffer while folding the bytes into a running SHA-256, so
// the only post-last-byte work is a digest() finalize + compare rather
// than a second full pass (concat + hash) over a reassembled file.
//
// It is MUTABLE by design — the hasher and buffer are stateful — and so
// must live in a ref and be driven from the WebSocket event handler,
// which runs exactly once per received frame. It must NOT live in React
// state or be mutated from a setState updater: React may invoke updaters
// more than once under StrictMode / concurrent rendering, which would
// double-feed the hasher. App mirrors the UI-facing scalars
// (receivedBytes, status) into InboundTransfer separately.
export interface InboundAssembler {
  totalBytes: number
  sink: TransferSink
  hasher: ReturnType<typeof sha256.create>
  // Bytes written contiguously from seq 0 — equals the number of bytes
  // already folded into `hasher`. Out-of-order arrivals wait in `pending`
  // until the gap before them fills, so the hash is always taken over a
  // contiguous prefix in seq order.
  writeOffset: number
  // Next seq expected in contiguous order.
  nextSeq: number
  // Out-of-order arrivals (seq > nextSeq), holding owned copies until the
  // preceding gap fills. Empty on the common in-order path.
  pending: Map<number, Uint8Array>
  // Running total of accepted bytes (contiguous + pending) — drives the
  // progress UI and the overshoot cap.
  receivedBytes: number
  // seq of the chunk whose flags marked it last, or null until it lands.
  lastSeq: number | null
  // Highest valid seq + 1 = ceil(totalBytes / CHUNK_DATA_SIZE), floored
  // at 1 so a 0-byte transfer still admits its single seq-0 chunk. A seq
  // at or above this is out of range for the advertised size. Always uses
  // the 64 KiB floor so larger negotiated chunks remain valid.
  expectedChunks: number
  // The finalized digest, set once every byte through lastSeq has been
  // written and hashed AND the streamed size matches totalBytes.
  digest: Uint8Array | null
  // The sender's advertised digest from transfer-end, or null until it
  // arrives — it may arrive before or after the last chunk.
  expectedSha256: Uint8Array | null
}

export function memorySink(totalBytes: number): TransferSink {
  const buf = new Uint8Array(totalBytes)
  let offset = 0
  return {
    write(data: Uint8Array) {
      buf.set(data, offset)
      offset += data.length
    },
    snapshot() {
      return buf
    },
    toBlob() {
      return new Blob([buf as Uint8Array<ArrayBuffer>], {
        type: 'application/octet-stream',
      })
    },
  }
}

/**
 * Growing in-memory sink: no up-front totalBytes allocation. Chunks are
 * kept as separate parts so a multi-GB offer does not OOM at accept time
 * (only as data actually arrives). Finalize via toBlob() when possible.
 */
export function growingMemorySink(): TransferSink {
  const parts: Uint8Array[] = []
  let total = 0
  return {
    write(data: Uint8Array) {
      parts.push(data.slice())
      total += data.length
    },
    snapshot() {
      const out = new Uint8Array(total)
      let o = 0
      for (const p of parts) {
        out.set(p, o)
        o += p.length
      }
      return out
    },
    toBlob() {
      return new Blob(parts as BlobPart[], { type: 'application/octet-stream' })
    },
  }
}

// newInboundAssembler allocates a sink-backed assembler. Default sink is
// a growing in-memory store (no prealloc). Pass an OPFS sink for disk
// receives. A hostile/buggy peer can still OOM the tab by streaming
// absurd sizes — the overshoot cap and seq bounds still apply.
export function newInboundAssembler(
  totalBytes: number,
  sink?: TransferSink,
): InboundAssembler {
  return {
    totalBytes,
    sink: sink ?? growingMemorySink(),
    hasher: sha256.create(),
    writeOffset: 0,
    nextSeq: 0,
    pending: new Map(),
    receivedBytes: 0,
    lastSeq: null,
    expectedChunks: Math.max(1, Math.ceil(totalBytes / CHUNK_DATA_SIZE)),
    digest: null,
    expectedSha256: null,
  }
}

export type AcceptChunkResult = 'accepted' | 'duplicate' | 'abort'

// acceptChunk validates one chunk and folds it into the assembler.
// Returns 'abort' on any structural violation (the caller tears the
// transfer down), 'duplicate' for a seq already consumed or buffered
// (ignored), and 'accepted' otherwise. MUTATES the assembler — call once
// per frame from the event handler, never from a setState updater.
//
// `data` may alias the decrypted frame buffer: the in-order path copies
// it into `buf` immediately and the out-of-order path stores an owned
// `.slice()`, so the caller need not clone before calling.
export function acceptChunk(
  a: InboundAssembler,
  seq: number,
  flags: number,
  data: Uint8Array,
): AcceptChunkResult {
  // Bound seq against the advertised size. A seq at/above expectedChunks
  // is out of range — without this a hostile seq could index far past
  // the buffer (and would be a concrete post-consent DoS).
  if (!Number.isInteger(seq) || seq < 0 || seq >= a.expectedChunks) return 'abort'
  // Already consumed (below the contiguous frontier) or already buffered.
  // The legitimate sender never re-sends a seq; dropping silently stops a
  // hostile re-send from swapping bytes under the overshoot cap.
  if (seq < a.nextSeq || a.pending.has(seq)) return 'duplicate'
  const last = isLastChunk(flags)
  // A non-last chunk with no payload is meaningless — the only legitimate
  // empty chunk is the single last chunk of a 0-byte transfer. Without
  // this gate an attacker could spam distinct empty seqs to grow the
  // pending Map without ever advancing receivedBytes.
  if (data.length === 0 && !last) return 'abort'
  // Overshoot cap: a peer writing past the advertised size is buggy or
  // hostile. Bail before a buffered/contiguous write would exceed buf.
  if (a.receivedBytes + data.length > a.totalBytes) return 'abort'

  a.receivedBytes += data.length
  if (last) a.lastSeq = seq

  if (seq === a.nextSeq) {
    writeAndHash(a, data)
    // Drain any buffered successors now made contiguous.
    let next = a.pending.get(a.nextSeq)
    while (next !== undefined) {
      a.pending.delete(a.nextSeq)
      writeAndHash(a, next)
      next = a.pending.get(a.nextSeq)
    }
  } else {
    // Out-of-order (seq > nextSeq): stash an owned copy until the gap
    // before it fills in.
    a.pending.set(seq, data.slice())
  }

  // Once the contiguous frontier reaches past the last chunk, the whole
  // payload is written and hashed. The streamed size must match the
  // advertised size (the assembled-length integrity gate); a short stream
  // is a buggy/hostile peer.
  if (a.lastSeq !== null && a.nextSeq === a.lastSeq + 1) {
    if (a.writeOffset !== a.totalBytes) return 'abort'
    if (a.digest === null) a.digest = a.hasher.digest()
  }
  return 'accepted'
}

function writeAndHash(a: InboundAssembler, data: Uint8Array): void {
  a.sink.write(data)
  a.hasher.update(data)
  a.writeOffset += data.length
  a.nextSeq += 1
}

export type InboundVerdict = 'pending' | 'verified' | 'corrupt'

// inboundVerdict reports whether the transfer can be finalized yet:
// 'pending' until BOTH the contiguous digest is computed and the
// transfer-end digest has arrived; then 'verified' / 'corrupt' on the
// comparison. The AEAD already authenticated every chunk, so a 'corrupt'
// verdict means the sender's stream and its own advertised digest
// disagree (a bug, truncation, or a hostile peer) — never an in-flight
// tampering relay.
export function inboundVerdict(a: InboundAssembler): InboundVerdict {
  if (a.digest === null || a.expectedSha256 === null) return 'pending'
  return bytesEqual(a.digest, a.expectedSha256) ? 'verified' : 'corrupt'
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

// finalizeBlobUrl materializes the Blob and object URL for an inbound
// transfer that has assembledBlob or assembledBytes set. Side-effecting
// (calls URL.createObjectURL); call from a post-commit hook (useEffect),
// never inside a setState updater.
export function finalizeBlobUrl(t: InboundTransfer): InboundTransfer {
  if (t.blobUrl) return t
  let blob: Blob | null = t.assembledBlob ?? null
  if (!blob && t.assembledBytes) {
    // Use a generic MIME type — AGENTS.md doesn't define a content-type
    // negotiation. Cast to ArrayBuffer-backed for DOM BlobPart.
    blob = new Blob([t.assembledBytes as Uint8Array<ArrayBuffer>], {
      type: 'application/octet-stream',
    })
  }
  if (!blob) return t
  const blobUrl = URL.createObjectURL(blob)
  return {
    ...t,
    blobUrl,
    assembledBytes: undefined,
    assembledBlob: undefined,
  }
}

/** Snapshot contiguous bytes from a completed memory-backed assembler. */
export function assemblerSnapshot(a: InboundAssembler): Uint8Array | null {
  return a.sink.snapshot()
}

/** Prefer Blob finalize for growing sinks (avoids one full-size copy). */
export function assemblerBlob(a: InboundAssembler): Blob | null {
  if (a.sink.toBlob) return a.sink.toBlob()
  const snap = a.sink.snapshot()
  if (!snap) return null
  return new Blob([snap as Uint8Array<ArrayBuffer>], {
    type: 'application/octet-stream',
  })
}

// markOutboundStreaming flips one transfer's status from
// 'awaiting-decision' to 'streaming' and returns prev unchanged
// otherwise. Designed for use as a setOutbound functional updater so
// it composes with concurrent updates from other transfers' chunk
// loops — a value-setter built from a pre-stream snapshot would clobber
// any progress / 'done' updates that landed between the snapshot and
// the commit, leaving the earlier transfer stuck on `streaming, 0 B`.
export function markOutboundStreaming(
  prev: Record<string, OutboundTransfer>,
  transferIdHex: string,
): Record<string, OutboundTransfer> {
  const cur = prev[transferIdHex]
  if (!cur || cur.status !== 'awaiting-decision') return prev
  return { ...prev, [transferIdHex]: { ...cur, status: 'streaming' } }
}

// formatBytes renders a byte count like "1.4 MB". Rounded to 1 dp
// for non-byte units; integer for raw bytes.
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let val = n / 1024
  let unit = units[0]
  for (let i = 1; i < units.length && val >= 1024; i++) {
    val /= 1024
    unit = units[i]
  }
  return `${val.toFixed(1)} ${unit}`
}
