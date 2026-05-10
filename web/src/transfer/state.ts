// Transfer-state types + pure helpers for assembly and progress
// formatting. The App owns the React state that holds these records;
// this module just defines the shapes and the side-effect-free
// reassembly logic. AGENTS.md "Transfer Lifecycle" is the spec.

import { sha256 } from '@noble/hashes/sha2.js'

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
  // The file bytes, held in memory between offer-sent and the last
  // chunk going out. Set to null after status becomes 'done' /
  // 'rejected' / 'aborted' so the GC can reclaim.
  bytes: Uint8Array | null
}

// InboundTransfer is the receiver-side state for a file someone is
// (or wants to be) sending us.
export interface InboundTransfer {
  transferIdHex: string
  peerHex: string // sender's hex(ed25519_pub)
  filename: string
  totalBytes: number
  // Sender-advertised SHA-256 of the file payload, copied from the
  // transfer-offer. Verified against the assembled bytes in
  // tryAssemble before the transfer is allowed to flip to 'done'.
  expectedSha256: Uint8Array
  receivedBytes: number
  // Map<seq, chunk-data>. We tolerate out-of-order arrivals and
  // assemble in seq order once the last chunk + all gaps are filled.
  chunks: Map<number, Uint8Array>
  // Highest seq whose flags had CHUNK_FLAG_LAST set, or null if no
  // last-flag chunk has arrived yet. The receiver also accepts
  // transfer-end as a "no more chunks coming" signal even if the
  // last-flag chunk arrived earlier — they both converge on the same
  // assembly attempt.
  lastSeq: number | null
  status: 'offered' | 'streaming' | 'done' | 'rejected' | 'aborted'
  // Assembled bytes, set on the same setState pass that flips status
  // to 'done'. A separate post-commit step (a useEffect in App)
  // materializes these into a Blob + object URL — keeping the URL
  // creation OUT of the setState updater is required because React
  // (StrictMode and concurrent rendering) may invoke updaters more
  // than once per logical update, and `URL.createObjectURL` is not
  // idempotent: each call mints a fresh URL the browser holds alive
  // until `revokeObjectURL`. Cleared once `blobUrl` has been minted.
  assembledBytes?: Uint8Array
  // Object URL for downloading the assembled blob. Materialized from
  // `assembledBytes` post-commit. Caller is responsible for
  // URL.revokeObjectURL when the transfer is dropped.
  blobUrl?: string
}

// tryAssemble checks whether all chunks 0..lastSeq are present, and
// if so produces a status='done' InboundTransfer with `assembledBytes`
// holding the concatenated payload and the chunks map cleared
// (memory freed). If the assembled byte count or SHA-256 differs from
// what the sender advertised in the transfer-offer, returns
// status='aborted' instead — the AEAD already authenticated the bytes,
// so a divergence here means the sender's offer and stream don't agree
// (a buggy or hostile peer). Otherwise returns the input unchanged.
// Pure — no Blob / object-URL creation; caller materializes the URL in
// a post-commit step.
export function tryAssemble(t: InboundTransfer): InboundTransfer {
  if (t.lastSeq === null) return t // last chunk not seen yet
  // Walk 0..lastSeq looking for any gap.
  for (let seq = 0; seq <= t.lastSeq; seq++) {
    if (!t.chunks.has(seq)) return t
  }
  // All chunks present — assemble.
  let totalLen = 0
  for (const c of t.chunks.values()) totalLen += c.length
  const assembled = new Uint8Array(totalLen)
  let offset = 0
  for (let seq = 0; seq <= t.lastSeq; seq++) {
    // Non-null because the gap-walk above proved every seq is present.
    const c = t.chunks.get(seq)!
    assembled.set(c, offset)
    offset += c.length
  }
  if (assembled.length !== t.totalBytes) {
    return { ...t, status: 'aborted', chunks: new Map() }
  }
  if (!bytesEqualLocal(sha256(assembled), t.expectedSha256)) {
    return { ...t, status: 'aborted', chunks: new Map() }
  }
  return {
    ...t,
    status: 'done',
    assembledBytes: assembled,
    chunks: new Map(), // free chunk memory; assembled lives in assembledBytes
  }
}

function bytesEqualLocal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

// finalizeBlobUrl materializes the Blob and object URL for an inbound
// transfer that has `assembledBytes` set. Side-effecting (calls
// URL.createObjectURL); call from a post-commit hook (useEffect),
// never inside a setState updater. Returns a transfer with `blobUrl`
// set and `assembledBytes` cleared.
export function finalizeBlobUrl(t: InboundTransfer): InboundTransfer {
  if (!t.assembledBytes) return t
  // Use a generic MIME type — AGENTS.md doesn't define a content-type
  // negotiation, and the recipient downloads via Save As anyway. The
  // browser preserves the filename's extension when saving from a
  // download link, which is enough for the OS to round-trip the type.
  //
  // The `as Uint8Array<ArrayBuffer>` cast narrows the assembledBytes
  // field's broader Uint8Array<ArrayBufferLike> to the ArrayBuffer-
  // backed variant DOM BlobPart wants. The runtime allocation in
  // tryAssemble is `new Uint8Array(N)`, which is always
  // ArrayBuffer-backed; the cast is a no-op at runtime. Same pattern
  // as transfer/messenger.ts's WebSocket.send call site.
  const blob = new Blob(
    [t.assembledBytes as Uint8Array<ArrayBuffer>],
    { type: 'application/octet-stream' },
  )
  const blobUrl = URL.createObjectURL(blob)
  return {
    ...t,
    blobUrl,
    assembledBytes: undefined,
  }
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
