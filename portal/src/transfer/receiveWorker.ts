// Receive worker: decrypt file-chunk envelopes, assemble (memory or OPFS),
// hash, post throttled progress. Main routes 0x02 frames here (peerHex +
// raw frame only); demux by transfer_id after decrypt so concurrent
// receives from the same peer never cross-wire.
//
// Handlers are serialized through a single promise chain so an async
// 'start' (OPFS open) cannot race a later 'frame' past assembles.set.
//
// OPFS write path: prefer createSyncAccessHandle (fast, worker-only; Safari
// exposes it here but NOT on the main-thread prototype). Fall back to
// createWritable when sync handles are missing.

import { openEnvelope } from './messenger'
import { INNER_TYPE_FILE_CHUNK } from '../crypto/envelope'
import { parseChunk } from './chunk'
import {
  acceptChunk,
  memorySink,
  newInboundAssembler,
  type InboundAssembler,
  type TransferSink,
} from './state'
import { takeNeedAck } from './negotiate'
import { bytesToHex } from '@noble/hashes/utils.js'

type SinkMode = 'memory' | 'opfs'

// Minimal typing for worker-only OPFS APIs (not in all TS DOM libs).
interface SyncAccessHandle {
  write(buffer: BufferSource, options?: { at?: number }): number
  flush(): void
  close(): void
}

interface WritableLike {
  write(data: BufferSource | { type: 'write'; data: BufferSource; position?: number }): Promise<void>
  close(): Promise<void>
}

interface RegisterFriend {
  type: 'registerFriend'
  peerHex: string
  recvKey: ArrayBuffer
}
interface RemoveFriend {
  type: 'removeFriend'
  peerHex: string
}
interface StartTransfer {
  type: 'start'
  transferIdHex: string
  peerHex: string
  totalBytes: number
  mode: SinkMode
  /** Receiver-advertised window; worker fires needAck at window/4. */
  windowBytes: number
}
/** Raw envelope; worker demuxes by decrypted transfer_id. */
interface FrameMsg {
  type: 'frame'
  peerHex: string
  frame: ArrayBuffer
}
interface EndMsg {
  type: 'end'
  transferIdHex: string
  expectedSha256: ArrayBuffer
}
interface AbortMsg {
  type: 'abort'
  transferIdHex: string
}

type InMsg =
  | RegisterFriend
  | RemoveFriend
  | StartTransfer
  | FrameMsg
  | EndMsg
  | AbortMsg

const keys = new Map<string, Uint8Array>()
const assembles = new Map<
  string,
  {
    asm: InboundAssembler
    peerHex: string
    mode: SinkMode
    handle: SyncAccessHandle | null
    writable: WritableLike | null
    writeOffset: number
    lastProgressAt: number
    windowBytes: number
    lastAcked: number
  }
>()

// Frames that arrive before their transfer's 'start' completes are held
// here keyed by peerHex, then drained once assembles has the entry (demux
// by transfer_id after decrypt).
const pendingByPeer = new Map<string, ArrayBuffer[]>()

function post(msg: unknown, transfer?: Transferable[]) {
  const w = self as unknown as {
    postMessage(message: unknown, transfer?: Transferable[]): void
  }
  w.postMessage(msg, transfer)
}

async function opfsSink(
  transferIdHex: string,
): Promise<{
  sink: TransferSink
  handle: SyncAccessHandle | null
  writable: WritableLike | null
}> {
  const root = await navigator.storage.getDirectory()
  const inflight = await root.getDirectoryHandle('inflight', { create: true })
  const fileHandle = await inflight.getFileHandle(transferIdHex, { create: true })

  // 1) Sync access handle — preferred; available in dedicated workers
  //    (including Safari). Not always present on the main-thread prototype.
  const createSync = (
    fileHandle as unknown as {
      createSyncAccessHandle?: () => Promise<SyncAccessHandle>
    }
  ).createSyncAccessHandle
  if (typeof createSync === 'function') {
    const handle = await createSync.call(fileHandle)
    let offset = 0
    const sink: TransferSink = {
      write(data: Uint8Array) {
        handle.write(data as Uint8Array<ArrayBuffer>, { at: offset })
        offset += data.length
      },
      snapshot() {
        return null
      },
    }
    return { sink, handle, writable: null }
  }

  // 2) Async writable stream — broader main/worker support fallback.
  const createWritable = (
    fileHandle as unknown as {
      createWritable?: () => Promise<WritableLike>
    }
  ).createWritable
  if (typeof createWritable === 'function') {
    const writable = await createWritable.call(fileHandle)
    let offset = 0
    const sink: TransferSink = {
      write(data: Uint8Array) {
        // acceptChunk is sync; queue writes on the stream. The message
        // chain awaits handleMsg, but write itself is fire-and-forget
        // from the sink's perspective — we keep a tail promise so end
        // flushes before close.
        const pos = offset
        offset += data.length
        const copy = data.slice()
        writeTail = writeTail.then(() =>
          writable.write({
            type: 'write',
            data: copy as Uint8Array<ArrayBuffer>,
            position: pos,
          }),
        )
      },
      snapshot() {
        return null
      },
    }
    return { sink, handle: null, writable }
  }

  throw new Error(
    'OPFS has no createSyncAccessHandle or createWritable in this worker',
  )
}

// Serializes async writable.write calls for the createWritable fallback.
let writeTail: Promise<void> = Promise.resolve()

// Serialize all message handling so await inside 'start' cannot let a
// concurrent 'frame' handler run before assembles.set.
let chain: Promise<void> = Promise.resolve()

self.onmessage = (ev: MessageEvent<InMsg>) => {
  const msg = ev.data
  chain = chain.then(() => handleMsg(msg)).catch((err) => {
    const id =
      'transferIdHex' in msg ? (msg as { transferIdHex: string }).transferIdHex : ''
    post({
      type: id ? 'startFailed' : 'aborted',
      transferIdHex: id,
      reason: String(err),
    })
  })
}

async function handleMsg(msg: InMsg): Promise<void> {
  switch (msg.type) {
    case 'registerFriend':
      keys.set(msg.peerHex, new Uint8Array(msg.recvKey))
      break
    case 'removeFriend':
      keys.delete(msg.peerHex)
      break
    case 'start': {
      try {
        let sink: TransferSink
        let handle: SyncAccessHandle | null = null
        let writable: WritableLike | null = null
        if (msg.mode === 'opfs') {
          const s = await opfsSink(msg.transferIdHex)
          sink = s.sink
          handle = s.handle
          writable = s.writable
        } else {
          sink = memorySink(msg.totalBytes)
        }
        // OPFS path: assembler does not preallocate totalBytes in RAM.
        const asm = newInboundAssembler(msg.totalBytes, sink)
        assembles.set(msg.transferIdHex, {
          asm,
          peerHex: msg.peerHex,
          mode: msg.mode,
          handle,
          writable,
          writeOffset: 0,
          lastProgressAt: 0,
          windowBytes: msg.windowBytes > 0 ? msg.windowBytes : 0,
          lastAcked: 0,
        })
        // Tell main the disk path is ready BEFORE it sends transfer-accept,
        // so a failed open never races the peer into streaming.
        post({ type: 'startReady', transferIdHex: msg.transferIdHex })
        await drainPendingForPeer(msg.peerHex)
      } catch (err) {
        post({
          type: 'startFailed',
          transferIdHex: msg.transferIdHex,
          reason:
            err instanceof Error
              ? err.message
              : 'could not open on-disk receive path',
        })
      }
      break
    }
    case 'frame':
      await handleFrame(msg.peerHex, msg.frame)
      break
    case 'end': {
      const entry = assembles.get(msg.transferIdHex)
      if (!entry) return
      // Flush async writable before finalize comparison.
      if (entry.writable) {
        await writeTail
      }
      entry.asm.expectedSha256 = new Uint8Array(msg.expectedSha256)
      tryFinalize(msg.transferIdHex)
      break
    }
    case 'abort':
      cleanup(msg.transferIdHex, true)
      break
  }
}

async function handleFrame(peerHex: string, frame: ArrayBuffer): Promise<void> {
  const recvKey = keys.get(peerHex)
  if (!recvKey) return

  // If this peer has no active assemble yet, buffer until start lands.
  let hasActive = false
  for (const e of assembles.values()) {
    if (e.peerHex === peerHex) {
      hasActive = true
      break
    }
  }
  if (!hasActive) {
    const q = pendingByPeer.get(peerHex) ?? []
    q.push(frame)
    pendingByPeer.set(peerHex, q)
    return
  }

  processFrame(peerHex, recvKey, frame)
  // Keep writeTail progressing; no await needed per frame for sync handle.
  if (writeTail) {
    // Swallow stream errors into the chain via a no-op catch so one
    // failed write doesn't permanently break later transfers.
    writeTail = writeTail.catch((err) => {
      console.warn('opfs writable write failed:', err)
    })
  }
}

async function drainPendingForPeer(peerHex: string): Promise<void> {
  const q = pendingByPeer.get(peerHex)
  if (!q || q.length === 0) return
  pendingByPeer.delete(peerHex)
  const recvKey = keys.get(peerHex)
  if (!recvKey) return
  for (const frame of q) {
    processFrame(peerHex, recvKey, frame)
  }
}

function processFrame(peerHex: string, recvKey: Uint8Array, frame: ArrayBuffer): void {
  let env
  try {
    env = openEnvelope(recvKey, new Uint8Array(frame))
  } catch {
    return
  }
  if (env.innerType !== INNER_TYPE_FILE_CHUNK) return
  let chunk
  try {
    chunk = parseChunk(env.plaintext)
  } catch {
    return
  }
  // Demux by decrypted transfer_id — concurrent receives from the same
  // peer each have a distinct id; main never stamps one.
  const transferIdHex = bytesToHex(chunk.transferId)
  const entry = assembles.get(transferIdHex)
  if (!entry) {
    // Start for this id not ready yet — re-buffer under peer.
    const q = pendingByPeer.get(peerHex) ?? []
    q.push(frame)
    pendingByPeer.set(peerHex, q)
    return
  }
  if (entry.peerHex !== peerHex) return

  const result = acceptChunk(entry.asm, chunk.seq, chunk.flags, chunk.data)
  if (result === 'abort') {
    cleanup(transferIdHex, true)
    post({ type: 'aborted', transferIdHex, reason: 'chunk-abort' })
    return
  }
  if (result === 'duplicate') return

  const received = entry.asm.receivedBytes
  // Flow-control: report every time received crosses window/4 past last
  // acked — not throttled. UI progress stays ≤10 Hz separately.
  const need = takeNeedAck(received, entry.lastAcked, entry.windowBytes)
  if (need) {
    entry.lastAcked = need.lastAcked
    post({
      type: 'needAck',
      transferIdHex,
      receivedBytes: need.receivedBytes,
    })
  }
  const now = Date.now()
  if (now - entry.lastProgressAt >= 100) {
    entry.lastProgressAt = now
    post({
      type: 'progress',
      transferIdHex,
      receivedBytes: received,
    })
  }
  tryFinalize(transferIdHex)
}

function tryFinalize(transferIdHex: string): void {
  const entry = assembles.get(transferIdHex)
  if (!entry) return
  const { asm } = entry
  if (asm.digest === null || asm.expectedSha256 === null) return
  const ok =
    asm.digest.length === asm.expectedSha256.length &&
    asm.digest.every((b, i) => b === asm.expectedSha256![i])
  if (!ok) {
    cleanup(transferIdHex, true)
    post({ type: 'aborted', transferIdHex, reason: 'sha256-mismatch' })
    return
  }
  void (async () => {
    try {
      if (entry.writable) {
        await writeTail
        await entry.writable.close()
        entry.writable = null
      }
      if (entry.handle) {
        entry.handle.flush()
        entry.handle.close()
        entry.handle = null
      }
    } catch (err) {
      cleanup(transferIdHex, true)
      post({
        type: 'aborted',
        transferIdHex,
        reason: err instanceof Error ? err.message : 'opfs finalize failed',
      })
      return
    }
    const snap = asm.sink.snapshot()
    assembles.delete(transferIdHex)
    if (snap) {
      const buf = snap.buffer.slice(snap.byteOffset, snap.byteOffset + snap.byteLength)
      post(
        {
          type: 'done',
          transferIdHex,
          mode: 'memory',
          bytes: buf,
          totalBytes: asm.totalBytes,
        },
        [buf as ArrayBuffer],
      )
    } else {
      post({
        type: 'done',
        transferIdHex,
        mode: 'opfs',
        totalBytes: asm.totalBytes,
      })
    }
  })()
}

function cleanup(transferIdHex: string, deleteOpfs: boolean): void {
  const entry = assembles.get(transferIdHex)
  if (!entry) return
  if (entry.handle) {
    try {
      entry.handle.close()
    } catch {
      /* ignore */
    }
    entry.handle = null
  }
  if (entry.writable) {
    void entry.writable.close().catch(() => {
      /* ignore */
    })
    entry.writable = null
  }
  assembles.delete(transferIdHex)
  if (deleteOpfs && entry.mode === 'opfs') {
    void (async () => {
      try {
        const root = await navigator.storage.getDirectory()
        const inflight = await root.getDirectoryHandle('inflight')
        await inflight.removeEntry(transferIdHex)
      } catch {
        /* ignore */
      }
    })()
  }
}

export {}
