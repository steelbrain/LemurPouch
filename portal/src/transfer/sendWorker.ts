// Send worker: pull-model chunk seal + hash. Main owns the WebSocket and
// pacing; this worker never sees socket state. Messages:
//   { type: 'start', transferId, sendKey, peerEd25519Pub, file, chunkSize, totalBytes }
//   { type: 'pull' }  → worker replies with
//       { type: 'frame', frame, sentBytes, last }
//     or, on the final chunk (single message — digest rides with the frame so
//     main cannot race transfer-end ahead of the last socket.send):
//       { type: 'frame', frame, sentBytes, last: true, sha256, transferId }
//   { type: 'abort' }

import { sha256 } from '@noble/hashes/sha2.js'

import { sealEnvelope } from './messenger'
import { INNER_TYPE_FILE_CHUNK } from '../crypto/envelope'
import { CHUNK_FLAG_LAST, buildChunk } from './chunk'

interface StartMsg {
  type: 'start'
  transferId: ArrayBuffer
  sendKey: ArrayBuffer
  peerEd25519Pub: ArrayBuffer
  file: File
  chunkSize: number
  totalBytes: number
}

type InMsg = StartMsg | { type: 'pull' } | { type: 'abort' }

let active: {
  transferId: Uint8Array
  sendKey: Uint8Array
  peer: Uint8Array
  file: File
  chunkSize: number
  totalBytes: number
  offset: number
  seq: number
  hasher: ReturnType<typeof sha256.create>
  done: boolean
} | null = null

self.onmessage = async (ev: MessageEvent<InMsg>) => {
  const msg = ev.data
  if (msg.type === 'abort') {
    active = null
    return
  }
  if (msg.type === 'start') {
    active = {
      transferId: new Uint8Array(msg.transferId),
      sendKey: new Uint8Array(msg.sendKey),
      peer: new Uint8Array(msg.peerEd25519Pub),
      file: msg.file,
      chunkSize: msg.chunkSize,
      totalBytes: msg.totalBytes,
      offset: 0,
      seq: 0,
      hasher: sha256.create(),
      done: false,
    }
    return
  }
  if (msg.type === 'pull') {
    if (!active || active.done) return
    const a = active
    const remaining = a.totalBytes - a.offset
    // Zero-byte file: single empty last chunk at seq 0.
    const size = a.totalBytes === 0 ? 0 : Math.min(a.chunkSize, remaining)
    const isLast = a.totalBytes === 0 || a.offset + size >= a.totalBytes
    let data = new Uint8Array(0)
    if (size > 0) {
      const buf = await a.file.slice(a.offset, a.offset + size).arrayBuffer()
      data = new Uint8Array(buf)
    }
    const flags = isLast ? CHUNK_FLAG_LAST : 0
    const chunkPlain = buildChunk(a.transferId, a.seq, flags, data)
    const frame = sealEnvelope(a.sendKey, a.peer, INNER_TYPE_FILE_CHUNK, chunkPlain)
    a.hasher.update(data)
    a.offset += size
    a.seq++
    const sentBytes = a.offset
    // Transfer ownership of the frame buffer to main.
    const copy = frame.buffer.slice(
      frame.byteOffset,
      frame.byteOffset + frame.byteLength,
    ) as ArrayBuffer
    const w = self as unknown as {
      postMessage(message: unknown, transfer?: Transferable[]): void
    }
    if (isLast) {
      // Digest rides on the last frame message so main can only send
      // transfer-end after that frame has been socket.send'd. A separate
      // 'end' message raced ahead under async onmessage + waitForWindow
      // and could mark the transfer done before the last chunk left,
      // leaving the receiver stuck at ~100% streaming.
      a.done = true
      const digest = a.hasher.digest()
      const shaBuf = digest.buffer.slice(
        digest.byteOffset,
        digest.byteOffset + digest.byteLength,
      ) as ArrayBuffer
      const tidBuf = a.transferId.buffer.slice(
        a.transferId.byteOffset,
        a.transferId.byteOffset + a.transferId.byteLength,
      ) as ArrayBuffer
      w.postMessage(
        {
          type: 'frame',
          frame: copy,
          sentBytes,
          last: true,
          sha256: shaBuf,
          transferId: tidBuf,
        },
        [copy, shaBuf, tidBuf],
      )
      active = null
    } else {
      w.postMessage({ type: 'frame', frame: copy, sentBytes, last: false }, [copy])
    }
  }
}

export {}
