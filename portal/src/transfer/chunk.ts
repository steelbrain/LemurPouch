// Inner 0x02 chunk format — AGENTS.md "Encrypted Envelopes > Inner
// type 0x02 — file chunk (binary)". Like the JSON control messages
// in ./control.ts, chunks live INSIDE the encrypted envelope's
// plaintext: the relay sees only ciphertext.
//
//   [ 16 bytes] transfer_id
//   [  4 bytes] seq          (uint32 big-endian)
//   [  1 byte ] flags         (bit 0 = last chunk)
//   [  N bytes] raw file data (target 64 KiB raw per chunk)
//
// The receiver writes chunks in `seq` order, buffering out-of-order
// arrivals. Multiple concurrent transfers between the same pair are
// supported by distinct transfer_ids; the relay never inspects them.

import { TRANSFER_ID_LEN } from './control'

export const CHUNK_HEADER_LEN = TRANSFER_ID_LEN + 4 + 1 // = 21

// Flags byte — only bit 0 is used in v0; the other 7 bits are reserved
// for forward-compat (a future "compressed-data" or "encrypted-twice"
// flag would land in one of them). Receivers should mask CHUNK_FLAG_LAST
// rather than equality-compare the flags byte so unknown bits don't
// trip the last-chunk check.
export const CHUNK_FLAG_LAST = 0x01

// ChunkError is the typed error every parse/build path throws on
// validation failure. Lets callers `instanceof ChunkError` to
// discriminate "wire-level malformed" from upstream JS errors.
export class ChunkError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ChunkError'
  }
}

export interface Chunk {
  transferId: Uint8Array // length 16; aliases plaintext[0..16] on parse
  seq: number // 0..2^32-1 (uint32 BE)
  flags: number // 0..255
  data: Uint8Array // arbitrary length (including 0); aliases plaintext[21:] on parse
}

// buildChunk concatenates the header parts and raw data into a single
// Uint8Array ready to feed to aeadEncrypt as plaintext. data may be
// empty (a trailing empty chunk with CHUNK_FLAG_LAST set is a valid
// way to signal "no more bytes" without sending any final byte —
// though the typical sender embeds the last bytes in the same chunk
// that sets the last flag).
//
// Throws ChunkError if transferId is not 16 bytes, seq is out of
// uint32 range, or flags is out of byte range.
export function buildChunk(
  transferId: Uint8Array,
  seq: number,
  flags: number,
  data: Uint8Array,
): Uint8Array {
  if (transferId.length !== TRANSFER_ID_LEN) {
    throw new ChunkError(
      `chunk: transfer_id must be ${TRANSFER_ID_LEN} bytes, got ${transferId.length}`,
    )
  }
  if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) {
    throw new ChunkError(`chunk: seq must be a uint32 (0..2^32-1), got ${seq}`)
  }
  if (!Number.isInteger(flags) || flags < 0 || flags > 0xff) {
    throw new ChunkError(`chunk: flags must be a byte (0..255), got ${flags}`)
  }
  const out = new Uint8Array(CHUNK_HEADER_LEN + data.length)
  out.set(transferId, 0)
  // DataView writes uint32 big-endian directly — clearer than manual
  // shifts and avoids the int32-vs-uint32 sign trap with `<<`.
  new DataView(out.buffer, out.byteOffset, CHUNK_HEADER_LEN).setUint32(
    TRANSFER_ID_LEN,
    seq,
    /* littleEndian = */ false,
  )
  out[CHUNK_HEADER_LEN - 1] = flags & 0xff
  out.set(data, CHUNK_HEADER_LEN)
  return out
}

// parseChunk extracts the chunk's structured fields from an envelope
// plaintext. transferId and data are zero-copy subarray views into
// the input — same aliasing contract as parseEnvelopeHeader: callers
// that need a stable snapshot should clone explicitly.
//
// Throws ChunkError if plaintext is shorter than CHUNK_HEADER_LEN.
export function parseChunk(plaintext: Uint8Array): Chunk {
  if (plaintext.length < CHUNK_HEADER_LEN) {
    throw new ChunkError(
      `chunk: plaintext too short: ${plaintext.length} bytes (min ${CHUNK_HEADER_LEN})`,
    )
  }
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, CHUNK_HEADER_LEN)
  return {
    transferId: plaintext.subarray(0, TRANSFER_ID_LEN),
    seq: view.getUint32(TRANSFER_ID_LEN, /* littleEndian = */ false),
    flags: plaintext[CHUNK_HEADER_LEN - 1],
    data: plaintext.subarray(CHUNK_HEADER_LEN),
  }
}

// isLastChunk masks the bit-0 last-chunk flag — receivers should use
// this rather than equality-compare the flags byte so unknown reserved
// bits in a future flags-byte addition don't break last-chunk detection.
export function isLastChunk(flags: number): boolean {
  return (flags & CHUNK_FLAG_LAST) !== 0
}
