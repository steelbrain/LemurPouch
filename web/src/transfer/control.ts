// Transfer-control wire types — AGENTS.md "Encrypted Envelopes (binary
// frames) > Inner type 0x01 — JSON control (UTF-8)". These messages
// live INSIDE the encrypted envelope's plaintext payload (the relay
// never sees them); the build helpers return JSON strings ready to be
// passed to AEAD-encrypt, and the parsers consume the AEAD-decrypted
// plaintext.
//
// The transport is therefore encrypted end-to-end between the two
// peers, but the JSON-on-the-wire format is otherwise identical to the
// cleartext-relay wire (../relay/wire.ts) — same field-name and base64
// conventions so a hex dump of either layer reads consistently.

import { WireProtocolError, base64ToBytes, bytesToBase64, peekType } from '../relay/wire'

// --- type discriminators ---

export const TYPE_TRANSFER_OFFER = 'transfer-offer'
export const TYPE_TRANSFER_ACCEPT = 'transfer-accept'
export const TYPE_TRANSFER_REJECT = 'transfer-reject'
export const TYPE_TRANSFER_END = 'transfer-end'

// --- spec-mandated byte lengths ---

// transfer_id is 16 random bytes — distinguishes concurrent transfers
// between the same pair without the relay ever inspecting it.
export const TRANSFER_ID_LEN = 16

// sha256 is the 32-byte digest of the file payload, carried on
// transfer-end (NOT transfer-offer): the sender hashes incrementally
// while streaming, so the digest only exists once the last chunk has
// gone out. Integrity check the recipient runs after the last byte;
// not used for routing.
const SHA256_LEN = 32

// --- decoded message types ---

export interface TransferOfferMsg {
  type: typeof TYPE_TRANSFER_OFFER
  transferId: Uint8Array
  filename: string
  size: number
}

export interface TransferAcceptMsg {
  type: typeof TYPE_TRANSFER_ACCEPT
  transferId: Uint8Array
}

export interface TransferRejectMsg {
  type: typeof TYPE_TRANSFER_REJECT
  transferId: Uint8Array
  // Optional human-readable reason — the recipient may include this
  // when rejecting (e.g., "out of disk space"); senders log/display it.
  reason?: string
}

export interface TransferEndMsg {
  type: typeof TYPE_TRANSFER_END
  transferId: Uint8Array
  // The sender's finalized SHA-256 of the file payload, computed
  // incrementally as chunks were streamed. The recipient verifies it
  // against its own incremental digest of the received bytes.
  sha256: Uint8Array
}

// TransferControlMsg is the discriminated union of every inner-type-0x01
// JSON message. Single source of truth for the dispatcher's return
// type — adding a new variant in one place forces the dispatch table
// to update or fail to compile (mirrors the FriendshipNotificationMsg
// pattern in ../relay/wire.ts).
export type TransferControlMsg =
  | TransferOfferMsg
  | TransferAcceptMsg
  | TransferRejectMsg
  | TransferEndMsg

// --- build helpers ---
//
// All build helpers return a JSON string ready to be UTF-8 encoded and
// passed as plaintext to aeadEncrypt.

export function buildTransferOffer(
  transferId: Uint8Array,
  filename: string,
  size: number,
): string {
  if (transferId.length !== TRANSFER_ID_LEN) {
    throw new WireProtocolError(
      `transfer-offer: transfer_id must be ${TRANSFER_ID_LEN} bytes, got ${transferId.length}`,
    )
  }
  if (!Number.isInteger(size) || size < 0) {
    throw new WireProtocolError(
      `transfer-offer: size must be a non-negative integer, got ${size}`,
    )
  }
  return JSON.stringify({
    type: TYPE_TRANSFER_OFFER,
    transfer_id: bytesToBase64(transferId),
    filename,
    size,
  })
}

export function buildTransferAccept(transferId: Uint8Array): string {
  if (transferId.length !== TRANSFER_ID_LEN) {
    throw new WireProtocolError(
      `transfer-accept: transfer_id must be ${TRANSFER_ID_LEN} bytes, got ${transferId.length}`,
    )
  }
  return JSON.stringify({
    type: TYPE_TRANSFER_ACCEPT,
    transfer_id: bytesToBase64(transferId),
  })
}

export function buildTransferReject(transferId: Uint8Array, reason?: string): string {
  if (transferId.length !== TRANSFER_ID_LEN) {
    throw new WireProtocolError(
      `transfer-reject: transfer_id must be ${TRANSFER_ID_LEN} bytes, got ${transferId.length}`,
    )
  }
  // Only emit `reason` when the caller passed one; omitting the field
  // matches AGENTS.md's "<optional>" annotation and keeps the JSON
  // minimal.
  if (reason === undefined) {
    return JSON.stringify({
      type: TYPE_TRANSFER_REJECT,
      transfer_id: bytesToBase64(transferId),
    })
  }
  return JSON.stringify({
    type: TYPE_TRANSFER_REJECT,
    transfer_id: bytesToBase64(transferId),
    reason,
  })
}

export function buildTransferEnd(transferId: Uint8Array, sha256: Uint8Array): string {
  if (transferId.length !== TRANSFER_ID_LEN) {
    throw new WireProtocolError(
      `transfer-end: transfer_id must be ${TRANSFER_ID_LEN} bytes, got ${transferId.length}`,
    )
  }
  if (sha256.length !== SHA256_LEN) {
    throw new WireProtocolError(
      `transfer-end: sha256 must be ${SHA256_LEN} bytes, got ${sha256.length}`,
    )
  }
  return JSON.stringify({
    type: TYPE_TRANSFER_END,
    transfer_id: bytesToBase64(transferId),
    sha256: bytesToBase64(sha256),
  })
}

// --- parsers ---

export function parseTransferOffer(json: string): TransferOfferMsg {
  const obj = parseJsonObject(json)
  expectType(obj, TYPE_TRANSFER_OFFER)
  const transferId = decodeB64Field(obj, 'transfer_id', TRANSFER_ID_LEN)
  const filename = expectString(obj.filename, 'filename')
  const size = expectNonNegativeInteger(obj.size, 'size')
  return { type: TYPE_TRANSFER_OFFER, transferId, filename, size }
}

export function parseTransferAccept(json: string): TransferAcceptMsg {
  const obj = parseJsonObject(json)
  expectType(obj, TYPE_TRANSFER_ACCEPT)
  return {
    type: TYPE_TRANSFER_ACCEPT,
    transferId: decodeB64Field(obj, 'transfer_id', TRANSFER_ID_LEN),
  }
}

export function parseTransferReject(json: string): TransferRejectMsg {
  const obj = parseJsonObject(json)
  expectType(obj, TYPE_TRANSFER_REJECT)
  const out: TransferRejectMsg = {
    type: TYPE_TRANSFER_REJECT,
    transferId: decodeB64Field(obj, 'transfer_id', TRANSFER_ID_LEN),
  }
  // `reason` is optional. Accept missing OR null (Go marshals an
  // unset string field as "" rather than null, but a future Go-side
  // optional pointer field could marshal as null — robust to both).
  if (obj.reason !== undefined && obj.reason !== null) {
    out.reason = expectString(obj.reason, 'reason')
  }
  return out
}

export function parseTransferEnd(json: string): TransferEndMsg {
  const obj = parseJsonObject(json)
  expectType(obj, TYPE_TRANSFER_END)
  return {
    type: TYPE_TRANSFER_END,
    transferId: decodeB64Field(obj, 'transfer_id', TRANSFER_ID_LEN),
    sha256: decodeB64Field(obj, 'sha256', SHA256_LEN),
  }
}

// transferControlParsers is the per-type dispatch table keyed by the
// TransferControlMsg union's `type`. Typing as
// Record<TransferControlMsg['type'], ...> makes the table exhaustive at
// compile time — adding a new transfer-control variant without
// registering its parser here is a TS error. Mirrors the dispatcher
// pattern in ../relay/wire.ts.
const transferControlParsers: Record<
  TransferControlMsg['type'],
  (json: string) => TransferControlMsg
> = {
  [TYPE_TRANSFER_OFFER]: parseTransferOffer,
  [TYPE_TRANSFER_ACCEPT]: parseTransferAccept,
  [TYPE_TRANSFER_REJECT]: parseTransferReject,
  [TYPE_TRANSFER_END]: parseTransferEnd,
}

// parseTransferControl centralizes the per-type dispatch for
// inner-type-0x01 JSON messages. Returns null for any other type
// (or unparseable type) so the receive path can stay a single call.
// Throws WireProtocolError if the type matches a known variant but
// the payload is malformed — same null-vs-throw contract as
// parseDiscovery / parseFriendshipNotification.
export function parseTransferControl(data: string): TransferControlMsg | null {
  const t = peekType(data)
  if (t === null) return null
  const parser = (
    transferControlParsers as Record<
      string,
      ((json: string) => TransferControlMsg) | undefined
    >
  )[t]
  return parser ? parser(data) : null
}

// --- internal parsing helpers ---
//
// Locally-scoped to keep this module self-contained. The cleartext
// relay/wire.ts has its own private versions of these (kept private
// there because exposing them would invite cross-module drift); we
// duplicate the small surface here rather than re-export.

function parseJsonObject(json: string): Record<string, unknown> {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch (e) {
    throw new WireProtocolError(`malformed JSON: ${(e as Error).message}`)
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new WireProtocolError('expected JSON object')
  }
  return parsed as Record<string, unknown>
}

function expectType(obj: Record<string, unknown>, want: string): void {
  if (obj.type !== want) {
    throw new WireProtocolError(
      `expected type "${want}", got "${String(obj.type)}"`,
    )
  }
}

function expectString(v: unknown, field: string): string {
  if (typeof v !== 'string') {
    throw new WireProtocolError(`field "${field}" must be a string`)
  }
  return v
}

function expectNonNegativeInteger(v: unknown, field: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
    throw new WireProtocolError(
      `field "${field}" must be a non-negative integer`,
    )
  }
  return v
}

// decodeB64Field decodes a base64-encoded byte field and asserts its
// decoded length. The wantLen check is what catches a forged or
// truncated transfer_id / sha256 — without it, a sender could ship a
// 12-byte transfer_id that still parses but breaks downstream lookups.
function decodeB64Field(
  obj: Record<string, unknown>,
  field: string,
  wantLen: number,
): Uint8Array {
  const s = expectString(obj[field], field)
  let bytes: Uint8Array
  try {
    bytes = base64ToBytes(s)
  } catch (e) {
    throw new WireProtocolError(
      `field "${field}" is not valid base64: ${(e as Error).message}`,
    )
  }
  if (bytes.length !== wantLen) {
    throw new WireProtocolError(
      `field "${field}" must decode to ${wantLen} bytes, got ${bytes.length}`,
    )
  }
  return bytes
}
