// Wire-protocol types and helpers for the cleartext JSON messages described
// in AGENTS.md "Wire Protocol > Cleartext Control". Mirrors the
// connection-handshake, discovery, and friendship subsets of
// internal/wireproto. Encrypted-envelope message types will be added when
// that layer lands. Type discriminator strings, JSON field names, and
// base64-encoded byte fields are kept identical to the Go side; any drift
// here silently breaks Go-TS interop.

// --- type discriminators ---

export const TYPE_CHALLENGE = 'challenge'
export const TYPE_IDENTIFY = 'identify'
export const TYPE_WELCOME = 'welcome'
export const TYPE_ERROR = 'error'

// Discovery — AGENTS.md "Discovery". The relay pushes peer-list once
// after WelcomeMsg and broadcasts peer-joined / peer-left as the live
// peer set changes.
export const TYPE_PEER_LIST = 'peer-list'
export const TYPE_PEER_JOINED = 'peer-joined'
export const TYPE_PEER_LEFT = 'peer-left'

// Friendship — AGENTS.md "Consent Model > Tier 1: Friendship".
//
// Three c2s directives the client sends to express intent toward another
// peer (carrying a `to` ed25519_pub):
export const TYPE_INVITE = 'invite'
export const TYPE_ACCEPT = 'accept'
export const TYPE_REJECT = 'reject'

// Five s2c notifications the relay forwards/originates (carrying a `from`
// ed25519_pub: who the message is *about*):
//   - invite-from / accept-from / reject-from: a counterparty's directive
//     is being relayed to you.
//   - invite-deferred: an invite you previously sent (silently queued
//     because the recipient already had a pending invite from your IP)
//     just became the active invite — your turn finally came up.
//   - invite-auto-rejected: an invite you sent never reached the
//     recipient because they had previously rejected an invite from your
//     IP. The originator carried in `from` is the recipient who set the
//     rejection (NOT the sender of the auto-reject).
export const TYPE_INVITE_FROM = 'invite-from'
export const TYPE_ACCEPT_FROM = 'accept-from'
export const TYPE_REJECT_FROM = 'reject-from'
export const TYPE_INVITE_DEFERRED = 'invite-deferred'
export const TYPE_INVITE_AUTO_REJECTED = 'invite-auto-rejected'

// --- error code discriminators ---

export const ERR_MALFORMED = 'malformed'
export const ERR_INVALID_SIGNATURE = 'invalid-signature'
export const ERR_INTERNAL = 'internal-error'

// --- decoded message types ---
//
// After parsing JSON off the wire, byte fields are decoded from base64 to
// Uint8Array so consumers don't deal with base64 strings directly.

export interface PeerRecord {
  ed25519Pub: Uint8Array
  x25519Pub: Uint8Array
  sigBinding: Uint8Array
  ip: string
  port: number
}

export interface ChallengeMsg {
  type: typeof TYPE_CHALLENGE
  nonce: Uint8Array
}

export interface IdentifyMsg {
  type: typeof TYPE_IDENTIFY
  ed25519Pub: Uint8Array
  x25519Pub: Uint8Array
  sigLiveness: Uint8Array
  sigBinding: Uint8Array
}

export interface WelcomeLimits {
  maxChunkBytes: number
}

export interface WelcomeMsg {
  type: typeof TYPE_WELCOME
  you: PeerRecord
  /** Absent on old relays ⇒ treat as 64 KiB floor. */
  limits?: WelcomeLimits
}

export interface ErrorMsg {
  type: typeof TYPE_ERROR
  code: string
  message: string
}

// Discovery messages. PeerListMsg arrives once immediately after WelcomeMsg
// (excludes the recipient's own record). PeerJoinedMsg / PeerLeftMsg are
// broadcast as the live peer set changes.
export interface PeerListMsg {
  type: typeof TYPE_PEER_LIST
  peers: PeerRecord[]
}

export interface PeerJoinedMsg {
  type: typeof TYPE_PEER_JOINED
  peer: PeerRecord
}

export interface PeerLeftMsg {
  type: typeof TYPE_PEER_LEFT
  ed25519Pub: Uint8Array
}

// Friendship s2c notifications. The shape is uniform — `{type, from}` —
// across all five variants because the relay forwards the originator's
// identity in `from` regardless of which side of the handshake fired the
// notification.
export interface InviteFromMsg {
  type: typeof TYPE_INVITE_FROM
  from: Uint8Array
}

export interface AcceptFromMsg {
  type: typeof TYPE_ACCEPT_FROM
  from: Uint8Array
}

export interface RejectFromMsg {
  type: typeof TYPE_REJECT_FROM
  from: Uint8Array
}

export interface InviteDeferredMsg {
  type: typeof TYPE_INVITE_DEFERRED
  from: Uint8Array
}

export interface InviteAutoRejectedMsg {
  type: typeof TYPE_INVITE_AUTO_REJECTED
  from: Uint8Array
}

// FriendshipNotificationMsg is the discriminated union of every s2c
// friendship notification. Single source of truth for the dispatcher's
// return type and the per-type interfaces — adding a new variant in one
// place forces the dispatcher's exhaustive switch to update or fail to
// compile.
export type FriendshipNotificationMsg =
  | InviteFromMsg
  | AcceptFromMsg
  | RejectFromMsg
  | InviteDeferredMsg
  | InviteAutoRejectedMsg

// --- error classes ---

// Thrown when a frame can't be parsed or doesn't have the expected shape /
// type. Distinct from RelayRejectedError, which represents a well-formed
// rejection that the relay sent intentionally.
export class WireProtocolError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'WireProtocolError'
  }
}

// Thrown when the relay sends an ErrorMsg in response to our request.
// `code` matches one of the ERR_* constants (or a future code).
export class RelayRejectedError extends Error {
  readonly code: string
  constructor(err: ErrorMsg) {
    super(`relay rejected: ${err.code} (${err.message})`)
    this.name = 'RelayRejectedError'
    this.code = err.code
  }
}

// --- base64 helpers ---
//
// Go's encoding/json marshals []byte as RFC 4648 standard base64 with
// padding. We use the same encoding so JSON over the wire round-trips.

// TODO(perf): O(n^2) string concatenation. Acceptable for the small
// handshake payloads (≤ a few hundred bytes), but the future encrypted
// envelope/binary-frame layer (AGENTS.md "Encrypted Envelopes") will need
// a chunked builder or native Uint8Array → base64 conversion.
export function bytesToBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// --- parsing helpers ---

function expectObject(v: unknown): Record<string, unknown> {
  if (typeof v !== 'object' || v === null) {
    throw new WireProtocolError('expected JSON object')
  }
  return v as Record<string, unknown>
}

function expectString(v: unknown, field: string): string {
  if (typeof v !== 'string') {
    throw new WireProtocolError(`field "${field}" must be a string`)
  }
  return v
}

function expectInteger(v: unknown, field: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v)) {
    throw new WireProtocolError(`field "${field}" must be an integer`)
  }
  return v
}

function decodeB64Field(obj: Record<string, unknown>, field: string): Uint8Array {
  const s = expectString(obj[field], field)
  try {
    return base64ToBytes(s)
  } catch (e) {
    // base64ToBytes -> atob throws DOMException (InvalidCharacterError) on
    // malformed input. Wrap so callers can rely on the WireProtocolError
    // typed-error contract documented on the parsers above.
    throw new WireProtocolError(
      `field "${field}" is not valid base64: ${(e as Error).message}`,
    )
  }
}

// parseJsonObject wraps JSON.parse so the concrete frame parsers raise
// WireProtocolError (rather than a raw SyntaxError) on malformed JSON.
// Callers can `instanceof WireProtocolError`-discriminate uniformly.
function parseJsonObject(json: string): Record<string, unknown> {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch (e) {
    throw new WireProtocolError(`malformed JSON: ${(e as Error).message}`)
  }
  return expectObject(parsed)
}

// PeekType extracts the {"type": "..."} field from a JSON frame. Returns
// null if the frame is malformed JSON, isn't an object, or has a non-string
// type field. Used to dispatch to the correct concrete parser.
export function peekType(json: string): string | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  const t = (parsed as Record<string, unknown>).type
  return typeof t === 'string' ? t : null
}

export function parsePeerRecord(o: unknown): PeerRecord {
  const obj = expectObject(o)
  return {
    ed25519Pub: decodeB64Field(obj, 'ed25519_pub'),
    x25519Pub: decodeB64Field(obj, 'x25519_pub'),
    sigBinding: decodeB64Field(obj, 'sig_binding'),
    ip: expectString(obj.ip, 'ip'),
    port: expectInteger(obj.port, 'port'),
  }
}

export function parseChallenge(json: string): ChallengeMsg {
  const obj = parseJsonObject(json)
  if (obj.type !== TYPE_CHALLENGE) {
    throw new WireProtocolError(
      `expected type "${TYPE_CHALLENGE}", got "${String(obj.type)}"`,
    )
  }
  return { type: TYPE_CHALLENGE, nonce: decodeB64Field(obj, 'nonce') }
}

export function parseWelcome(json: string): WelcomeMsg {
  const obj = parseJsonObject(json)
  if (obj.type !== TYPE_WELCOME) {
    throw new WireProtocolError(
      `expected type "${TYPE_WELCOME}", got "${String(obj.type)}"`,
    )
  }
  const out: WelcomeMsg = { type: TYPE_WELCOME, you: parsePeerRecord(obj.you) }
  if (obj.limits !== undefined && obj.limits !== null) {
    const lim = expectObject(obj.limits)
    const raw = lim.max_chunk_bytes
    if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 0) {
      throw new WireProtocolError('field "limits.max_chunk_bytes" must be a non-negative integer')
    }
    // Floor at 64 KiB — same invariant as Go FloorChunkSize.
    out.limits = { maxChunkBytes: Math.max(raw, 64 * 1024) }
  }
  return out
}

export function parsePeerList(json: string): PeerListMsg {
  const obj = parseJsonObject(json)
  if (obj.type !== TYPE_PEER_LIST) {
    throw new WireProtocolError(
      `expected type "${TYPE_PEER_LIST}", got "${String(obj.type)}"`,
    )
  }
  // Go marshals nil []PeerRecord as JSON null; an explicitly-allocated
  // empty slice marshals as []. Treat both as "no other peers." JSON has
  // no `undefined` literal so we don't need to handle that case.
  const rawPeers = obj.peers
  if (rawPeers === null) {
    return { type: TYPE_PEER_LIST, peers: [] }
  }
  if (!Array.isArray(rawPeers)) {
    throw new WireProtocolError('field "peers" must be an array')
  }
  return {
    type: TYPE_PEER_LIST,
    peers: rawPeers.map((p) => parsePeerRecord(p)),
  }
}

export function parsePeerJoined(json: string): PeerJoinedMsg {
  const obj = parseJsonObject(json)
  if (obj.type !== TYPE_PEER_JOINED) {
    throw new WireProtocolError(
      `expected type "${TYPE_PEER_JOINED}", got "${String(obj.type)}"`,
    )
  }
  return { type: TYPE_PEER_JOINED, peer: parsePeerRecord(obj.peer) }
}

export function parsePeerLeft(json: string): PeerLeftMsg {
  const obj = parseJsonObject(json)
  if (obj.type !== TYPE_PEER_LEFT) {
    throw new WireProtocolError(
      `expected type "${TYPE_PEER_LEFT}", got "${String(obj.type)}"`,
    )
  }
  return {
    type: TYPE_PEER_LEFT,
    ed25519Pub: decodeB64Field(obj, 'ed25519_pub'),
  }
}

// DiscoveryMsg is the discriminated union of every s2c discovery frame the
// relay pushes during a connected session. Single source of truth for the
// dispatcher's return type — adding a new discovery variant in one place
// forces the dispatch table below to update or fail to compile.
export type DiscoveryMsg = PeerListMsg | PeerJoinedMsg | PeerLeftMsg

// discoveryParsers is a per-type dispatch table keyed by the DiscoveryMsg
// union's `type` discriminator. Typing the table as
// Record<DiscoveryMsg['type'], ...> forces the table to cover every
// variant in the union — adding a new discovery interface without
// registering its parser here is a compile error. Mirrors the same
// exhaustiveness pattern used by friendshipNotificationParsers below.
const discoveryParsers: Record<
  DiscoveryMsg['type'],
  (json: string) => DiscoveryMsg
> = {
  [TYPE_PEER_LIST]: parsePeerList,
  [TYPE_PEER_JOINED]: parsePeerJoined,
  [TYPE_PEER_LEFT]: parsePeerLeft,
}

// parseDiscovery centralizes the per-type dispatch for the three discovery
// frames the relay can push during a connected session. Returns null for
// any other type (or unparseable type), so the App's message handler can
// stay a single call instead of repeating the peekType + parse* dance for
// each discriminator. Throws WireProtocolError if the type matches a
// discovery type but the payload is malformed — same contract as the
// per-type parsers.
export function parseDiscovery(json: string): DiscoveryMsg | null {
  const t = peekType(json)
  if (t === null) return null
  const parser = (
    discoveryParsers as Record<
      string,
      ((json: string) => DiscoveryMsg) | undefined
    >
  )[t]
  return parser ? parser(json) : null
}

// parseFriendshipNotificationOfType is the shared parser body for the five
// s2c friendship notifications, all of which have an identical
// `{type, from}` shape. Factored as a generic so the per-type wrappers
// retain a precise discriminated-union return type.
function parseFriendshipNotificationOfType<T extends string>(
  json: string,
  expectedType: T,
): { type: T; from: Uint8Array } {
  const obj = parseJsonObject(json)
  if (obj.type !== expectedType) {
    throw new WireProtocolError(
      `expected type "${expectedType}", got "${String(obj.type)}"`,
    )
  }
  return { type: expectedType, from: decodeB64Field(obj, 'from') }
}

export function parseInviteFrom(json: string): InviteFromMsg {
  return parseFriendshipNotificationOfType(json, TYPE_INVITE_FROM)
}

export function parseAcceptFrom(json: string): AcceptFromMsg {
  return parseFriendshipNotificationOfType(json, TYPE_ACCEPT_FROM)
}

export function parseRejectFrom(json: string): RejectFromMsg {
  return parseFriendshipNotificationOfType(json, TYPE_REJECT_FROM)
}

export function parseInviteDeferred(json: string): InviteDeferredMsg {
  return parseFriendshipNotificationOfType(json, TYPE_INVITE_DEFERRED)
}

export function parseInviteAutoRejected(json: string): InviteAutoRejectedMsg {
  return parseFriendshipNotificationOfType(json, TYPE_INVITE_AUTO_REJECTED)
}

// friendshipNotificationParsers is a per-type dispatch table keyed by the
// FriendshipNotificationMsg union's `type` discriminator. Typing the
// table as Record<FriendshipNotificationMsg['type'], ...> forces the
// table to cover every variant in the union — adding a new
// `*-from` / `invite-*` notification interface without registering its
// parser here is a compile error. This is the static guarantee the
// dispatcher relies on for exhaustiveness; mirrors discoveryParsers above
// for the discovery layer.
const friendshipNotificationParsers: Record<
  FriendshipNotificationMsg['type'],
  (json: string) => FriendshipNotificationMsg
> = {
  [TYPE_INVITE_FROM]: parseInviteFrom,
  [TYPE_ACCEPT_FROM]: parseAcceptFrom,
  [TYPE_REJECT_FROM]: parseRejectFrom,
  [TYPE_INVITE_DEFERRED]: parseInviteDeferred,
  [TYPE_INVITE_AUTO_REJECTED]: parseInviteAutoRejected,
}

// parseFriendshipNotification centralizes the per-type dispatch for the
// five s2c friendship notifications, mirroring parseDiscovery's role
// above for the discovery layer. Returns null for any other type (or
// unparseable type) so the App's message handler can stay a single call.
// Throws WireProtocolError if the type matches a friendship notification
// but the payload is malformed — same contract as the per-type parsers.
export function parseFriendshipNotification(json: string): FriendshipNotificationMsg | null {
  const t = peekType(json)
  if (t === null) return null
  const parser = (
    friendshipNotificationParsers as Record<
      string,
      ((json: string) => FriendshipNotificationMsg) | undefined
    >
  )[t]
  return parser ? parser(json) : null
}

export function parseError(json: string): ErrorMsg {
  const obj = parseJsonObject(json)
  if (obj.type !== TYPE_ERROR) {
    throw new WireProtocolError(
      `expected type "${TYPE_ERROR}", got "${String(obj.type)}"`,
    )
  }
  return {
    type: TYPE_ERROR,
    code: expectString(obj.code, 'code'),
    message: expectString(obj.message, 'message'),
  }
}

// --- encoding helpers ---

// buildIdentifyMsg returns a JSON-encoded IdentifyMsg with byte fields
// base64-encoded so the Go relay's encoding/json unmarshalling round-trips
// them as []byte. The Type field is hardcoded so a caller can't accidentally
// produce a struct with the wrong discriminator.
export function buildIdentifyMsg(msg: Omit<IdentifyMsg, 'type'>): string {
  return JSON.stringify({
    type: TYPE_IDENTIFY,
    ed25519_pub: bytesToBase64(msg.ed25519Pub),
    x25519_pub: bytesToBase64(msg.x25519Pub),
    sig_liveness: bytesToBase64(msg.sigLiveness),
    sig_binding: bytesToBase64(msg.sigBinding),
  })
}

// buildFriendshipDirective is the shared body for the three c2s directives
// (invite/accept/reject), all of which marshal to `{type, to}` with `to`
// as the recipient's ed25519_pub bytes. Factored privately and exposed via
// per-type helpers so a caller can't accidentally pass an arbitrary string
// in `type`.
function buildFriendshipDirective(
  type: typeof TYPE_INVITE | typeof TYPE_ACCEPT | typeof TYPE_REJECT,
  to: Uint8Array,
): string {
  return JSON.stringify({ type, to: bytesToBase64(to) })
}

export function buildInviteMsg(to: Uint8Array): string {
  return buildFriendshipDirective(TYPE_INVITE, to)
}

export function buildAcceptMsg(to: Uint8Array): string {
  return buildFriendshipDirective(TYPE_ACCEPT, to)
}

export function buildRejectMsg(to: Uint8Array): string {
  return buildFriendshipDirective(TYPE_REJECT, to)
}
