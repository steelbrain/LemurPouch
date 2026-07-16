// High-level encrypted-envelope messenger — wires together the
// per-friendship session keys (../crypto/session), the AEAD
// (../crypto/aead), and the binary envelope wire format
// (../crypto/envelope) into a small surface that the App can drive
// without touching crypto on every send / receive.
//
// Lifecycle:
//   1. After connectToRelay, construct an EnvelopeMessenger(socket, identity).
//   2. When a friendship is mutually established (accept-from arrives,
//      OR you click Accept on an incoming invite), call registerFriend
//      with the peer's discovery record. This derives the per-pair
//      session keys once and caches them.
//   3. send(peer, innerType, plaintext) and onEnvelope(handler) work
//      as long as the friendship is registered.
//   4. When peer-left arrives (or the friendship is otherwise torn
//      down), call removeFriend to evict the cached keys.
//   5. close() unsubscribes the underlying socket listener and clears
//      all state — call from the React effect cleanup.
//
// Receive-side failures (no friendship, AEAD auth fail, malformed
// frame) drop silently with a console.warn — the relay never replies
// inline to envelope frames, and surfacing inline errors would leak
// routing/keying state to a probing attacker.

import { bytesToHex } from '@noble/hashes/utils.js'

import { type Identity } from '../crypto/index'
import { aeadDecrypt, aeadEncrypt } from '../crypto/aead'
import {
  marshalEnvelope,
  parseEnvelopeHeader,
  ENVELOPE_PEER_KEY_LEN,
} from '../crypto/envelope'
import { deriveSessionKeys, type SessionKeys } from '../crypto/session'
import { type PeerRecord } from '../relay/wire'

export interface IncomingEnvelope {
  // Sender's ed25519_pub — the relay's authenticated rewrite of the
  // peer field. A fresh-allocated copy (not a view into the underlying
  // frame buffer) so the receiver can store it past the next socket
  // message without aliasing concerns.
  from: Uint8Array
  innerType: number
  // Decrypted plaintext. Always a freshly-allocated Uint8Array.
  plaintext: Uint8Array
}

// Subset of WebSocket the messenger actually uses. send()'s
// parameter is BufferSource (the DOM type for binary IO arguments,
// = ArrayBuffer | ArrayBufferView<ArrayBuffer>). This is the
// narrowest type that:
//   1. is contravariant-assignable from the real WebSocket.send
//      (which accepts string | BufferSource | Blob), so a real
//      WebSocket satisfies the interface; and
//   2. excludes SharedArrayBuffer-backed views (WebSocket itself
//      doesn't accept those, so the messenger must not produce them
//      either — marshalEnvelope's caller-side cast in send() makes
//      this explicit).
export interface EnvelopeSocket {
  send(data: BufferSource): void
  addEventListener(
    type: 'message',
    listener: (ev: MessageEvent) => void,
  ): void
  removeEventListener(
    type: 'message',
    listener: (ev: MessageEvent) => void,
  ): void
}

// sealEnvelope is the pure-function send-side primitive: encrypt the
// plaintext under sendKey with a fresh nonce, wrap in the binary
// envelope frame addressed to peer. Useful as a public export so
// callers that want to encrypt-without-sending (e.g. for batched I/O
// or testing) don't need to instantiate a messenger.
export function sealEnvelope(
  sendKey: Uint8Array,
  peerEd25519Pub: Uint8Array,
  innerType: number,
  plaintext: Uint8Array,
): Uint8Array {
  if (peerEd25519Pub.length !== ENVELOPE_PEER_KEY_LEN) {
    throw new Error(
      `messenger: peerEd25519Pub must be ${ENVELOPE_PEER_KEY_LEN} bytes, got ${peerEd25519Pub.length}`,
    )
  }
  const aad = new Uint8Array([innerType & 0xff])
  const { nonce, sealed } = aeadEncrypt(sendKey, plaintext, aad)
  return marshalEnvelope(innerType, peerEd25519Pub, nonce, sealed)
}

// openEnvelope is the pure-function receive-side primitive: parse the
// binary envelope, decrypt the sealed payload under recvKey, and
// return the decoded {from, innerType, plaintext}. Throws on parse or
// decrypt failure — callers that want silent-drop semantics catch
// and ignore.
//
// from is a freshly-allocated Uint8Array (not a view into frame), so
// callers can store it past the next socket-message processing
// without aliasing concerns.
export function openEnvelope(
  recvKey: Uint8Array,
  frame: Uint8Array,
): IncomingEnvelope {
  const { header, sealed } = parseEnvelopeHeader(frame)
  const aad = new Uint8Array([header.innerType])
  const plaintext = aeadDecrypt(recvKey, header.nonce, sealed, aad)
  return {
    // slice() forces a fresh-allocation copy out of the
    // ParseEnvelopeHeader-aliased view, so the caller's IncomingEnvelope
    // survives the underlying frame buffer being reused.
    from: header.peerKey.slice(),
    innerType: header.innerType,
    plaintext,
  }
}

export class EnvelopeMessenger {
  private readonly sessionCache = new Map<string, SessionKeys>()
  private readonly subscribers = new Set<(env: IncomingEnvelope) => void>()
  private readonly socketHandler: (ev: MessageEvent) => void
  // Optional pre-handler for raw binary frames (e.g. route 0x02 to a
  // receive worker so decrypt+hash stay off the main thread). Return true
  // to skip the messenger's own decrypt path for that frame.
  private rawFrameHandler: ((frame: Uint8Array) => boolean) | null = null
  // Stored as explicit fields rather than constructor parameter
  // properties because the project's tsconfig sets erasableSyntaxOnly,
  // which rejects the parameter-property shorthand (it produces
  // runtime code beyond pure type erasure).
  private readonly socket: EnvelopeSocket
  private readonly identity: Identity
  private closed = false

  constructor(socket: EnvelopeSocket, identity: Identity) {
    this.socket = socket
    this.identity = identity
    this.socketHandler = (ev) => {
      if (this.closed) return
      // Only ArrayBuffer payloads are envelopes (the connection-handshake
      // sets binaryType='arraybuffer'). Strings are cleartext control
      // messages handled elsewhere; anything else is unknown and we
      // silently ignore.
      if (!(ev.data instanceof ArrayBuffer)) return
      const frame = new Uint8Array(ev.data)
      if (this.rawFrameHandler?.(frame)) return
      this.handleIncomingFrame(frame)
    }
    this.socket.addEventListener('message', this.socketHandler)
  }

  // setRawFrameHandler installs a pre-decrypt interceptor. Used by the
  // App to hand 0x02 file-chunk frames to a receive worker.
  setRawFrameHandler(handler: ((frame: Uint8Array) => boolean) | null): void {
    this.rawFrameHandler = handler
  }

  // registerFriend derives the per-friendship session keys for `peer`
  // and caches them. Idempotent: re-registering a peer overwrites the
  // cached entry (useful if the peer reconnects with a fresh X25519
  // key — though v0 reuses keys for the session lifetime).
  registerFriend(peer: PeerRecord): void {
    const keys = deriveSessionKeys(
      this.identity.x25519Priv,
      peer.x25519Pub,
      this.identity.ed25519Pub,
      peer.ed25519Pub,
    )
    this.sessionCache.set(bytesToHex(peer.ed25519Pub), keys)
  }

  // removeFriend evicts the cached session keys for the given peer.
  // Call from the peer-left handler — AGENTS.md "Session Lifetime".
  removeFriend(peerEd25519Pub: Uint8Array): void {
    this.sessionCache.delete(bytesToHex(peerEd25519Pub))
  }

  // hasFriend reports whether session keys are cached for the given
  // peer. Useful for UI gating ("disable Send button if !hasFriend").
  hasFriend(peerEd25519Pub: Uint8Array): boolean {
    return this.sessionCache.has(bytesToHex(peerEd25519Pub))
  }

  // getFriendKeys returns a copy of the cached directional keys for a
  // peer (for transfer workers). Returns null if the peer is not a friend.
  getFriendKeys(peerEd25519Pub: Uint8Array): SessionKeys | null {
    const k = this.sessionCache.get(bytesToHex(peerEd25519Pub))
    if (!k) return null
    return { sendKey: k.sendKey.slice(), recvKey: k.recvKey.slice() }
  }

  // send encrypts plaintext under the cached session key for peer and
  // ships the frame as a binary WebSocket message. Throws if no
  // session keys are cached for peer (the caller must registerFriend
  // first); throws if the underlying socket.send throws (e.g. socket
  // is CLOSING or CLOSED — caller decides whether to surface to the UI
  // or quietly retry).
  send(peerEd25519Pub: Uint8Array, innerType: number, plaintext: Uint8Array): void {
    if (this.closed) throw new Error('messenger: closed')
    const keys = this.sessionCache.get(bytesToHex(peerEd25519Pub))
    if (!keys) {
      throw new Error(
        `messenger: no session keys for peer ${bytesToHex(peerEd25519Pub).slice(0, 16)}…; registerFriend first`,
      )
    }
    const frame = sealEnvelope(keys.sendKey, peerEd25519Pub, innerType, plaintext)
    // marshalEnvelope (called inside sealEnvelope) constructs the
    // frame via `new Uint8Array(N)` which is Uint8Array<ArrayBuffer>
    // at runtime — never SharedArrayBuffer-backed — but TS infers
    // the broader Uint8Array<ArrayBufferLike>. The cast narrows to
    // satisfy the BufferSource-typed send parameter.
    this.socket.send(frame as Uint8Array<ArrayBuffer>)
  }

  // onEnvelope subscribes to incoming envelopes. Multi-subscriber:
  // each handler is called in registration order with the same
  // IncomingEnvelope object (handlers MUST treat it as read-only).
  // Returns an unsubscribe function. Safe to call any time before
  // close(); after close() it returns a no-op unsubscriber.
  onEnvelope(handler: (env: IncomingEnvelope) => void): () => void {
    if (this.closed) return () => {}
    this.subscribers.add(handler)
    return () => {
      this.subscribers.delete(handler)
    }
  }

  // close unsubscribes the underlying socket listener, clears the
  // session-key cache, and drops all subscribers. Idempotent — safe
  // to call multiple times. Call from the React effect cleanup or
  // when the WebSocket itself closes.
  close(): void {
    if (this.closed) return
    this.closed = true
    this.socket.removeEventListener('message', this.socketHandler)
    this.subscribers.clear()
    this.sessionCache.clear()
  }

  private handleIncomingFrame(frame: Uint8Array): void {
    let env: IncomingEnvelope
    try {
      // First peek the header to look up the session key — we need the
      // sender's ed25519_pub before openEnvelope can decrypt. (We could
      // call openEnvelope and have it look up the key internally, but
      // pulling key lookup out keeps the failure path's logging more
      // specific.)
      const { header } = parseEnvelopeHeader(frame)
      const fromHex = bytesToHex(header.peerKey)
      const keys = this.sessionCache.get(fromHex)
      if (!keys) {
        // Frame from a peer we don't have session keys for — could be
        // a stale frame after peer-left, an unknown peer, or an
        // attempted forgery. Silent drop (no warn — this can be noisy
        // in normal teardown sequences).
        return
      }
      env = openEnvelope(keys.recvKey, frame)
    } catch (err) {
      console.warn('envelope: incoming frame rejected:', err)
      return
    }

    for (const handler of this.subscribers) {
      try {
        handler(env)
      } catch (err) {
        // A throw from one handler must not block the others — common
        // case is a parse error inside a handler that wants to dispatch
        // by inner type; we log and continue.
        console.warn('envelope: handler threw:', err)
      }
    }
  }
}
