// Connection-handshake client for the LemurPouch relay. See AGENTS.md
// "Connection Handshake" — opens a WebSocket to the relay, awaits the
// ChallengeMsg, signs the nonce with the local Identity, sends an
// IdentifyMsg, and resolves with the WelcomeMsg.you PeerRecord (or rejects
// with a RelayRejectedError on relay-side rejection / WireProtocolError on
// malformed frames).

import { type Identity, signBinding, signLiveness } from '../crypto/index'
import {
  type PeerRecord,
  type WelcomeLimits,
  RelayRejectedError,
  TYPE_CHALLENGE,
  TYPE_ERROR,
  TYPE_WELCOME,
  WireProtocolError,
  buildIdentifyMsg,
  parseChallenge,
  parseError,
  parseWelcome,
  peekType,
} from './wire'

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000

// RelayClosedError is thrown when the WebSocket closes before or during
// the handshake. It carries the raw close code/reason so callers (e.g.
// the App-level UI) can apply the same code-aware messaging they use for
// post-handshake closes — most importantly, special-casing 1008
// ("session replaced by newer connection") which the Go relay uses to
// displace a stale duplicate.
export class RelayClosedError extends Error {
  readonly code: number
  readonly reason: string
  constructor(code: number, reason: string) {
    super(`socket closed during handshake (code ${code}${reason ? `: ${reason}` : ''})`)
    this.name = 'RelayClosedError'
    this.code = code
    this.reason = reason
  }
}

// Allowed close codes per the WebSocket spec for the optional `code` arg
// to WebSocket.close: 1000 (normal closure) or any value in 3000-4999
// (application-defined). Other codes (e.g. 1006, 1008) are reserved for
// the protocol layer and throw if passed.
function isValidCloseCode(code: number): boolean {
  return code === 1000 || (code >= 3000 && code <= 4999)
}

export interface RelayConnection {
  // The open WebSocket. Subsequent layers (discovery, friendship, etc.)
  // attach their own listeners; this client only owns the handshake.
  // Prefer onMessage() over socket.addEventListener('message', ...) because
  // it closes the post-handshake race window — see the comment on
  // onMessage below.
  socket: WebSocket
  // The relay's view of the local peer (echoes the identity plus the IP
  // and ephemeral port the relay observed). Byte fields are freshly
  // allocated Uint8Array copies decoded from the welcome frame.
  you: PeerRecord
  // Optional relay capability ads from welcome.limits (absent on old relays).
  limits?: WelcomeLimits
  // The Identity passed in. Carried through so callers don't need to
  // thread it separately to subsequent layers.
  // Treat the byte fields as read-only — they are the same references the
  // caller passed in to connectToRelay.
  identity: Identity
  // Subscribe to post-handshake text frames. Frames the relay sent between
  // welcome and the first onMessage() call (e.g. the peer-list the Go
  // relay pushes immediately after welcome) are buffered in arrival order
  // and delivered synchronously on subscribe — closing the microtask gap
  // between connectToRelay's promise resolving and the App registering its
  // handler. After the buffer drains, live frames forward to the handler.
  //
  // First subscribe receives buffered + live frames; once it returns,
  // buffering is permanently disabled. Subsequent subscribers receive only
  // live frames. If every subscriber later unsubscribes, incoming frames
  // are dropped (the buffer never re-engages). Multiple concurrent
  // subscribers are supported and frames fan out in registration order.
  // Returns an unsubscribe function; calling it during a synchronous flush
  // stops further delivery to that handler immediately.
  //
  // Binary frames are dropped silently — text-only is what the cleartext
  // control protocol uses. Subsequent layers that need binary will add
  // their own handle.
  onMessage(handler: (data: string) => void): () => void
  // Convenience: gracefully close the WebSocket. Optional code/reason are
  // forwarded to WebSocket.close (default 1005 / empty when omitted).
  //
  // The WebSocket spec only allows 1000 or 3000-4999 as the close code;
  // passing anything else (e.g. 1006, 1008) makes the browser throw a
  // SyntaxError. Since callers will commonly want to forward the relay's
  // OWN close code straight back (e.g. echoing back a 1008 they observed),
  // any invalid code is silently dropped: we fall back to calling
  // socket.close() with no arguments rather than throwing.
  close(code?: number, reason?: string): void
}

export interface ConnectOptions {
  // Maximum time to wait for the relay's ChallengeMsg + WelcomeMsg.
  // Default 10s (matches the Go side's handshakeReadTimeout).
  timeoutMs?: number
  // Optional AbortSignal to cancel the handshake. Aborting after the
  // socket is open will close it.
  signal?: AbortSignal
}

// connectToRelay opens a WebSocket to url, runs the connection handshake,
// and resolves with a RelayConnection on success.
//
// On failure the underlying WebSocket is closed before the promise rejects,
// so callers don't need to clean up partial state. Possible rejection
// reasons:
//   - Error('socket error before open' / 'socket error during handshake')
//   - RelayClosedError (socket closed before/during handshake; carries the
//     close code and reason so callers can apply the same code-aware UI
//     they use for post-handshake closes)
//   - WireProtocolError (relay sent an unexpected or malformed frame)
//   - RelayRejectedError (relay sent a well-formed ErrorMsg)
//   - AbortError (caller aborted via options.signal)
//   - Error('handshake timed out')
export async function connectToRelay(
  url: string,
  identity: Identity,
  options: ConnectOptions = {},
): Promise<RelayConnection> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS
  // Reject pre-aborted signals before opening any socket — otherwise a
  // caller passing AbortSignal.abort() would still trigger a real connect
  // attempt to the relay, which could be wasteful or surprising.
  if (options.signal?.aborted) {
    throw new DOMException('aborted', 'AbortError')
  }
  const socket = new WebSocket(url)
  // Future layers (encrypted-envelope routing per AGENTS.md "Encrypted
  // Envelopes") need binary frames as ArrayBuffer rather than Blob.
  socket.binaryType = 'arraybuffer'

  // Wrap the whole handshake so any failure path closes the socket cleanly.
  try {
    await waitForOpen(socket, options.signal)
    const challenge = await readNextFrame(socket, timeoutMs, options.signal, peekChallenge)
    const identifyJson = buildIdentifyMsg({
      ed25519Pub: identity.ed25519Pub,
      x25519Pub: identity.x25519Pub,
      sigLiveness: signLiveness(identity, challenge.nonce),
      sigBinding: signBinding(identity),
    })
    // Re-check the abort signal after the async hops above; without this
    // a late abort would still synchronously transmit identify bytes.
    if (options.signal?.aborted) {
      throw new DOMException('aborted', 'AbortError')
    }
    socket.send(identifyJson)
    // readWelcomeWithBuffer attaches a single long-lived 'message' listener
    // BEFORE resolving with the welcome. Frames the relay sends after
    // welcome (e.g. peer-list, which the Go relay pushes immediately) are
    // captured into a buffer that the caller drains via onMessage(). This
    // closes the microtask gap that would otherwise exist between this
    // promise resolving and a consumer attaching its own listener.
    const { welcome, onMessage } = await readWelcomeWithBuffer(
      socket,
      timeoutMs,
      options.signal,
    )
    return {
      socket,
      you: welcome.you,
      limits: welcome.limits,
      identity,
      onMessage,
      close: (code?: number, reason?: string) => {
        if (code === undefined) {
          socket.close()
          return
        }
        if (isValidCloseCode(code)) {
          socket.close(code, reason)
          return
        }
        // Invalid code (e.g. 1006/1008) — drop the code+reason and close
        // with no args rather than throwing. See the doc comment on
        // RelayConnection.close for rationale.
        socket.close()
      },
    }
  } catch (err) {
    // Best-effort close. If the socket isn't open yet the close is a no-op.
    try {
      socket.close()
    } catch {
      // ignore — we're already on the failure path
    }
    throw err
  }
}

// --- internal helpers ---

function waitForOpen(socket: WebSocket, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('aborted', 'AbortError'))
      return
    }
    const cleanup = () => {
      socket.removeEventListener('open', onOpen)
      socket.removeEventListener('error', onError)
      socket.removeEventListener('close', onClose)
      signal?.removeEventListener('abort', onAbort)
    }
    const onOpen = () => {
      cleanup()
      resolve()
    }
    const onError = () => {
      cleanup()
      reject(new Error('socket error before open'))
    }
    const onClose = (event: CloseEvent) => {
      cleanup()
      reject(new RelayClosedError(event.code, event.reason))
    }
    const onAbort = () => {
      cleanup()
      reject(new DOMException('aborted', 'AbortError'))
    }
    socket.addEventListener('open', onOpen, { once: true })
    socket.addEventListener('error', onError, { once: true })
    socket.addEventListener('close', onClose, { once: true })
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

// readNextFrame waits for the next text frame from the socket, applies the
// given parser to it, and returns the parsed result. Times out after
// timeoutMs ms and respects the abort signal. Rejects with WireProtocolError
// for binary frames, malformed JSON, or wrong-type messages.
function readNextFrame<T>(
  socket: WebSocket,
  timeoutMs: number,
  signal: AbortSignal | undefined,
  parse: (frame: string) => T,
): Promise<T> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('aborted', 'AbortError'))
      return
    }
    const timer = setTimeout(() => {
      cleanup()
      reject(new Error(`handshake timed out after ${timeoutMs}ms`))
    }, timeoutMs)
    const cleanup = () => {
      clearTimeout(timer)
      socket.removeEventListener('message', onMessage)
      socket.removeEventListener('error', onError)
      socket.removeEventListener('close', onClose)
      signal?.removeEventListener('abort', onAbort)
    }
    const onMessage = (ev: MessageEvent) => {
      cleanup()
      if (typeof ev.data !== 'string') {
        reject(new WireProtocolError('expected text frame, got binary'))
        return
      }
      try {
        resolve(parse(ev.data))
      } catch (err) {
        reject(err)
      }
    }
    const onError = () => {
      cleanup()
      reject(new Error('socket error during handshake'))
    }
    const onClose = (event: CloseEvent) => {
      cleanup()
      reject(new RelayClosedError(event.code, event.reason))
    }
    const onAbort = () => {
      cleanup()
      reject(new DOMException('aborted', 'AbortError'))
    }
    socket.addEventListener('message', onMessage, { once: true })
    socket.addEventListener('error', onError, { once: true })
    socket.addEventListener('close', onClose, { once: true })
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

// readWelcomeWithBuffer reads the post-Identify welcome frame using a
// single long-lived 'message' listener. The same listener that delivers
// the welcome stays attached and either buffers subsequent frames or fans
// them out to subscribers — eliminating the microtask gap that a
// once: true listener would create between welcome-resolution and
// consumer-attach (the moment when peer-list typically arrives).
//
// The error/close/abort listeners are still once: true and detached as
// soon as welcome resolves. The long-lived message listener is detached
// only when the socket closes (browsers stop dispatching 'message' after
// readyState >= CLOSING, so the leak is bounded; the App can also remove
// it explicitly via the unsubscribe-from-onMessage handle if needed).
function readWelcomeWithBuffer(
  socket: WebSocket,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<{
  welcome: ReturnType<typeof peekWelcomeOrError>
  onMessage: (handler: (data: string) => void) => () => void
}> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('aborted', 'AbortError'))
      return
    }
    // Pre-welcome state: error/close/abort/timeout reject the promise and
    // detach the listeners. Once the welcome arrives, gotWelcome flips and
    // the message listener becomes the long-lived multiplexer.
    let gotWelcome = false
    // Buffered frames received between welcome and the first subscribe.
    // Shifted out in arrival order on first subscribe.
    const buffer: string[] = []
    // Active subscribers. Frames received after welcome fan out to every
    // subscriber in registration order.
    const subscribers: Array<(data: string) => void> = []
    // Flips on the first subscribe; after that, buffering is permanently
    // disabled. If every subscriber later unsubscribes, incoming frames
    // are dropped on the floor rather than silently queueing into a buffer
    // a future re-subscriber would unexpectedly receive.
    let drained = false

    const timer = setTimeout(() => {
      if (gotWelcome) return
      cleanupPreWelcome()
      // Detach the long-lived message listener too — without this a frame
      // arriving after the timeout would still be processed as a welcome
      // (resolving an already-rejected promise — silent) and any later
      // frames would queue forever in a buffer no one can drain.
      socket.removeEventListener('message', onMessage)
      reject(new Error(`handshake timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    const cleanupPreWelcome = () => {
      clearTimeout(timer)
      socket.removeEventListener('error', onError)
      socket.removeEventListener('close', onClose)
      signal?.removeEventListener('abort', onAbort)
    }

    const onMessage = (ev: MessageEvent) => {
      // Binary frames are silently dropped post-welcome (and rejected
      // pre-welcome) — text-only is what the cleartext control protocol
      // uses; binary belongs to a future encrypted-envelope layer.
      if (typeof ev.data !== 'string') {
        if (gotWelcome) return
        cleanupPreWelcome()
        socket.removeEventListener('message', onMessage)
        reject(new WireProtocolError('expected text frame, got binary'))
        return
      }
      if (!gotWelcome) {
        // First frame: must be welcome (or a typed error). On any failure
        // the listener detaches and we reject.
        let parsed: ReturnType<typeof peekWelcomeOrError>
        try {
          parsed = peekWelcomeOrError(ev.data)
        } catch (err) {
          cleanupPreWelcome()
          socket.removeEventListener('message', onMessage)
          reject(err)
          return
        }
        gotWelcome = true
        cleanupPreWelcome()
        // Listener stays attached: from here on it routes to buffer/fanout.
        resolve({ welcome: parsed, onMessage: subscribe })
        return
      }
      // Post-welcome: route the frame.
      if (!drained) {
        // No subscriber has registered yet; queue for the first subscribe.
        buffer.push(ev.data)
        return
      }
      // Snapshot to insulate against subscribers that unsubscribe during
      // dispatch (the unsubscribe filter mutates the array).
      for (const h of subscribers.slice()) h(ev.data)
    }

    const subscribe = (handler: (data: string) => void): (() => void) => {
      // First subscriber drains the buffer synchronously, in arrival
      // order, before any live frame can be dispatched. Subsequent
      // subscribers see only live frames; if every subscriber later
      // unsubscribes, frames are dropped (we never re-engage buffering).
      const isFirst = !drained
      // Track per-handler subscription state so a handler that
      // unsubscribes itself mid-flush stops receiving the rest of the
      // drained frames (and any synchronous fan-out it lands inside).
      let subscribed = true
      const wrapped = (data: string) => {
        if (!subscribed) return
        handler(data)
      }
      subscribers.push(wrapped)
      if (isFirst) {
        drained = true
        // Splice out the buffered frames so a re-entrant onMessage call
        // during dispatch doesn't see them again.
        const queued = buffer.splice(0, buffer.length)
        for (const data of queued) {
          if (!subscribed) break
          handler(data)
        }
      }
      return () => {
        if (!subscribed) return
        subscribed = false
        const idx = subscribers.indexOf(wrapped)
        if (idx >= 0) subscribers.splice(idx, 1)
      }
    }

    const onError = () => {
      if (gotWelcome) return
      cleanupPreWelcome()
      socket.removeEventListener('message', onMessage)
      reject(new Error('socket error during handshake'))
    }
    const onClose = (event: CloseEvent) => {
      if (gotWelcome) return
      cleanupPreWelcome()
      socket.removeEventListener('message', onMessage)
      reject(new RelayClosedError(event.code, event.reason))
    }
    const onAbort = () => {
      if (gotWelcome) return
      cleanupPreWelcome()
      socket.removeEventListener('message', onMessage)
      reject(new DOMException('aborted', 'AbortError'))
    }

    // The message listener is intentionally NOT once: true — it survives
    // the welcome handshake and continues delivering frames.
    socket.addEventListener('message', onMessage)
    socket.addEventListener('error', onError, { once: true })
    socket.addEventListener('close', onClose, { once: true })
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function peekChallenge(frame: string) {
  const t = peekType(frame)
  if (t !== TYPE_CHALLENGE) {
    throw new WireProtocolError(`expected "${TYPE_CHALLENGE}", got "${t ?? '<unparseable>'}"`)
  }
  return parseChallenge(frame)
}

// peekWelcomeOrError dispatches the post-Identify frame to the right typed
// error class. Note: typed-error discrimination depends on the reject
// frame being well-formed. If the relay sends a malformed ErrorMsg (e.g.,
// missing the `code` field), parseError throws WireProtocolError rather
// than RelayRejectedError. That's intentional — a malformed reject frame
// is itself a protocol violation and should surface as such.
function peekWelcomeOrError(frame: string) {
  const t = peekType(frame)
  if (t === TYPE_ERROR) {
    throw new RelayRejectedError(parseError(frame))
  }
  if (t !== TYPE_WELCOME) {
    throw new WireProtocolError(
      `expected "${TYPE_WELCOME}" or "${TYPE_ERROR}", got "${t ?? '<unparseable>'}"`,
    )
  }
  return parseWelcome(frame)
}
