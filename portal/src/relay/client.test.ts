// Tests for the connection-handshake client. The real wire side (parsers
// and the live relay end-to-end path) is exercised in wire.test.ts and via
// App.tsx; these tests stub WebSocket so we can exercise client.ts's
// control-flow concerns: pre-aborted signals, typed-error dispatch on the
// post-Identify frame, and unexpected-frame handling.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { generateIdentity } from '../crypto/index'
import { RelayClosedError, connectToRelay } from './client'
import {
  ERR_INVALID_SIGNATURE,
  RelayRejectedError,
  TYPE_CHALLENGE,
  TYPE_ERROR,
  TYPE_WELCOME,
  WireProtocolError,
  bytesToBase64,
} from './wire'

// MockEvent is the structural shape that covers every literal we synthesize
// in the fire helpers below: bare `{}` for open/error, `{ data }` for
// message frames, `{ code, reason }` for close. Listeners declared by the
// SUT in terms of MessageEvent / CloseEvent are still assignable to this
// because the SUT wires them up via the real-WebSocket typing on the global
// (vi.stubGlobal preserves that surface); this alias is internal to the
// mock and to its dispatch path.
type MockEvent = { data?: unknown; code?: number; reason?: string }
type MockListener = (ev: MockEvent) => void

// MockWebSocket is a minimal stand-in that supports addEventListener /
// removeEventListener / send / close, plus test-driver helpers to push
// frames and lifecycle events. Behaviour is shaped by the test scenarios
// below — it does NOT try to be a faithful WebSocket emulator.
class MockWebSocket {
  static instances: MockWebSocket[] = []

  // Match real-WebSocket readyState constants (per WHATWG spec).
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSING = 2
  static readonly CLOSED = 3

  readonly url: string
  readyState: number = MockWebSocket.CONNECTING
  binaryType: 'blob' | 'arraybuffer' = 'blob'
  sent: string[] = []
  // Records the arguments passed to the most recent close() call so tests
  // can assert that RelayConnection.close forwarded the right code/reason.
  // [] means close() was invoked with no args.
  lastCloseArgs: [number?, string?] | null = null

  private listeners: Record<string, MockListener[]> = {}

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
  }

  addEventListener(type: string, listener: MockListener): void {
    ;(this.listeners[type] ||= []).push(listener)
  }

  removeEventListener(type: string, listener: MockListener): void {
    const arr = this.listeners[type]
    if (!arr) return
    this.listeners[type] = arr.filter(l => l !== listener)
  }

  send(data: string): void {
    this.sent.push(data)
  }

  close(code?: number, reason?: string): void {
    this.lastCloseArgs = code === undefined ? [] : reason === undefined ? [code] : [code, reason]
    this.readyState = MockWebSocket.CLOSED
  }

  // --- test-driver helpers ---

  fireOpen(): void {
    this.readyState = MockWebSocket.OPEN
    this.dispatch('open', {})
  }

  fireMessage(data: string): void {
    this.dispatch('message', { data })
  }

  fireBinaryMessage(data: ArrayBuffer): void {
    this.dispatch('message', { data })
  }

  fireClose(code = 1006, reason = ''): void {
    this.readyState = MockWebSocket.CLOSED
    this.dispatch('close', { code, reason })
  }

  fireError(): void {
    this.dispatch('error', {})
  }

  // listenerCount lets tests assert that the SUT detached its listeners
  // on terminal paths — guards against listener leaks (e.g. the
  // post-timeout-frame regression covered below).
  listenerCount(type: string): number {
    return (this.listeners[type] || []).length
  }

  private dispatch(type: string, ev: MockEvent): void {
    // Copy first: handlers may remove themselves during iteration.
    const handlers = (this.listeners[type] || []).slice()
    for (const h of handlers) h(ev)
  }
}

afterEach(() => {
  MockWebSocket.instances = []
  vi.unstubAllGlobals()
})

describe('connectToRelay', () => {
  it('rejects synchronously without opening a socket when signal is pre-aborted', async () => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const ac = new AbortController()
    ac.abort()

    await expect(connectToRelay('ws://x', id, { signal: ac.signal })).rejects.toMatchObject({
      name: 'AbortError',
    })
    // Critical: no actual WebSocket constructor invocation.
    expect(MockWebSocket.instances.length).toBe(0)
  })

  it('rejects with RelayRejectedError when relay sends ErrorMsg after challenge', async () => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id)

    // Drive the handshake forward across microtasks: open, then challenge,
    // then error. Each await flushes the microtask queue so the client's
    // promise-chained listeners are wired up before we fire the next
    // event.
    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_ERROR,
        code: ERR_INVALID_SIGNATURE,
        message: 'no good',
      }),
    )

    await expect(promise).rejects.toBeInstanceOf(RelayRejectedError)
    await expect(promise).rejects.toMatchObject({ code: ERR_INVALID_SIGNATURE })
  })

  it('rejects with WireProtocolError on an unexpected frame type after challenge', async () => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id)

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    await flushMicrotasks()
    // Send something that isn't welcome OR error.
    ws.fireMessage(JSON.stringify({ type: TYPE_CHALLENGE, nonce: 'AA==' }))

    await expect(promise).rejects.toBeInstanceOf(WireProtocolError)
  })

  it('honours a late abort fired between challenge-receive and identify-send', async () => {
    // Covers the abort re-check in client.ts after the challenge-read
    // resolves. Without it a late abort would still synchronously transmit
    // the identify bytes.
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const ac = new AbortController()
    const promise = connectToRelay('ws://x', id, { signal: ac.signal })

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    // Abort BEFORE the challenge-handler microtask runs — the handler has
    // already fired synchronously inside fireMessage above, so the
    // post-await abort re-check in client.ts is what catches us.
    ac.abort()

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' })
    // Identify should never have been sent.
    expect(ws.sent.length).toBe(0)
  })

  it('rejects with handshake-timeout when no message arrives in time', async () => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id, { timeoutMs: 1 })

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    // Don't send any message — the timeout should fire.

    await expect(promise).rejects.toThrow(/handshake timed out/)
  })

  it('rejects with WireProtocolError when the relay sends a binary frame', async () => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id)

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireBinaryMessage(new ArrayBuffer(8))

    await expect(promise).rejects.toBeInstanceOf(WireProtocolError)
    await expect(promise).rejects.toThrow(/expected text frame, got binary/)
  })

  it('rejects with RelayClosedError carrying code+reason when the socket closes mid-handshake', async () => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id)

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    await flushMicrotasks()
    // Simulate the relay displacing a stale duplicate during the
    // handshake window — the close-code surface must be preserved so the
    // App layer can render the same friendly UI it does post-handshake.
    ws.fireClose(1008, 'replaced by newer connection')

    await expect(promise).rejects.toBeInstanceOf(RelayClosedError)
    await expect(promise).rejects.toMatchObject({
      code: 1008,
      reason: 'replaced by newer connection',
    })
  })

  it('rejects with socket-error when the WebSocket fires `error` mid-handshake', async () => {
    // Covers the readNextFrame onError branch — distinct from the close
    // branch above. We get past challenge-receive (so we're in the
    // welcome-read) and then synthesize an `error` event.
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id)

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    await flushMicrotasks()
    ws.fireError()

    await expect(promise).rejects.toThrow(/socket error during handshake/)
  })

  it('forwards code and reason through RelayConnection.close for a valid 1000 close', async () => {
    const conn = await drainHandshake()
    const ws = MockWebSocket.instances[0]

    conn.close(1000, 'bye')

    expect(ws.lastCloseArgs).toEqual([1000, 'bye'])
  })

  it('silently drops an invalid close code (e.g. 1008) and falls back to no-arg close', async () => {
    // Callers will commonly want to forward the relay's own observed
    // close code straight back; 1008 is not a legal code for the
    // close()-arg side and would otherwise throw. We expect a silent
    // fall-through to socket.close() with no args.
    const conn = await drainHandshake()
    const ws = MockWebSocket.instances[0]

    expect(() => conn.close(1008, 'replaced')).not.toThrow()
    expect(ws.lastCloseArgs).toEqual([])
  })

  it('does not leave a dangling message listener after a handshake timeout', async () => {
    // Regression: previously the timeout path detached error/close/abort
    // listeners but left the long-lived message listener attached. A
    // post-timeout frame would then be parsed as the welcome and the
    // resolve call would silently no-op against the already-rejected
    // promise — leaking subscribers/buffer state for the socket lifetime.
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id, { timeoutMs: 1 })

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    expect(ws).toBeDefined()
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    // Don't send a welcome — the welcome-read times out.
    await expect(promise).rejects.toThrow(/handshake timed out/)

    // After the rejection, no message listener should remain — a late
    // welcome frame must NOT be processed.
    expect(ws.listenerCount('message')).toBe(0)
  })
})

describe('RelayConnection.onMessage', () => {
  it('delivers frames buffered between welcome and the first subscribe', async () => {
    // Drive the handshake but synthesize a peer-list frame in the same
    // synchronous tick as welcome — that's the race the buffer exists for.
    vi.stubGlobal('WebSocket', MockWebSocket)
    const id = generateIdentity()
    const promise = connectToRelay('ws://x', id)

    await flushMicrotasks()
    const ws = MockWebSocket.instances[0]
    ws.fireOpen()
    await flushMicrotasks()
    ws.fireMessage(
      JSON.stringify({
        type: TYPE_CHALLENGE,
        nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
      }),
    )
    await flushMicrotasks()
    ws.fireMessage(welcomeFrame(id))
    // Synchronously fire two more frames before the consumer subscribes —
    // these go into the buffer.
    ws.fireMessage('{"type":"peer-list","peers":[]}')
    ws.fireMessage('{"type":"peer-joined","peer":{}}')

    const conn = await promise
    const seen: string[] = []
    conn.onMessage((data) => seen.push(data))

    expect(seen).toEqual([
      '{"type":"peer-list","peers":[]}',
      '{"type":"peer-joined","peer":{}}',
    ])
  })

  it('does not re-buffer frames after every subscriber unsubscribes', async () => {
    // After the first subscribe, buffering is permanently disabled. If
    // the lone subscriber unsubscribes and a frame arrives, it must be
    // dropped — otherwise a future re-subscriber would silently receive
    // queued frames it didn't ask for.
    const conn = await drainHandshake()
    const ws = MockWebSocket.instances[0]

    const seen1: string[] = []
    const unsub = conn.onMessage((d) => seen1.push(d))
    unsub()
    ws.fireMessage('{"type":"peer-left","ed25519_pub":"AA=="}')

    const seen2: string[] = []
    conn.onMessage((d) => seen2.push(d))
    expect(seen1).toEqual([])
    expect(seen2).toEqual([])

    // Live frames after the second subscribe are delivered as normal.
    ws.fireMessage('{"type":"peer-joined","peer":{}}')
    expect(seen2).toEqual(['{"type":"peer-joined","peer":{}}'])
  })

  it('fans out live frames to multiple concurrent subscribers in registration order', async () => {
    const conn = await drainHandshake()
    const ws = MockWebSocket.instances[0]

    const order: string[] = []
    conn.onMessage(() => order.push('a'))
    conn.onMessage(() => order.push('b'))
    ws.fireMessage('{"type":"peer-joined","peer":{}}')

    expect(order).toEqual(['a', 'b'])
  })

  it('stops delivering live frames to a handler that unsubscribes itself during fan-out', async () => {
    // Two subscribers; the first unsubscribes itself when invoked. The
    // second must still receive the same frame (snapshot semantics
    // protect ongoing fan-out). The first handler must not receive any
    // subsequent live frame.
    const conn = await drainHandshake()
    const ws = MockWebSocket.instances[0]

    const seenA: string[] = []
    const seenB: string[] = []
    const holder: { unsub: (() => void) | null } = { unsub: null }
    holder.unsub = conn.onMessage((data) => {
      seenA.push(data)
      holder.unsub?.()
    })
    conn.onMessage((data) => seenB.push(data))

    ws.fireMessage('{"type":"peer-joined","peer":{}}')
    ws.fireMessage('{"type":"peer-left","ed25519_pub":"AA=="}')

    // First handler saw only the first live frame, then unsubscribed.
    expect(seenA).toEqual(['{"type":"peer-joined","peer":{}}'])
    // Second handler saw both live frames (mid-fan-out unsubscribe of A
    // doesn't disturb B's delivery).
    expect(seenB).toEqual([
      '{"type":"peer-joined","peer":{}}',
      '{"type":"peer-left","ed25519_pub":"AA=="}',
    ])
  })
})

// drainHandshake spins up connectToRelay against a fresh MockWebSocket
// and drives it through challenge → welcome so tests focused on
// post-handshake behaviour (close forwarding, etc.) don't repeat the
// boilerplate. The mock instance is at MockWebSocket.instances[0].
async function drainHandshake() {
  vi.stubGlobal('WebSocket', MockWebSocket)
  const id = generateIdentity()
  const promise = connectToRelay('ws://x', id)
  await flushMicrotasks()
  const ws = MockWebSocket.instances[0]
  ws.fireOpen()
  await flushMicrotasks()
  ws.fireMessage(
    JSON.stringify({
      type: TYPE_CHALLENGE,
      nonce: bytesToBase64(new Uint8Array(32).fill(0x42)),
    }),
  )
  await flushMicrotasks()
  // Synthesize a minimal welcome frame. The shape mirrors what the Go
  // relay sends and what wire.parseWelcome accepts. The sig_binding bytes
  // are arbitrary — parseWelcome only requires them to decode as base64.
  ws.fireMessage(
    JSON.stringify({
      type: TYPE_WELCOME,
      you: {
        ed25519_pub: bytesToBase64(id.ed25519Pub),
        x25519_pub: bytesToBase64(id.x25519Pub),
        sig_binding: bytesToBase64(new Uint8Array(64)),
        ip: '127.0.0.1',
        port: 12345,
      },
    }),
  )
  return await promise
}

// flushMicrotasks yields long enough for any chain of resolved promises
// queued by the SUT to drain. Two awaits empirically suffices for the
// listener-attach pattern used in client.ts (waitForOpen → readNextFrame →
// readNextFrame).
async function flushMicrotasks(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
}

// welcomeFrame builds a minimal valid welcome JSON for the given identity.
// Used by the buffering tests that need to fire welcome and follow-up
// frames in the same synchronous tick.
function welcomeFrame(id: { ed25519Pub: Uint8Array; x25519Pub: Uint8Array }): string {
  return JSON.stringify({
    type: TYPE_WELCOME,
    you: {
      ed25519_pub: bytesToBase64(id.ed25519Pub),
      x25519_pub: bytesToBase64(id.x25519Pub),
      sig_binding: bytesToBase64(new Uint8Array(64)),
      ip: '127.0.0.1',
      port: 12345,
    },
  })
}
