// Pure helpers for negotiated chunk size and windowed flow control.
// Mirrors internal/wireproto/limits.go so vitest can drive the real
// selection logic without React/WebSocket. See AGENTS.md "Flow Control
// & Negotiated Limits".

/** Legacy / floor raw chunk size (64 KiB). Negotiated sizes never go below this. */
export const CHUNK_DATA_SIZE = 64 * 1024

/** Sender preference when both peers and the relay advertise capacity. */
export const PREFERRED_CHUNK_SIZE = 1 << 20 // 1 MiB

/** Relay-advertised max raw chunk (matches Go MaxChunkBytes). */
export const MAX_CHUNK_BYTES = 1 << 20 // 1 MiB

/** Default receiver-advertised window. */
export const DEFAULT_WINDOW_BYTES = 8 << 20 // 8 MiB

/**
 * Stall timeout (ms): windowed sender without ack progress ("flow-control
 * stall"), and receiver without peer progress ("receive stall").
 */
export const STALL_TIMEOUT_MS = 30_000

/** Socket bufferedAmount high-water (pause sending). */
export const BUFFERED_HIGH = 8 << 20 // 8 MiB

/** Socket bufferedAmount low-water (resume sending). */
export const BUFFERED_LOW = 2 << 20 // 2 MiB

/** Transfer UI setState throttle. */
export const UI_UPDATE_MS = 250 // ≤4 Hz

export function floorChunkSize(n: number): number {
  if (!Number.isFinite(n) || n < CHUNK_DATA_SIZE) return CHUNK_DATA_SIZE
  return Math.floor(n)
}

/**
 * Effective raw chunk size for a transfer.
 * Absent ads (0 / undefined) → legacy floor.
 */
export function negotiateChunkSize(
  preference: number,
  relayMax: number,
  acceptMax: number,
): number {
  let eff = preference > 0 ? preference : PREFERRED_CHUNK_SIZE
  const relay = relayMax > 0 ? relayMax : CHUNK_DATA_SIZE
  const accept = acceptMax > 0 ? acceptMax : CHUNK_DATA_SIZE
  if (relay < eff) eff = relay
  if (accept < eff) eff = accept
  return floorChunkSize(eff)
}

/** 0 window = unwindowed. Otherwise ≥ 2× chunk. */
export function effectiveWindow(windowBytes: number, chunkSize: number): number {
  if (windowBytes <= 0) return 0
  const minWin = 2 * chunkSize
  return windowBytes < minWin ? minWin : windowBytes
}

export function ackThreshold(windowBytes: number): number {
  if (windowBytes <= 0) return 0
  return Math.floor(windowBytes / 4)
}

export function inFlight(sent: number, lastAck: number): number {
  return sent < lastAck ? 0 : sent - lastAck
}

export function windowFull(sent: number, lastAck: number, windowBytes: number): boolean {
  if (windowBytes <= 0) return false
  return inFlight(sent, lastAck) >= windowBytes
}

/** True when the receiver should emit a cumulative transfer-ack. */
export function shouldAck(
  received: number,
  lastAcked: number,
  windowBytes: number,
): boolean {
  const th = ackThreshold(windowBytes)
  if (th <= 0) return false
  return received - lastAcked >= th
}

/**
 * Receiver-side ack bookkeeping used by the OPFS receive worker (and
 * mirrorable by main). If `received` has crossed window/4 past `lastAcked`,
 * returns the new cumulative received_bytes to report and the updated
 * lastAcked; otherwise null. Independent of UI progress throttling — acks
 * must fire promptly so the sender window never stalls on a 100ms tick.
 */
export function takeNeedAck(
  received: number,
  lastAcked: number,
  windowBytes: number,
): { receivedBytes: number; lastAcked: number } | null {
  if (!shouldAck(received, lastAcked, windowBytes)) return null
  return { receivedBytes: received, lastAcked: received }
}

/** True when socket.bufferedAmount is at/above the high-water mark. */
export function bufferedAmountHigh(bufferedAmount: number): boolean {
  return bufferedAmount >= BUFFERED_HIGH
}

/** True when bufferedAmount has drained to/below the low-water mark. */
export function bufferedAmountLow(bufferedAmount: number): boolean {
  return bufferedAmount <= BUFFERED_LOW
}

/**
 * EMA rate sample. τ ≈ 3 s: alpha = dt / (τ + dt).
 * Returns bytes/sec.
 */
export function emaRate(
  prevRate: number,
  deltaBytes: number,
  dtMs: number,
  tauMs = 3000,
): number {
  if (dtMs <= 0 || deltaBytes < 0) return prevRate
  const instant = (deltaBytes * 1000) / dtMs
  if (prevRate <= 0) return instant
  const alpha = dtMs / (tauMs + dtMs)
  return prevRate + alpha * (instant - prevRate)
}

/** ETA in seconds from remaining bytes and rate (bytes/sec). null if unknown. */
export function etaSeconds(remainingBytes: number, rateBps: number): number | null {
  if (rateBps <= 0 || remainingBytes <= 0) return null
  return remainingBytes / rateBps
}

export function formatRate(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0) return '—'
  if (bps < 1024) return `${Math.round(bps)} B/s`
  const units = ['KB/s', 'MB/s', 'GB/s']
  let val = bps / 1024
  let i = 0
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024
    i++
  }
  return `${val.toFixed(1)} ${units[i]}`
}

export function formatEta(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds)) return '—'
  if (seconds < 1) return '<1s'
  if (seconds < 60) return `${Math.round(seconds)}s`
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  if (m < 60) return `${m}m ${s}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}
