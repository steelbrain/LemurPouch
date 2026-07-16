import { describe, expect, it } from 'vitest'

import {
  CHUNK_DATA_SIZE,
  DEFAULT_WINDOW_BYTES,
  PREFERRED_CHUNK_SIZE,
  ackThreshold,
  bufferedAmountHigh,
  bufferedAmountLow,
  effectiveWindow,
  emaRate,
  etaSeconds,
  floorChunkSize,
  formatEta,
  formatRate,
  negotiateChunkSize,
  shouldAck,
  takeNeedAck,
  windowFull,
} from './negotiate'

describe('floorChunkSize', () => {
  it('floors sub-64Ki ads to 64 KiB', () => {
    expect(floorChunkSize(0)).toBe(CHUNK_DATA_SIZE)
    expect(floorChunkSize(1000)).toBe(CHUNK_DATA_SIZE)
    expect(floorChunkSize(65535)).toBe(CHUNK_DATA_SIZE)
  })
  it('passes through values at/above the floor', () => {
    expect(floorChunkSize(CHUNK_DATA_SIZE)).toBe(CHUNK_DATA_SIZE)
    expect(floorChunkSize(PREFERRED_CHUNK_SIZE)).toBe(PREFERRED_CHUNK_SIZE)
  })
})

describe('negotiateChunkSize', () => {
  it('new↔new with full ads → preferred', () => {
    expect(
      negotiateChunkSize(PREFERRED_CHUNK_SIZE, PREFERRED_CHUNK_SIZE, PREFERRED_CHUNK_SIZE),
    ).toBe(PREFERRED_CHUNK_SIZE)
  })
  it('absent ads → legacy 64 KiB (old accept / old relay)', () => {
    expect(negotiateChunkSize(PREFERRED_CHUNK_SIZE, 0, 0)).toBe(CHUNK_DATA_SIZE)
  })
  it('advertised < 65536 treated as 65536', () => {
    expect(negotiateChunkSize(PREFERRED_CHUNK_SIZE, 1000, PREFERRED_CHUNK_SIZE)).toBe(
      CHUNK_DATA_SIZE,
    )
  })
  it('takes the min of preference, relay, accept', () => {
    expect(negotiateChunkSize(PREFERRED_CHUNK_SIZE, 256 * 1024, PREFERRED_CHUNK_SIZE)).toBe(
      256 * 1024,
    )
  })
})

describe('effectiveWindow / windowFull / shouldAck', () => {
  it('zero window is unwindowed (old accept)', () => {
    expect(effectiveWindow(0, PREFERRED_CHUNK_SIZE)).toBe(0)
    expect(windowFull(1e9, 0, 0)).toBe(false)
    expect(shouldAck(1e9, 0, 0)).toBe(false)
  })
  it('raises window to 2× chunk', () => {
    expect(effectiveWindow(PREFERRED_CHUNK_SIZE, PREFERRED_CHUNK_SIZE)).toBe(
      2 * PREFERRED_CHUNK_SIZE,
    )
  })
  it('blocks at window and acks every window/4', () => {
    const win = DEFAULT_WINDOW_BYTES
    expect(windowFull(win, 0, win)).toBe(true)
    expect(windowFull(win - 1, 0, win)).toBe(false)
    expect(shouldAck(win / 4, 0, win)).toBe(true)
    expect(shouldAck(win / 4 - 1, 0, win)).toBe(false)
  })
})

describe('bufferedAmount pacing', () => {
  it('high/low water marks', () => {
    expect(bufferedAmountHigh(8 << 20)).toBe(true)
    expect(bufferedAmountHigh((8 << 20) - 1)).toBe(false)
    expect(bufferedAmountLow(2 << 20)).toBe(true)
    expect(bufferedAmountLow((2 << 20) + 1)).toBe(false)
  })
})

describe('emaRate / eta / format', () => {
  it('seeds from first sample then smooths', () => {
    const r0 = emaRate(0, 1_000_000, 1000)
    expect(r0).toBe(1_000_000)
    const r1 = emaRate(r0, 0, 1000)
    expect(r1).toBeLessThan(r0)
  })
  it('eta and format helpers', () => {
    expect(etaSeconds(10_000_000, 1_000_000)).toBe(10)
    expect(etaSeconds(10, 0)).toBeNull()
    expect(formatRate(1_500_000)).toMatch(/MB\/s/)
    expect(formatEta(90)).toMatch(/1m/)
  })
})

describe('takeNeedAck (OPFS worker ack cadence)', () => {
  it('fires at every window/4 independent of a 100ms UI throttle', () => {
    // Simulate the receiveWorker loop: 1 MiB chunks at 1 ms each (far
    // faster than the 100 ms UI progress throttle). needAck must still
    // fire every window/4 so the sender never waits on a progress tick.
    const window = DEFAULT_WINDOW_BYTES
    const thr = ackThreshold(window)
    expect(thr).toBe(window / 4)

    let lastAcked = 0
    let lastProgressAt = -Infinity
    let needAcks = 0
    let progressPosts = 0
    let received = 0
    const chunk = PREFERRED_CHUNK_SIZE
    // Stream two full windows' worth of bytes.
    const target = window * 2
    for (let t = 0; received < target; t += 1) {
      received = Math.min(received + chunk, target)
      const need = takeNeedAck(received, lastAcked, window)
      if (need) {
        lastAcked = need.lastAcked
        needAcks++
      }
      if (t - lastProgressAt >= 100) {
        lastProgressAt = t
        progressPosts++
      }
    }
    // Exact: each needAck advances lastAcked by ≥ thr; over 2×window we
    // get floor(2×window / thr) = 8 needAcks when chunks land on boundaries.
    expect(needAcks).toBe(8)
    // UI progress at 100ms with 1ms/chunk ⇒ only a few posts over ~16 chunks.
    expect(progressPosts).toBeLessThan(needAcks)
    // Critical: acks are NOT gated by the progress cadence.
    expect(needAcks).toBeGreaterThan(0)
  })

  it('returns null when unwindowed (legacy accept)', () => {
    expect(takeNeedAck(1_000_000, 0, 0)).toBeNull()
  })
})
