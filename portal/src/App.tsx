import { useCallback, useEffect, useRef, useState } from 'react'

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'

import { fingerprint, generateIdentity, verifyBinding, type Identity } from './crypto/index'
import {
  ENVELOPE_PEER_KEY_LEN,
  INNER_TYPE_FILE_CHUNK,
  INNER_TYPE_JSON_CONTROL,
} from './crypto/envelope'
import {
  RelayRejectedError,
  TYPE_ACCEPT_FROM,
  TYPE_INVITE_AUTO_REJECTED,
  TYPE_INVITE_DEFERRED,
  TYPE_INVITE_FROM,
  TYPE_PEER_JOINED,
  TYPE_PEER_LEFT,
  TYPE_PEER_LIST,
  TYPE_REJECT_FROM,
  WireProtocolError,
  buildAcceptMsg,
  buildInviteMsg,
  buildRejectMsg,
  parseDiscovery,
  parseFriendshipNotification,
  type PeerRecord,
} from './relay/wire'
import { RelayClosedError, connectToRelay, type RelayConnection } from './relay/client'
import { CHUNK_FLAG_LAST, buildChunk, parseChunk } from './transfer/chunk'
import {
  TRANSFER_ID_LEN,
  TYPE_TRANSFER_ACCEPT,
  TYPE_TRANSFER_ACK,
  TYPE_TRANSFER_END,
  TYPE_TRANSFER_OFFER,
  TYPE_TRANSFER_REJECT,
  buildTransferAccept,
  buildTransferAck,
  buildTransferEnd,
  buildTransferOffer,
  buildTransferReject,
  parseTransferControl,
} from './transfer/control'
import {
  EnvelopeMessenger,
  type IncomingEnvelope,
} from './transfer/messenger'
import {
  DEFAULT_WINDOW_BYTES,
  MAX_CHUNK_BYTES,
  PREFERRED_CHUNK_SIZE,
  STALL_TIMEOUT_MS,
  UI_UPDATE_MS,
  bufferedAmountHigh,
  bufferedAmountLow,
  effectiveWindow,
  emaRate,
  etaSeconds,
  formatEta,
  formatRate,
  negotiateChunkSize,
  shouldAck,
  windowFull,
} from './transfer/negotiate'
import {
  type InboundAssembler,
  type InboundTransfer,
  type OutboundTransfer,
  acceptChunk,
  assemblerBlob,
  finalizeBlobUrl,
  formatBytes,
  inboundVerdict,
  markOutboundStreaming,
  newInboundAssembler,
} from './transfer/state'

/**
 * Disk-backed receive (OPFS) needs a secure context. Chrome/Firefox/Safari
 * only expose navigator.storage.getDirectory on https:// or
 * http://localhost / http://127.0.0.1 — NOT on plain http://LAN-IP, which
 * is how LemurPouch is normally opened on a LAN. Sync access handles are
 * additionally worker-only in Safari; we open those inside the receive
 * worker after this gate passes.
 */
function diskReceiveAvailable(): boolean {
  try {
    if (typeof window === 'undefined' || !window.isSecureContext) return false
    return typeof navigator.storage?.getDirectory === 'function'
  } catch {
    return false
  }
}

function diskReceiveBlockedReason(): string {
  if (typeof window !== 'undefined' && !window.isSecureContext) {
    return (
      'Browsers only allow on-disk receives (OPFS) in a secure context ' +
      '(https:// or http://localhost). This page is plain http:// on a LAN ' +
      'IP, so large files cannot be stored on disk here. Use the LemurPouch ' +
      'TUI client (`LemurPouch --connect <relay-url>`) for multi-GB transfers, ' +
      'or open the portal via https:// / localhost for smaller on-disk receives.'
    )
  }
  return (
    'On-disk browser storage (OPFS) is unavailable in this environment. ' +
    'Use the LemurPouch TUI client (`LemurPouch --connect <relay-url>`) ' +
    'for multi-GB transfers.'
  )
}

const OPFS_OK = diskReceiveAvailable()
/** Soft UI warning when falling back to RAM (≥ this size). */
const MEMORY_WARN_BYTES = 512 * 1024 * 1024

type State =
  | { kind: 'connecting' }
  | { kind: 'connected'; you: PeerRecord; identity: Identity }
  | { kind: 'closed'; code: number; reason: string }
  | { kind: 'error'; message: string }

// Per the WebSocket spec / Go relay implementation:
//   1000 — normal closure
//   1001 — going away (peer left; tab closing, server shutting down)
//   1006 — abnormal (no close frame; e.g. network drop)
//   1008 — policy violation; the Go relay uses this to displace a stale
//          duplicate connection of the same identity (reason "replaced by
//          newer connection"). See internal/relay/relay.go.
const CLOSE_NORMAL = 1000
const CLOSE_GOING_AWAY = 1001
const CLOSE_ABNORMAL = 1006
const CLOSE_POLICY_VIOLATION = 1008

// Notification is a transient banner surfaced to the user when the relay
// reports a friendship-side event that's not directly user-driven (an
// originator getting their accept/reject relayed back, or a deferred /
// auto-rejected signal). Stored as plain serializable data so the renderer
// can lookup peers by ed25519_pub at display time.
interface FriendshipNotice {
  // Monotonically incremented per session so React keys are stable even
  // if multiple notifications arrive for the same peer.
  id: number
  kind:
    | typeof TYPE_ACCEPT_FROM
    | typeof TYPE_REJECT_FROM
    | typeof TYPE_INVITE_DEFERRED
    | typeof TYPE_INVITE_AUTO_REJECTED
  // hex(ed25519_pub) of the peer the notification is *about*.
  peerHex: string
}

let nextNoticeId = 1

// Soft cap on the on-screen notice queue. Each friendship signal is
// one-shot per pair under normal relay behavior, so the queue rarely
// grows large — the cap is purely defensive (a misbehaving or buggy
// relay can't pin the page open with an unbounded array). Oldest
// notices are dropped first so the most recent (and actionable) ones
// stay visible.
const MAX_NOTICES = 50

export default function App() {
  const [state, setState] = useState<State>({ kind: 'connecting' })
  // peers tracks every other connected peer the relay has told us about —
  // populated from the peer-list pushed right after welcome, then kept in
  // sync via peer-joined / peer-left broadcasts (AGENTS.md "Discovery").
  const [peers, setPeers] = useState<PeerRecord[]>([])
  // invitesIn / invitesOut / friends are session-scoped friendship state —
  // the Go relay's FriendshipManager owns the authoritative copy
  // (AGENTS.md "Consent Model"); we mirror it locally as hex(ed25519_pub)
  // strings so React state diffs stay cheap and dedupe is just .includes().
  const [invitesIn, setInvitesIn] = useState<string[]>([])
  const [invitesOut, setInvitesOut] = useState<string[]>([])
  const [friends, setFriends] = useState<string[]>([])
  const [notices, setNotices] = useState<FriendshipNotice[]>([])
  // outbound / inbound track in-flight + completed transfers. Keyed by
  // hex(transfer_id) (16-byte id rendered as 32-char hex). Status
  // transitions: outbound 'awaiting-decision' -> 'streaming' -> 'done'
  // (or '-> 'rejected' / 'aborted'); inbound 'offered' -> 'streaming'
  // -> 'done' (or '-> 'rejected' / 'aborted').
  const [outbound, setOutbound] = useState<Record<string, OutboundTransfer>>({})
  const [inbound, setInbound] = useState<Record<string, InboundTransfer>>({})

  // Refs that mirror live state for the long-lived `onMessage` /
  // `onEnvelope` closures (created once per useEffect run) so they
  // can synchronously read state without stale captures or chained
  // functional setters.
  //   - friendsRef: invite-from de-dup against established friends.
  //   - peersRef: registerFriend lookup needs the X25519 key from
  //     the peer's discovery record at the moment friendship is
  //     established (in sendAccept and the accept-from handler).
  //   - connRef: send handlers reach the WebSocket without going
  //     through React state.
  //   - messengerRef: same, for envelope sends + friend registry.
  //   - outboundRef: the chunk-streaming async loop reads it each
  //     iteration so an aborted-during-send transfer breaks out
  //     promptly instead of streaming all chunks past abort.
  //   - inboundRef: click handlers (accept / reject) read it
  //     synchronously so they can do the wire send OUTSIDE the
  //     setInbound updater (updaters must be pure; React may
  //     invoke them more than once per logical update under
  //     StrictMode and concurrent rendering).
  const friendsRef = useRef<string[]>([])
  const peersRef = useRef<PeerRecord[]>([])
  const connRef = useRef<RelayConnection | null>(null)
  const messengerRef = useRef<EnvelopeMessenger | null>(null)
  const outboundRef = useRef<Record<string, OutboundTransfer>>({})
  const inboundRef = useRef<Record<string, InboundTransfer>>({})
  // Per-inbound-transfer mutable accumulators (preallocated buffer +
  // running SHA-256 + reorder bookkeeping), keyed by transferIdHex. Held
  // OUTSIDE React state because the hasher is stateful and must be driven
  // exactly once per frame from the chunk event handler, never from a
  // (possibly double-invoked) setInbound updater. Allocated on accept,
  // dropped on done / abort / reject / dismiss / peer-left.
  const inboundDataRef = useRef<Map<string, InboundAssembler>>(new Map())
  // Relay-advertised max chunk (0 = legacy floor). Set from welcome.limits.
  const relayMaxChunkRef = useRef(0)
  // Window waiters: transferIdHex → wake (resolves waitForWindow).
  const ackWaitersRef = useRef(new Map<string, () => void>())
  // Inbound ack bookkeeping for windowed receives.
  const inboundAckRef = useRef(new Map<string, { window: number; lastAcked: number }>())
  // Receive-stall timers: abort inbound streaming if the peer stops
  // making progress (no chunk / transfer-end) for STALL_TIMEOUT_MS.
  const inboundIdleTimersRef = useRef(new Map<string, ReturnType<typeof setTimeout>>())
  // UI throttle + rate EMA per transfer id.
  const uiThrottleRef = useRef(
    new Map<string, { lastAt: number; lastBytes: number; rate: number }>(),
  )
  const receiveWorkerRef = useRef<Worker | null>(null)
  // Set of hex(ed25519_pub) for peers we've observed a peer-left for.
  // Friendship notifications and peer-left broadcasts are dispatched
  // from independent goroutines on the relay (writeAsyncToIdentity vs
  // broadcastExcept), so a stale invite-from / accept-from can land
  // AFTER peer-left has cleared the relay's pair-state. We use this
  // set to drop those — but ONLY those: invite-from before peer-joined
  // (no peer-left yet) is still accepted, preserving the "(peer not
  // in directory)" UI fallback. Cleared on peer-joined (reconnect of
  // same identity re-enables notifications).
  const seenLeftRef = useRef<Set<string>>(new Set())

  const clearInboundIdle = useCallback((transferIdHex: string) => {
    const t = inboundIdleTimersRef.current.get(transferIdHex)
    if (t !== undefined) {
      clearTimeout(t)
      inboundIdleTimersRef.current.delete(transferIdHex)
    }
  }, [])

  // Tear down a streaming inbound on receive-stall (or shared abort path).
  const abortInboundStreaming = useCallback(
    (transferIdHex: string, reason: string) => {
      clearInboundIdle(transferIdHex)
      inboundDataRef.current.delete(transferIdHex)
      inboundAckRef.current.delete(transferIdHex)
      try {
        receiveWorkerRef.current?.postMessage({ type: 'abort', transferIdHex })
      } catch {
        /* worker may already be gone */
      }
      setInbound((prev) => {
        const c2 = prev[transferIdHex]
        if (!c2 || c2.status !== 'streaming') return prev
        return {
          ...prev,
          [transferIdHex]: { ...c2, status: 'aborted', rejectReason: reason },
        }
      })
      // Keep inboundRef in sync immediately (handlers read it).
      const cur = inboundRef.current[transferIdHex]
      if (cur && cur.status === 'streaming') {
        inboundRef.current = {
          ...inboundRef.current,
          [transferIdHex]: { ...cur, status: 'aborted', rejectReason: reason },
        }
      }
    },
    [clearInboundIdle],
  )

  const armInboundIdle = useCallback(
    (transferIdHex: string) => {
      clearInboundIdle(transferIdHex)
      const t = setTimeout(() => {
        inboundIdleTimersRef.current.delete(transferIdHex)
        const cur = inboundRef.current[transferIdHex]
        if (!cur || cur.status !== 'streaming') return
        abortInboundStreaming(transferIdHex, 'receive stall')
      }, STALL_TIMEOUT_MS)
      inboundIdleTimersRef.current.set(transferIdHex, t)
    },
    [abortInboundStreaming, clearInboundIdle],
  )
  // Connection effect is mount-once; keep latest idle helpers via refs.
  const armInboundIdleRef = useRef(armInboundIdle)
  const clearInboundIdleRef = useRef(clearInboundIdle)
  const abortInboundStreamingRef = useRef(abortInboundStreaming)
  armInboundIdleRef.current = armInboundIdle
  clearInboundIdleRef.current = clearInboundIdle
  abortInboundStreamingRef.current = abortInboundStreaming

  // Keep peersRef, outboundRef, and inboundRef in sync with React
  // state. Done in a separate effect (not inline at every setState
  // site) to avoid missing updates on a future setState path.
  useEffect(() => {
    peersRef.current = peers
  }, [peers])
  useEffect(() => {
    // The send loop mutates outboundRef for lastAck (transfer-ack) and
    // sentBytes between React paints. A wholesale replace would drop a
    // just-applied ack → window looks full with lastAck=0 → sender stops
    // → receiver never crosses the next ack threshold → flow-control stall.
    const prev = outboundRef.current
    const next: Record<string, OutboundTransfer> = { ...outbound }
    for (const id of Object.keys(next)) {
      const t = next[id]!
      const live = prev[id]
      if (!live || live.status !== 'streaming' || t.status !== 'streaming') continue
      next[id] = {
        ...t,
        lastAck: Math.max(t.lastAck ?? 0, live.lastAck ?? 0),
        sentBytes: Math.max(t.sentBytes, live.sentBytes),
      }
    }
    outboundRef.current = next
  }, [outbound])
  useEffect(() => {
    inboundRef.current = inbound
  }, [inbound])

  // Post-commit finalization for inbound transfers that just assembled.
  // The chunk / transfer-end handlers stage assembledBytes/assembledBlob
  // and flip status to 'done', but do NOT create the object URL — that
  // side effect lives here, after the React commit.
  useEffect(() => {
    const finalized: Array<{ key: string; updated: InboundTransfer }> = []
    for (const [k, t] of Object.entries(inbound)) {
      if (
        t.status === 'done' &&
        !t.blobUrl &&
        (t.assembledBytes || t.assembledBlob)
      ) {
        finalized.push({ key: k, updated: finalizeBlobUrl(t) })
      }
    }
    if (finalized.length === 0) return
    // The set-state-in-effect rule discourages deriving state from
    // state, but here the effect is materializing an external resource
    // (a Blob + object URL) that lives in browser memory outside React.
    // The URL handle has to be stored alongside the transfer so the
    // download <a> can reference it and so cleanup paths can revoke it
    // — derived render-time computation isn't an option (createObjectURL
    // is a side effect that allocates a kept resource). Cascading
    // renders are bounded: each affected transfer transitions exactly
    // once from "assembled, no URL" to "URL minted", and on the next
    // run of this effect the !t.blobUrl gate skips it.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setInbound((prev) => {
      let modified = false
      const next = { ...prev }
      for (const { key, updated } of finalized) {
        const cur = prev[key]
        // The entry may have been dismissed (deleted) or otherwise
        // mutated between this effect computing `finalized` and the
        // updater running. If the slot no longer matches, skip — the
        // URL we minted leaks until page-close, but the window is
        // microseconds and only opens on a user dismissing a transfer
        // the same tick it finishes assembling.
        if (
          !cur ||
          cur.status !== 'done' ||
          cur.blobUrl ||
          (!cur.assembledBytes && !cur.assembledBlob)
        ) {
          continue
        }
        next[key] = updated
        modified = true
      }
      return modified ? next : prev
    })
  }, [inbound])

  useEffect(() => {
    let conn: RelayConnection | null = null
    let messenger: EnvelopeMessenger | null = null
    // The cancelled flag also handles React StrictMode's intentional
    // mount → unmount → remount replay in development: the first run's
    // cleanup sets cancelled=true, so its in-flight handshake resolution
    // becomes a no-op and the second run starts fresh.
    let cancelled = false
    let unsubscribeMessage: (() => void) | null = null
    let unsubscribeEnvelope: (() => void) | null = null
    const ac = new AbortController()
    // Capture the assembler Map instance for the cleanup below. The ref's
    // `.current` is a single Map created once via useRef and never
    // reassigned (we only mutate its entries), so this is the same
    // instance the chunk handlers use — capturing it here just satisfies
    // the exhaustive-deps "ref may have changed by cleanup" lint.
    const inboundData = inboundDataRef.current
    const inboundIdleTimers = inboundIdleTimersRef.current
    // Captured here so the cleanup function can unregister the same
    // function references we attached.
    const onClose = (event: CloseEvent) => {
      if (!cancelled) setState({ kind: 'closed', code: event.code, reason: event.reason })
    }
    const onMessage = (data: string) => {
      if (cancelled) return
      try {
        const dmsg = parseDiscovery(data)
        if (dmsg !== null) {
          switch (dmsg.type) {
            case TYPE_PEER_LIST:
              // peer-list arrives once right after welcome — replace
              // state wholesale so a reconnect that re-sends peer-list
              // correctly resets any stale entries. Verify each peer's
              // sig_binding locally before trusting their X25519 key
              // (AGENTS.md "Transfer Flow" step 3): without this, a
              // compromised relay could swap in its own X25519 while
              // keeping the legitimate Ed25519 fingerprint and MITM the
              // session keys. De-dup defensively in case the relay ever
              // ships an entry twice; React would otherwise warn about
              // duplicate keys.
              setPeers(dedupPeers(dmsg.peers.filter(isPeerBindingValid)))
              break
            case TYPE_PEER_JOINED: {
              if (!isPeerBindingValid(dmsg.peer)) break
              const joinedHex = bytesToHex(dmsg.peer.ed25519Pub)
              // Reconnect of a same-key peer re-enables friendship
              // notifications for them; clear the seen-left memo.
              seenLeftRef.current.delete(joinedHex)
              setPeers((prev) => upsertPeer(prev, dmsg.peer))
              // If accept-from arrived BEFORE this peer-joined (rare
              // out-of-order delivery — the relay broadcasts join and
              // forwards friendship notifications from independent
              // goroutines), the friendship was recorded in friendsRef
              // without a session-key derivation. Catch up here so
              // inbound encrypted traffic actually decrypts; without
              // this, the friendship would be permanently broken until
              // the peer reconnects again. Re-derivation can throw on
              // a low-order X25519 — drop the friendship in that case.
              if (
                friendsRef.current.includes(joinedHex) &&
                messenger &&
                !messenger.hasFriend(dmsg.peer.ed25519Pub)
              ) {
                try {
                  messenger.registerFriend(dmsg.peer)
                } catch (err) {
                  console.warn(
                    'peer-joined: deferred session-key derivation failed for',
                    joinedHex.slice(0, 16),
                    '— dropping friendship',
                    err,
                  )
                  friendsRef.current = friendsRef.current.filter((h) => h !== joinedHex)
                  setFriends(friendsRef.current)
                }
              }
              break
            }
            case TYPE_PEER_LEFT: {
              const goneHex = bytesToHex(dmsg.ed25519Pub)
              // Memo the departure so a stale friendship notification
              // arriving after this peer-left is dropped — see
              // seenLeftRef declaration.
              seenLeftRef.current.add(goneHex)
              const goneEd = dmsg.ed25519Pub
              setPeers((prev) =>
                prev.filter((p) => !bytesEqual(p.ed25519Pub, goneEd)),
              )
              // Cleanup friendship state for the departing peer —
              // AGENTS.md "Session Lifetime": a disconnect drops the
              // relay-side friendship + pair state, so the client
              // should drop its mirror to avoid stale-button bugs (e.g.
              // a "Friend" badge for someone whose connection is gone).
              setInvitesIn((prev) => prev.filter((h) => h !== goneHex))
              setInvitesOut((prev) => prev.filter((h) => h !== goneHex))
              friendsRef.current = friendsRef.current.filter((h) => h !== goneHex)
              setFriends(friendsRef.current)
              // Evict cached session keys + abort any in-flight
              // transfers with this peer. Completed ('done',
              // 'rejected', 'aborted') entries are intentionally
              // preserved with their blob URLs so the user can still
              // download a file whose sender has since left; the URL
              // is revoked later via dismissTransfer or the unmount
              // cleanup. Only mid-flight ('offered' / 'streaming')
              // entries are mutated here.
              messenger?.removeFriend(goneEd)
              setOutbound((prev) => {
                const next: Record<string, OutboundTransfer> = {}
                for (const [k, t] of Object.entries(prev)) {
                  if (t.peerHex === goneHex) {
                    if (t.status === 'awaiting-decision' || t.status === 'streaming') {
                      next[k] = { ...t, status: 'aborted', file: null }
                    }
                    // 'done' / 'rejected' transfers stay around (they
                    // don't reference the peer past completion); the
                    // 'aborted' entry surfaces in the transfer list
                    // so the user knows the disconnect interrupted.
                    else {
                      next[k] = t
                    }
                  } else {
                    next[k] = t
                  }
                }
                return next
              })
              // Drop the receive buffers for the gone peer's in-flight
              // transfers. Done outside the setInbound updater below —
              // mutating the ref inside a (possibly double-invoked) pure
              // updater would be a side effect.
              for (const [k, t] of Object.entries(inboundRef.current)) {
                if (t.peerHex === goneHex) {
                  clearInboundIdleRef.current(k)
                  inboundDataRef.current.delete(k)
                  inboundAckRef.current.delete(k)
                }
              }
              setInbound((prev) => {
                const next: Record<string, InboundTransfer> = {}
                for (const [k, t] of Object.entries(prev)) {
                  if (t.peerHex === goneHex) {
                    if (t.status === 'offered' || t.status === 'streaming') {
                      // Aborted mid-flight — revoke any prematurely-
                      // assembled blobUrl (shouldn't happen but defensive).
                      if (t.blobUrl) URL.revokeObjectURL(t.blobUrl)
                      next[k] = { ...t, status: 'aborted', blobUrl: undefined }
                    } else {
                      next[k] = t
                    }
                  } else {
                    next[k] = t
                  }
                }
                return next
              })
              break
            }
            default:
              // Exhaustiveness check: if a new discovery variant is added
              // to parseDiscovery without a case here, this assignment
              // becomes a TypeScript error.
              assertNever(dmsg)
          }
          return
        }
        // Not a discovery frame — try friendship. Returns null for any
        // other type (encrypted-envelope etc.); those land in subsequent
        // layers and are ignored here.
        const fmsg = parseFriendshipNotification(data)
        if (fmsg !== null) handleFriendshipNotification(fmsg)
      } catch (err) {
        console.warn('relay message parse failed:', err)
      }
    }

    function handleFriendshipNotification(
      msg: NonNullable<ReturnType<typeof parseFriendshipNotification>>,
    ): void {
      const peerHex = bytesToHex(msg.from)
      // Stale-notification gate: friendship notifications and
      // peer-left broadcasts are dispatched from independent goroutines
      // on the relay (writeAsyncToIdentity vs broadcastExcept), so a
      // delayed invite-from / accept-from can land AFTER the matching
      // peer-left has already cleared the relay's pair-state. Drop any
      // notification for a peer we've observed leave (and not rejoined)
      // — without this, the local UI would gain a friend / pending
      // invite the relay no longer honors. Notifications arriving
      // BEFORE peer-joined still pass (seenLeftRef has no entry); the
      // IncomingInvites UI tolerates a missing peer record.
      if (seenLeftRef.current.has(peerHex)) return
      switch (msg.type) {
        case TYPE_INVITE_FROM:
          // Defensive guard: if the relay (despite owning the
          // authoritative pair-state) ever surfaces invite-from for a
          // peer we already consider a friend, drop it — otherwise
          // IncomingInvites would render Accept/Reject for a friendship
          // that's already established.
          if (friendsRef.current.includes(peerHex)) break
          // De-dup: the relay shouldn't fire two invite-from for the same
          // sender at once (the second would be queued), but defensive
          // dedupe avoids weird UI if the invariant is violated.
          setInvitesIn((prev) => (prev.includes(peerHex) ? prev : [...prev, peerHex]))
          break
        case TYPE_ACCEPT_FROM: {
          // Try to derive session keys BEFORE updating friend state.
          // A peer can sign (with their Ed25519) a low-order X25519
          // pub: sig_binding verifies, but ECDH yields a zero shared
          // secret. deriveSessionKeys throws on that, registerFriend
          // re-throws, and we leave friendsRef untouched — the peer
          // doesn't get a "Friend" badge for an unusable session.
          const peer = peersRef.current.find((p) => bytesToHex(p.ed25519Pub) === peerHex)
          if (peer && messenger) {
            try {
              messenger.registerFriend(peer)
              const keys = messenger.getFriendKeys(peer.ed25519Pub)
              const rw = receiveWorkerRef.current
              if (keys && rw) {
                const rk = keys.recvKey
                const buf = rk.buffer.slice(
                  rk.byteOffset,
                  rk.byteOffset + rk.byteLength,
                ) as ArrayBuffer
                rw.postMessage(
                  { type: 'registerFriend', peerHex, recvKey: buf },
                  [buf],
                )
              }
            } catch (err) {
              console.warn(
                'accept-from: session-key derivation failed for',
                peerHex.slice(0, 16),
                '— dropping friendship',
                err,
              )
              setInvitesOut((prev) => prev.filter((h) => h !== peerHex))
              break
            }
          }
          // The originator's invite was accepted: friendship established.
          // (If peer wasn't in peersRef yet — accept-from before
          // peer-joined — we skip registerFriend; the outbound send
          // path's hasFriend gate catches that until peer-joined lands.)
          setInvitesOut((prev) => prev.filter((h) => h !== peerHex))
          // Reciprocal cleanup: if this peer had ALSO sent us an
          // invite (the "we both invited each other" case), our
          // invitesIn entry for them is now moot — we just became
          // friends, so the relay-side reciprocal active was cleared
          // too (handleResponse on the Go side). Without this filter,
          // IncomingInvites would render an Accept/Reject row for an
          // already-established friendship.
          setInvitesIn((prev) => prev.filter((h) => h !== peerHex))
          if (!friendsRef.current.includes(peerHex)) {
            friendsRef.current = [...friendsRef.current, peerHex]
            setFriends(friendsRef.current)
          }
          pushNotice(TYPE_ACCEPT_FROM, peerHex)
          break
        }
        case TYPE_REJECT_FROM:
          setInvitesOut((prev) => prev.filter((h) => h !== peerHex))
          pushNotice(TYPE_REJECT_FROM, peerHex)
          break
        case TYPE_INVITE_DEFERRED:
          // A previously-queued outbound invite just became active. Don't
          // change invitesOut — it was already tracking this peer.
          pushNotice(TYPE_INVITE_DEFERRED, peerHex)
          break
        case TYPE_INVITE_AUTO_REJECTED:
          // Sender's invite never reached the recipient (prior reject from
          // sender's IP). Drop from invitesOut — there's no outstanding
          // invite anymore.
          setInvitesOut((prev) => prev.filter((h) => h !== peerHex))
          pushNotice(TYPE_INVITE_AUTO_REJECTED, peerHex)
          break
        default:
          // Exhaustiveness check: if FriendshipNotificationMsg gains a new
          // variant without a case here, this assignment becomes a
          // TypeScript error.
          assertNever(msg)
      }
    }

    function pushNotice(kind: FriendshipNotice['kind'], peerHex: string): void {
      const notice: FriendshipNotice = { id: nextNoticeId++, kind, peerHex }
      setNotices((prev) => {
        const next = [...prev, notice]
        // Drop oldest (FIFO) if we exceed the cap. slice() copy is O(N)
        // but N is tiny so the simplest impl is fine.
        return next.length > MAX_NOTICES ? next.slice(-MAX_NOTICES) : next
      })
    }

    // --- envelope (encrypted-payload) dispatch ---
    //
    // After friendship is established with a peer, both sides exchange
    // encrypted envelopes (AGENTS.md "Encrypted Envelopes"). Inner-type
    // 0x01 carries JSON transfer-control directives (offer / accept /
    // reject / end); inner-type 0x02 carries file chunks. Failures
    // (parse, decrypt, unknown type) are dropped silently — the relay
    // never replies inline to envelope frames, so neither do we.

    const onEnvelope = (env: IncomingEnvelope): void => {
      if (cancelled) return
      try {
        if (env.innerType === INNER_TYPE_JSON_CONTROL) {
          const text = new TextDecoder().decode(env.plaintext)
          const msg = parseTransferControl(text)
          if (msg !== null) handleTransferControl(env.from, msg)
        } else if (env.innerType === INNER_TYPE_FILE_CHUNK) {
          const c = parseChunk(env.plaintext)
          handleIncomingChunk(env.from, c)
        }
        // Other inner-type values are reserved for future use; drop.
      } catch (err) {
        console.warn('envelope payload parse failed:', err)
      }
    }

    function handleTransferControl(
      from: Uint8Array,
      msg: NonNullable<ReturnType<typeof parseTransferControl>>,
    ): void {
      const peerHex = bytesToHex(from)
      const transferIdHex = bytesToHex(msg.transferId)

      switch (msg.type) {
        case TYPE_TRANSFER_OFFER: {
          // Sender wants to send us a file. Only accept offers from
          // peers we actually consider friends — defensive against
          // a buggy / forged offer slipping past the relay's
          // friendship gate. Without the gate, we'd render an
          // Accept/Reject prompt for someone we never befriended.
          if (!friendsRef.current.includes(peerHex)) return
          // Reject a duplicate transfer_id. Legitimate senders mint a
          // fresh 16-byte random id per offer; reuse is a misbehaving /
          // hostile peer. Without this, a re-used id would clobber the
          // existing entry — leaking a completed transfer's blobUrl
          // (revoke only runs on dismiss / unmount) and overwriting an
          // active transfer's accept/reject UI under the user.
          if (inboundRef.current[transferIdHex] !== undefined) {
            console.warn(
              'transfer-offer: duplicate transfer_id from',
              peerHex.slice(0, 16),
              '— dropping',
            )
            return
          }
          const t: InboundTransfer = {
            transferIdHex,
            peerHex,
            filename: msg.filename,
            totalBytes: msg.size,
            receivedBytes: 0,
            status: 'offered',
          }
          setInbound((prev) => ({ ...prev, [transferIdHex]: t }))
          break
        }
        case TYPE_TRANSFER_ACCEPT: {
          // Recipient accepted our offer — kick off chunk streaming.
          // Gate on (a) sender identity matches the transfer's stored
          // counterparty and (b) the transfer is still awaiting a
          // decision. Without these, a different friend who knows the
          // transfer ID could trigger streaming for a transfer that
          // wasn't theirs.
          const cur = outboundRef.current[transferIdHex]
          if (!cur || cur.peerHex !== peerHex || cur.status !== 'awaiting-decision') break
          const chunkSize = negotiateChunkSize(
            PREFERRED_CHUNK_SIZE,
            relayMaxChunkRef.current,
            msg.maxChunkBytes ?? 0,
          )
          const windowBytes = effectiveWindow(msg.windowBytes ?? 0, chunkSize)
          startStreaming(transferIdHex, chunkSize, windowBytes)
          break
        }
        case TYPE_TRANSFER_REJECT: {
          // Same gate as accept above. Without the status check, a late
          // reject (after accept-and-done) would rewrite a successful
          // transfer's UI to 'rejected'; without the sender check, any
          // friend that learned the transfer ID could mark someone
          // else's transfer rejected.
          setOutbound((prev) => {
            const cur = prev[transferIdHex]
            if (!cur || cur.peerHex !== peerHex || cur.status !== 'awaiting-decision') {
              return prev
            }
            return {
              ...prev,
              [transferIdHex]: {
                ...cur,
                status: 'rejected',
                rejectReason: msg.reason,
                file: null,
              },
            }
          })
          break
        }
        case TYPE_TRANSFER_END: {
          // Sender signaled end-of-stream and handed us its finalized
          // SHA-256. transfer-end may arrive before or after the last
          // chunk; record the expected digest and try to finalize. If
          // the contiguous digest isn't ready yet (a gap remains), the
          // verdict is 'pending' and the chunk handler finalizes once
          // the gap fills — we don't abort on transfer-end-without-last-
          // chunk, just wait for the gap or a disconnect.
          const asm = inboundDataRef.current.get(transferIdHex)
          const cur = inboundRef.current[transferIdHex]
          if (!asm || !cur || cur.peerHex !== peerHex || cur.status !== 'streaming') break
          // Peer control progress — reset receive-stall clock.
          armInboundIdleRef.current(transferIdHex)
          // If using receive worker, forward end there.
          const rw = receiveWorkerRef.current
          if (rw && OPFS_OK && !cur.memoryFallback) {
            const sha = msg.sha256
            const shaBuf = sha.buffer.slice(sha.byteOffset, sha.byteOffset + sha.byteLength)
            rw.postMessage(
              { type: 'end', transferIdHex, expectedSha256: shaBuf },
              [shaBuf as ArrayBuffer],
            )
            break
          }
          asm.expectedSha256 = msg.sha256
          const verdict = inboundVerdict(asm)
          if (verdict !== 'pending') finalizeInbound(transferIdHex, asm, verdict)
          break
        }
        case TYPE_TRANSFER_ACK: {
          // Cumulative receiver progress for windowed sends. Old accept
          // without window_bytes never blocks on acks; we still record
          // lastAck for UI but only gate when windowBytes > 0.
          //
          // Must update React state as well as the ref: progress
          // setOutbound + the outbound→ref sync effect would otherwise
          // wipe a ref-only lastAck and deadlock the window (sender
          // stops; receiver never re-acks past its last threshold).
          const cur = outboundRef.current[transferIdHex]
          if (!cur || cur.peerHex !== peerHex || cur.status !== 'streaming') break
          if (msg.receivedBytes < (cur.lastAck ?? 0)) break
          const updated = { ...cur, lastAck: msg.receivedBytes }
          outboundRef.current = { ...outboundRef.current, [transferIdHex]: updated }
          setOutbound((prev) => {
            const c2 = prev[transferIdHex]
            if (!c2 || c2.peerHex !== peerHex || c2.status !== 'streaming') return prev
            if (msg.receivedBytes < (c2.lastAck ?? 0)) return prev
            return { ...prev, [transferIdHex]: { ...c2, lastAck: msg.receivedBytes } }
          })
          // Wake any waiters via the ack wait map.
          const wake = ackWaitersRef.current.get(transferIdHex)
          if (wake) wake()
          break
        }
        default:
          // Exhaustiveness check — TransferControlMsg is a discriminated
          // union; adding a new variant without a case here is a TS error.
          assertNever(msg)
      }
    }

    function handleIncomingChunk(
      from: Uint8Array,
      c: ReturnType<typeof parseChunk>,
    ): void {
      // The AEAD already authenticates that `from` is the holder of
      // the matching session-send key, but we still gate the chunk on
      // matching the transfer's stored peerHex below — defense in
      // depth, so a different friend who somehow learned a transfer ID
      // can't inject chunks into the wrong inbound state.
      const peerHex = bytesToHex(from)
      const transferIdHex = bytesToHex(c.transferId)
      // Read the committed state synchronously from the ref so all the
      // mutating work (folding the chunk into the assembler's buffer +
      // running hash) happens HERE — exactly once per frame — and not in
      // the setInbound updater, which React may invoke more than once.
      const cur = inboundRef.current[transferIdHex]
      if (!cur || cur.peerHex !== peerHex || cur.status !== 'streaming') return
      const asm = inboundDataRef.current.get(transferIdHex)
      // 'streaming' implies the assembler was allocated on accept; if
      // it's somehow missing, drop rather than crash.
      if (!asm) return

      // acceptChunk runs all the structural / DoS guards (seq bound,
      // duplicate, empty-non-last, overshoot cap), copies the bytes into
      // the preallocated buffer, and folds the contiguous prefix into the
      // running hash. `c.data` aliases the decrypted frame buffer;
      // acceptChunk copies it as needed, so no pre-clone is required.
      const result = acceptChunk(asm, c.seq, c.flags, c.data)
      if (result === 'duplicate') return
      if (result === 'abort') {
        clearInboundIdleRef.current(transferIdHex)
        inboundDataRef.current.delete(transferIdHex)
        inboundAckRef.current.delete(transferIdHex)
        setInbound((prev) => {
          const c2 = prev[transferIdHex]
          if (!c2 || c2.status !== 'streaming') return prev
          return { ...prev, [transferIdHex]: { ...c2, status: 'aborted' } }
        })
        return
      }
      // Peer made progress — reset receive-stall clock.
      armInboundIdleRef.current(transferIdHex)
      // Windowed acks (main-thread path). Worker path posts acks from its
      // progress handler via maybeSendAck.
      maybeSendAck(transferIdHex, asm.receivedBytes, from)
      const verdict = inboundVerdict(asm)
      if (verdict === 'pending') {
        publishInboundProgress(transferIdHex, asm.receivedBytes)
        return
      }
      finalizeInbound(transferIdHex, asm, verdict)
    }

    function maybeSendAck(
      transferIdHex: string,
      received: number,
      peerEd25519Pub: Uint8Array,
    ): void {
      const book = inboundAckRef.current.get(transferIdHex)
      if (!book || book.window <= 0) return
      if (!shouldAck(received, book.lastAcked, book.window)) return
      book.lastAcked = received
      if (!messenger) return
      try {
        const json = buildTransferAck(hexToBytes(transferIdHex), received)
        messenger.send(
          peerEd25519Pub,
          INNER_TYPE_JSON_CONTROL,
          new TextEncoder().encode(json),
        )
      } catch (err) {
        console.warn('transfer-ack send failed:', err)
      }
    }

    function publishInboundProgress(transferIdHex: string, receivedBytes: number): void {
      const now = Date.now()
      let th = uiThrottleRef.current.get('in:' + transferIdHex)
      if (!th) {
        th = { lastAt: now, lastBytes: 0, rate: 0 }
        uiThrottleRef.current.set('in:' + transferIdHex, th)
      }
      if (now - th.lastAt < UI_UPDATE_MS && receivedBytes > 0) return
      const dt = now - th.lastAt
      const delta = receivedBytes - th.lastBytes
      th.rate = emaRate(th.rate, delta, dt > 0 ? dt : 1)
      th.lastAt = now
      th.lastBytes = receivedBytes
      const rate = th.rate
      setInbound((prev) => {
        const c2 = prev[transferIdHex]
        if (!c2 || c2.status !== 'streaming') return prev
        return {
          ...prev,
          [transferIdHex]: { ...c2, receivedBytes, rateBps: rate },
        }
      })
    }

    // finalizeInbound flips a fully-received inbound transfer to its
    // terminal state: 'done' (handing the assembler's buffer to
    // assembledBytes for the post-commit blob-URL step) or 'aborted' on a
    // digest mismatch. Drops the assembler from the ref either way — its
    // buffer is now either owned by assembledBytes or discarded. Called
    // from both the chunk handler (last byte arrived) and the
    // transfer-end handler (advertised digest arrived), whichever lands
    // second.
    function finalizeInbound(
      transferIdHex: string,
      asm: InboundAssembler,
      verdict: 'verified' | 'corrupt',
    ): void {
      clearInboundIdleRef.current(transferIdHex)
      inboundDataRef.current.delete(transferIdHex)
      inboundAckRef.current.delete(transferIdHex)
      setInbound((prev) => {
        const cur = prev[transferIdHex]
        if (!cur || cur.status !== 'streaming') return prev
        if (verdict === 'corrupt') {
          return {
            ...prev,
            [transferIdHex]: {
              ...cur,
              status: 'aborted',
              rejectReason: 'integrity check failed (sha256 mismatch)',
            },
          }
        }
        const blob = assemblerBlob(asm)
        return {
          ...prev,
          [transferIdHex]: {
            ...cur,
            status: 'done',
            receivedBytes: asm.totalBytes,
            // Prefer Blob (growing sink); avoids a second full-size Uint8Array.
            assembledBlob: blob ?? undefined,
          },
        }
      })
    }

    // startStreaming is the sender-side reaction to a transfer-accept.
    // Reads the File incrementally (no whole-file arrayBuffer); honor
    // negotiated chunk + window; pace on socket.bufferedAmount.
    function startStreaming(
      transferIdHex: string,
      chunkSize: number,
      windowBytes: number,
    ): void {
      const t = outboundRef.current[transferIdHex]
      if (!t || t.status !== 'awaiting-decision' || !t.file) return
      const updated: OutboundTransfer = {
        ...t,
        status: 'streaming',
        chunkSize,
        windowBytes,
        lastAck: 0,
      }
      outboundRef.current = { ...outboundRef.current, [transferIdHex]: updated }
      setOutbound((prev) => {
        const marked = markOutboundStreaming(prev, transferIdHex)
        const cur = marked[transferIdHex]
        if (!cur) return marked
        return {
          ...marked,
          [transferIdHex]: { ...cur, chunkSize, windowBytes, lastAck: 0 },
        }
      })
      const transferId = hexToBytes(t.transferIdHex)
      const peerEd25519Pub = hexToBytes(t.peerHex)
      void streamChunks(
        transferIdHex,
        transferId,
        peerEd25519Pub,
        t.file,
        chunkSize,
        windowBytes,
      )
    }

    async function waitForWindow(
      transferIdHex: string,
      needBytes: number,
      windowBytes: number,
    ): Promise<'ok' | 'stall' | 'abort'> {
      if (windowBytes <= 0) return 'ok'
      let lastProgress = Date.now()
      let lastAckSeen =
        outboundRef.current[transferIdHex]?.lastAck ?? 0
      for (;;) {
        const cur = outboundRef.current[transferIdHex]
        if (!cur || cur.status !== 'streaming') return 'abort'
        const sent = cur.sentBytes
        const lastAck = cur.lastAck ?? 0
        if (!windowFull(sent + needBytes, lastAck, windowBytes)) return 'ok'
        if (lastAck > lastAckSeen) {
          lastAckSeen = lastAck
          lastProgress = Date.now()
        }
        if (Date.now() - lastProgress >= STALL_TIMEOUT_MS) return 'stall'
        await new Promise<void>((resolve) => {
          ackWaitersRef.current.set(transferIdHex, resolve)
          setTimeout(resolve, 100)
        })
        ackWaitersRef.current.delete(transferIdHex)
      }
    }

    async function waitBufferedAmount(socket: WebSocket): Promise<void> {
      while (bufferedAmountHigh(socket.bufferedAmount)) {
        await new Promise<void>((r) => setTimeout(r, 10))
        if (bufferedAmountLow(socket.bufferedAmount)) return
      }
    }

    function publishOutboundProgress(
      transferIdHex: string,
      sentBytes: number,
    ): void {
      const now = Date.now()
      let th = uiThrottleRef.current.get(transferIdHex)
      if (!th) {
        th = { lastAt: now, lastBytes: 0, rate: 0 }
        uiThrottleRef.current.set(transferIdHex, th)
      }
      if (now - th.lastAt < UI_UPDATE_MS && sentBytes > 0) return
      const dt = now - th.lastAt
      const delta = sentBytes - th.lastBytes
      th.rate = emaRate(th.rate, delta, dt > 0 ? dt : 1)
      th.lastAt = now
      th.lastBytes = sentBytes
      const rate = th.rate
      // Preserve lastAck from the live ref: a throttled progress tick must
      // not regress the window cursor if React state is briefly behind.
      const liveAck = outboundRef.current[transferIdHex]?.lastAck ?? 0
      setOutbound((prev) => {
        const c2 = prev[transferIdHex]
        if (!c2) return prev
        return {
          ...prev,
          [transferIdHex]: {
            ...c2,
            sentBytes,
            rateBps: rate,
            lastAck: Math.max(c2.lastAck ?? 0, liveAck),
          },
        }
      })
    }

    async function streamChunks(
      transferIdHex: string,
      transferId: Uint8Array,
      peerEd25519Pub: Uint8Array,
      file: File,
      chunkSize: number,
      windowBytes: number,
    ): Promise<void> {
      // Prefer send worker (crypto + hash off main). Fall back to main-
      // thread seal if Worker construction fails.
      const keys = messenger?.getFriendKeys(peerEd25519Pub)
      const socket = connRef.current?.socket
      if (keys && socket && typeof Worker !== 'undefined') {
        try {
          await streamChunksViaWorker(
            transferIdHex,
            transferId,
            peerEd25519Pub,
            file,
            chunkSize,
            windowBytes,
            keys.sendKey,
            socket,
          )
          return
        } catch (err) {
          console.warn('send worker failed, falling back to main-thread seal:', err)
        }
      }
      await streamChunksMain(
        transferIdHex,
        transferId,
        peerEd25519Pub,
        file,
        chunkSize,
        windowBytes,
      )
    }

    async function streamChunksViaWorker(
      transferIdHex: string,
      transferId: Uint8Array,
      peerEd25519Pub: Uint8Array,
      file: File,
      chunkSize: number,
      windowBytes: number,
      sendKey: Uint8Array,
      socket: WebSocket,
    ): Promise<void> {
      const worker = new Worker(new URL('./transfer/sendWorker.ts', import.meta.url), {
        type: 'module',
      })
      const tidBuf = transferId.buffer.slice(
        transferId.byteOffset,
        transferId.byteOffset + transferId.byteLength,
      ) as ArrayBuffer
      const keyBuf = sendKey.buffer.slice(
        sendKey.byteOffset,
        sendKey.byteOffset + sendKey.byteLength,
      ) as ArrayBuffer
      const peerBuf = peerEd25519Pub.buffer.slice(
        peerEd25519Pub.byteOffset,
        peerEd25519Pub.byteOffset + peerEd25519Pub.byteLength,
      ) as ArrayBuffer
      worker.postMessage(
        {
          type: 'start',
          transferId: tidBuf,
          sendKey: keyBuf,
          peerEd25519Pub: peerBuf,
          file,
          chunkSize,
          totalBytes: file.size,
        },
        [tidBuf, keyBuf, peerBuf],
      )

      const abort = (reason: string) => {
        worker.postMessage({ type: 'abort' })
        worker.terminate()
        setOutbound((prev) => {
          const c2 = prev[transferIdHex]
          if (!c2) return prev
          return {
            ...prev,
            [transferIdHex]: {
              ...c2,
              status: 'aborted',
              file: null,
              rejectReason: reason,
            },
          }
        })
      }

      await new Promise<void>((resolve) => {
        // Serialize every worker message. An async onmessage without a
        // chain lets the last frame's waitForWindow interleave with a
        // follow-up message and mark the transfer done before the last
        // chunk is socket.send'd — receiver stuck at ~100% streaming.
        let chain: Promise<void> = Promise.resolve()
        type WorkerFrame =
          | {
              type: 'frame'
              frame: ArrayBuffer
              sentBytes: number
              last: false
            }
          | {
              type: 'frame'
              frame: ArrayBuffer
              sentBytes: number
              last: true
              sha256: ArrayBuffer
              transferId: ArrayBuffer
            }
        const handleFrame = async (msg: WorkerFrame): Promise<void> => {
          const cur = outboundRef.current[transferIdHex]
          if (!cur || cur.status !== 'streaming' || cancelled) {
            abort('aborted')
            resolve()
            return
          }
          const need = msg.sentBytes - (cur.sentBytes ?? 0)
          const w = await waitForWindow(transferIdHex, need, windowBytes)
          if (w === 'stall') {
            abort('flow-control stall')
            resolve()
            return
          }
          if (w === 'abort') {
            worker.terminate()
            resolve()
            return
          }
          // Re-check after awaits: peer-left / abort may have flipped status.
          const still = outboundRef.current[transferIdHex]
          if (!still || still.status !== 'streaming' || cancelled) {
            abort('aborted')
            resolve()
            return
          }
          await waitBufferedAmount(socket)
          try {
            socket.send(msg.frame)
          } catch (err) {
            console.warn('chunk send failed:', err)
            abort('send failed')
            resolve()
            return
          }
          const withSent: OutboundTransfer = {
            ...outboundRef.current[transferIdHex]!,
            sentBytes: msg.sentBytes,
          }
          outboundRef.current = {
            ...outboundRef.current,
            [transferIdHex]: withSent,
          }
          publishOutboundProgress(transferIdHex, msg.sentBytes)

          if (!msg.last) {
            worker.postMessage({ type: 'pull' })
            return
          }

          // Last chunk is on the wire. Only now send transfer-end and
          // flip to done — never before the final socket.send.
          if (!cancelled && messenger) {
            try {
              const endJson = buildTransferEnd(
                new Uint8Array(msg.transferId),
                new Uint8Array(msg.sha256),
              )
              messenger.send(
                peerEd25519Pub,
                INNER_TYPE_JSON_CONTROL,
                new TextEncoder().encode(endJson),
              )
            } catch (err) {
              console.warn('transfer-end send failed:', err)
              abort('transfer-end send failed')
              resolve()
              return
            }
          }
          worker.terminate()
          const done: OutboundTransfer = {
            ...outboundRef.current[transferIdHex]!,
            status: 'done',
            file: null,
            sentBytes: msg.sentBytes,
          }
          outboundRef.current = {
            ...outboundRef.current,
            [transferIdHex]: done,
          }
          setOutbound((prev) => {
            const c2 = prev[transferIdHex]
            if (!c2 || c2.status !== 'streaming') return prev
            return { ...prev, [transferIdHex]: done }
          })
          resolve()
        }

        worker.onmessage = (ev: MessageEvent) => {
          const msg = ev.data as WorkerFrame
          if (msg?.type !== 'frame') return
          chain = chain.then(() => handleFrame(msg)).catch((err) => {
            console.warn('send worker frame handler failed:', err)
            abort(err instanceof Error ? err.message : 'send failed')
            resolve()
          })
        }
        worker.postMessage({ type: 'pull' })
      })
    }

    async function streamChunksMain(
      transferIdHex: string,
      transferId: Uint8Array,
      peerEd25519Pub: Uint8Array,
      file: File,
      chunkSize: number,
      windowBytes: number,
    ): Promise<void> {
      const hasher = sha256.create()
      let offset = 0
      let seq = 0
      const total = file.size
      for (;;) {
        const cur = outboundRef.current[transferIdHex]
        if (!cur || cur.status !== 'streaming') return
        if (cancelled || !messenger) return

        const remaining = total - offset
        const size = total === 0 ? 0 : Math.min(chunkSize, remaining)
        const isLast = total === 0 || offset + size >= total
        let data = new Uint8Array(0)
        if (size > 0) {
          data = new Uint8Array(await file.slice(offset, offset + size).arrayBuffer())
        }
        const flags = isLast ? CHUNK_FLAG_LAST : 0
        const chunkPlaintext = buildChunk(transferId, seq, flags, data)

        const w = await waitForWindow(transferIdHex, size, windowBytes)
        if (w === 'stall') {
          setOutbound((prev) => {
            const c2 = prev[transferIdHex]
            if (!c2) return prev
            return {
              ...prev,
              [transferIdHex]: {
                ...c2,
                status: 'aborted',
                file: null,
                rejectReason: 'flow-control stall',
              },
            }
          })
          return
        }
        if (w === 'abort') return

        const sock = connRef.current?.socket
        if (sock) await waitBufferedAmount(sock)

        try {
          messenger.send(peerEd25519Pub, INNER_TYPE_FILE_CHUNK, chunkPlaintext)
        } catch (err) {
          console.warn('chunk send failed:', err)
          setOutbound((prev) => {
            const c2 = prev[transferIdHex]
            if (!c2) return prev
            return { ...prev, [transferIdHex]: { ...c2, status: 'aborted', file: null } }
          })
          return
        }

        hasher.update(data)
        offset += size
        seq++
        const withSent: OutboundTransfer = {
          ...outboundRef.current[transferIdHex]!,
          sentBytes: offset,
        }
        outboundRef.current = { ...outboundRef.current, [transferIdHex]: withSent }
        publishOutboundProgress(transferIdHex, offset)

        if (isLast) break
      }

      if (!cancelled && messenger) {
        try {
          const endJson = buildTransferEnd(transferId, hasher.digest())
          messenger.send(
            peerEd25519Pub,
            INNER_TYPE_JSON_CONTROL,
            new TextEncoder().encode(endJson),
          )
        } catch (err) {
          console.warn('transfer-end send failed:', err)
        }
      }
      setOutbound((prev) => {
        const c2 = prev[transferIdHex]
        if (!c2 || c2.status !== 'streaming') return prev
        return { ...prev, [transferIdHex]: { ...c2, status: 'done', file: null } }
      })
    }

    ;(async () => {
      try {
        const identity = generateIdentity()
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        // Same-origin assumption: the relay's Go binary serves both the
        // SPA (//go:embed) and the /ws endpoint.
        const url = `${proto}//${window.location.host}/ws`
        conn = await connectToRelay(url, identity, { signal: ac.signal })
        if (cancelled) {
          conn.close()
          return
        }
        // Sanity check: the relay's echoed ed25519_pub must match what we
        // sent. A mismatch here means either a relay bug or a malicious
        // relay trying to substitute a different identity in the echo.
        // We always render the fingerprint from the local identity (the
        // root of trust), but flag the discrepancy in the console.
        if (!bytesEqual(conn.you.ed25519Pub, identity.ed25519Pub)) {
          console.warn(
            'relay welcome echoed a different ed25519_pub than we sent; ' +
              'displaying local-identity fingerprint regardless',
          )
        }
        // Stash conn for the send handlers (sendInvite/sendAccept/
        // sendReject use connRef so they don't capture stale closures).
        connRef.current = conn
        // Capture relay capacity ads for chunk negotiation.
        relayMaxChunkRef.current = conn.limits?.maxChunkBytes ?? 0
        // Spin up the encrypted-envelope messenger. It owns its own
        // socket subscription (binary frames only) so it coexists with
        // conn.onMessage (text frames only).
        messenger = new EnvelopeMessenger(conn.socket, identity)
        messengerRef.current = messenger
        // Receive worker: decrypt + OPFS write + hash off the main thread
        // when origin-private storage exists. Sync-access-handle presence is
        // checked inside the worker (Safari does not expose it on the main
        // thread prototype). Sweep /inflight leftovers on start.
        if (OPFS_OK && typeof Worker !== 'undefined') {
          try {
            const rw = new Worker(
              new URL('./transfer/receiveWorker.ts', import.meta.url),
              { type: 'module' },
            )
            receiveWorkerRef.current = rw
            rw.onmessage = (ev: MessageEvent) => {
              const msg = ev.data as {
                type: string
                transferIdHex: string
                receivedBytes?: number
                mode?: string
                bytes?: ArrayBuffer
                totalBytes?: number
                reason?: string
              }
              if (msg.type === 'needAck' && msg.receivedBytes !== undefined) {
                // Unthrottled window/4 threshold from the worker — must
                // fire promptly so the sender never fills the window
                // waiting on a UI progress tick. Also peer progress for
                // the receive-stall clock.
                armInboundIdleRef.current(msg.transferIdHex)
                const peerHex =
                  inboundRef.current[msg.transferIdHex]?.peerHex ?? ''
                if (peerHex) {
                  maybeSendAck(
                    msg.transferIdHex,
                    msg.receivedBytes,
                    hexToBytes(peerHex),
                  )
                }
              } else if (
                msg.type === 'progress' &&
                msg.receivedBytes !== undefined
              ) {
                // UI-only throttle; acks come via needAck. Still count as
                // peer progress for receive-stall (needAck may not fire
                // every chunk).
                armInboundIdleRef.current(msg.transferIdHex)
                publishInboundProgress(msg.transferIdHex, msg.receivedBytes)
              } else if (msg.type === 'done') {
                clearInboundIdleRef.current(msg.transferIdHex)
                void (async () => {
                  let blobUrl: string | undefined
                  if (msg.mode === 'memory' && msg.bytes) {
                    const blob = new Blob([msg.bytes], {
                      type: 'application/octet-stream',
                    })
                    blobUrl = URL.createObjectURL(blob)
                  } else if (msg.mode === 'opfs') {
                    try {
                      const root = await navigator.storage.getDirectory()
                      const inflight = await root.getDirectoryHandle('inflight')
                      const fh = await inflight.getFileHandle(msg.transferIdHex)
                      const file = await fh.getFile()
                      blobUrl = URL.createObjectURL(file)
                    } catch (err) {
                      console.warn('opfs finalize getFile failed:', err)
                    }
                  }
                  setInbound((prev) => {
                    const c2 = prev[msg.transferIdHex]
                    if (!c2 || c2.status !== 'streaming') return prev
                    return {
                      ...prev,
                      [msg.transferIdHex]: {
                        ...c2,
                        status: 'done',
                        receivedBytes: msg.totalBytes ?? c2.totalBytes,
                        blobUrl,
                      },
                    }
                  })
                  inboundAckRef.current.delete(msg.transferIdHex)
                })()
              } else if (msg.type === 'aborted' || msg.type === 'startFailed') {
                clearInboundIdleRef.current(msg.transferIdHex)
                inboundAckRef.current.delete(msg.transferIdHex)
                inboundDataRef.current.delete(msg.transferIdHex)
                const reason =
                  msg.reason ??
                  (msg.type === 'startFailed'
                    ? 'could not open on-disk receive path'
                    : 'aborted')
                setInbound((prev) => {
                  const c2 = prev[msg.transferIdHex]
                  if (!c2) return prev
                  return {
                    ...prev,
                    [msg.transferIdHex]: {
                      ...c2,
                      status: 'aborted',
                      rejectReason: reason,
                    },
                  }
                })
              }
            }
            // Route 0x02 frames to the receive worker when any OPFS-backed
            // inbound is streaming. The worker demuxes by decrypted
            // transfer_id so concurrent receives from the same peer never
            // cross-wire (main only stamps peerHex + raw frame).
            messenger.setRawFrameHandler((frame) => {
              if (frame.length < 1 + ENVELOPE_PEER_KEY_LEN) return false
              if (frame[0] !== INNER_TYPE_FILE_CHUNK) return false
              if (!receiveWorkerRef.current) return false
              const peerHex = bytesToHex(frame.subarray(1, 1 + ENVELOPE_PEER_KEY_LEN))
              let anyOpfs = false
              for (const t of Object.values(inboundRef.current)) {
                if (
                  t.peerHex === peerHex &&
                  t.status === 'streaming' &&
                  !t.memoryFallback
                ) {
                  anyOpfs = true
                  break
                }
              }
              if (!anyOpfs) return false
              const copy = frame.buffer.slice(
                frame.byteOffset,
                frame.byteOffset + frame.byteLength,
              )
              receiveWorkerRef.current.postMessage(
                { type: 'frame', peerHex, frame: copy },
                [copy],
              )
              return true
            })
            // Best-effort OPFS /inflight sweep.
            void (async () => {
              try {
                const root = await navigator.storage.getDirectory()
                const inflight = await root.getDirectoryHandle('inflight', {
                  create: true,
                })
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                for await (const [name] of (inflight as any).entries()) {
                  try {
                    await inflight.removeEntry(name)
                  } catch {
                    /* ignore */
                  }
                }
              } catch {
                /* OPFS optional */
              }
            })()
          } catch (err) {
            console.warn('receive worker unavailable:', err)
          }
        }
        unsubscribeEnvelope = messenger.onEnvelope(onEnvelope)
        // Subscribe via conn.onMessage rather than socket.addEventListener.
        // The client buffers any frames the relay sent between welcome and
        // this call (e.g. peer-list, which the Go relay pushes immediately
        // after welcome) and delivers them synchronously here, so the
        // microtask gap between handshake-resolution and listener-attach
        // is closed by construction.
        unsubscribeMessage = conn.onMessage(onMessage)
        // Surface a closed state when the socket later drops. Attach
        // BEFORE checking readyState so we don't miss a close event that
        // fires synchronously after this listener is registered, then
        // synchronously check the current state so a close that fired
        // between handshake-resolution and listener-attach (TOCTOU) is
        // still observed.
        conn.socket.addEventListener('close', onClose)
        if (conn.socket.readyState === WebSocket.CLOSED) {
          // We missed the real CloseEvent; surface the abnormal-close code
          // with no reason (matches what browsers report when a close frame
          // never arrived).
          onClose(new CloseEvent('close', { code: 1006, reason: '' }))
        }
        // Don't render 'connected' over a socket that's already gone —
        // either the synthetic-close branch above just set 'closed', or
        // the real 'close' listener fired between handshake-resolution
        // and now.
        if (conn.socket.readyState === WebSocket.OPEN) {
          setState({ kind: 'connected', you: conn.you, identity })
        }
      } catch (err) {
        if (cancelled) return
        setState({ kind: 'error', message: errorMessage(err) })
      }
    })()

    return () => {
      cancelled = true
      ac.abort()
      unsubscribeEnvelope?.()
      messenger?.setRawFrameHandler(null)
      messenger?.close()
      messengerRef.current = null
      receiveWorkerRef.current?.terminate()
      receiveWorkerRef.current = null
      for (const t of inboundIdleTimers.values()) clearTimeout(t)
      inboundIdleTimers.clear()
      if (conn) {
        conn.socket.removeEventListener('close', onClose)
        unsubscribeMessage?.()
        conn.close()
      }
      // Reset peers so a future remount (or any code path that later
      // renders state outside `connected`) doesn't display stale entries.
      // Done in cleanup-only to avoid an extra render on every state
      // transition. Also revoke any blob URLs so the OS-tracked memory
      // backing assembled inbound transfers is released; subsequent
      // mount starts with a clean transfer table.
      setPeers([])
      // Drop any in-flight receive buffers too — the ref survives a
      // StrictMode/HMR unmount→remount, so without this an assembler
      // allocated mid-stream stays pinned into the next mount. Cleared
      // outside the setInbound updater (refs are not React-tracked state).
      inboundData.clear()
      setInbound((prev) => {
        for (const t of Object.values(prev)) {
          if (t.blobUrl) URL.revokeObjectURL(t.blobUrl)
        }
        return {}
      })
      setOutbound({})
      connRef.current = null
      friendsRef.current = []
    }
  }, [])

  const sendInvite = useCallback((peer: PeerRecord) => {
    const c = connRef.current
    if (!c || c.socket.readyState !== WebSocket.OPEN) return
    const peerHex = bytesToHex(peer.ed25519Pub)
    // Send BEFORE mutating local state so a synchronous send() failure
    // (socket transitioned OPEN→CLOSING between the readyState check and
    // the send call) doesn't leave the UI optimistically pending for an
    // invite the relay never received.
    try {
      c.socket.send(buildInviteMsg(peer.ed25519Pub))
    } catch (err) {
      console.warn('relay send (invite) failed:', err)
      return
    }
    // Optimistic-UI: mark the peer as pending immediately so the button
    // flips to "Pending…" without waiting for any wire echo. The relay
    // doesn't echo a positive ack on send (only error paths surface),
    // so this is the only signal we get.
    setInvitesOut((prev) => (prev.includes(peerHex) ? prev : [...prev, peerHex]))
  }, [])

  const sendAccept = useCallback((peerHex: string) => {
    const c = connRef.current
    if (!c || c.socket.readyState !== WebSocket.OPEN) return
    const ed25519Pub = hexToBytes(peerHex)
    // Derive session keys BEFORE sending the accept on the wire — a
    // low-order peer X25519 (signed but ECDH-unusable) makes
    // registerFriend throw, and we want to abort the entire accept so
    // the relay never establishes friendship for an unusable peer.
    // The Accept button is already gated on the peer being in
    // peersRef (b126de7), so a missing peer here is structurally
    // impossible — but defense-in-depth.
    const peer = peersRef.current.find((p) => bytesToHex(p.ed25519Pub) === peerHex)
    if (!peer || !messengerRef.current) return
    try {
      messengerRef.current.registerFriend(peer)
      const keys = messengerRef.current.getFriendKeys(peer.ed25519Pub)
      const rw = receiveWorkerRef.current
      if (keys && rw) {
        const rk = keys.recvKey
        const buf = rk.buffer.slice(
          rk.byteOffset,
          rk.byteOffset + rk.byteLength,
        ) as ArrayBuffer
        rw.postMessage({ type: 'registerFriend', peerHex, recvKey: buf }, [buf])
      }
    } catch (err) {
      console.warn(
        'sendAccept: session-key derivation failed for',
        peerHex.slice(0, 16),
        '— refusing accept',
        err,
      )
      return
    }
    try {
      c.socket.send(buildAcceptMsg(ed25519Pub))
    } catch (err) {
      console.warn('relay send (accept) failed:', err)
      // Roll back the messenger registration so we don't have
      // session keys for a friendship the relay never recorded.
      messengerRef.current.removeFriend(ed25519Pub)
      return
    }
    // Optimistic-UI: the relay does NOT echo accept-from to the responder
    // (it only forwards to the originator), so the local friendship-set
    // update has to happen here on the click — there's no other signal.
    setInvitesIn((prev) => prev.filter((h) => h !== peerHex))
    // Reciprocal cleanup mirroring the accept-from handler: if we had
    // also been inviting this peer, our outbound invite is now moot
    // (relay clears the reciprocal active in handleResponse).
    setInvitesOut((prev) => prev.filter((h) => h !== peerHex))
    if (!friendsRef.current.includes(peerHex)) {
      friendsRef.current = [...friendsRef.current, peerHex]
      setFriends(friendsRef.current)
    }
  }, [])

  const sendReject = useCallback((peerHex: string) => {
    const c = connRef.current
    if (!c || c.socket.readyState !== WebSocket.OPEN) return
    const ed25519Pub = hexToBytes(peerHex)
    try {
      c.socket.send(buildRejectMsg(ed25519Pub))
    } catch (err) {
      console.warn('relay send (reject) failed:', err)
      return
    }
    setInvitesIn((prev) => prev.filter((h) => h !== peerHex))
  }, [])

  const dismissNotice = useCallback((id: number) => {
    setNotices((prev) => prev.filter((n) => n.id !== id))
  }, [])

  // sendFile mints a transfer_id and ships a transfer-offer without
  // reading the whole file into RAM — streaming happens after accept
  // via file.slice() / send worker.
  const sendFile = useCallback(async (peer: PeerRecord, file: File): Promise<void> => {
    const m = messengerRef.current
    if (!m || !m.hasFriend(peer.ed25519Pub)) {
      console.warn('sendFile: no session keys for peer (not a friend?)')
      return
    }
    const transferId = randomBytes(TRANSFER_ID_LEN)
    const transferIdHex = bytesToHex(transferId)
    const peerHex = bytesToHex(peer.ed25519Pub)
    const t: OutboundTransfer = {
      transferIdHex,
      peerHex,
      filename: file.name,
      totalBytes: file.size,
      sentBytes: 0,
      status: 'awaiting-decision',
      file,
    }
    outboundRef.current = { ...outboundRef.current, [transferIdHex]: t }
    setOutbound((prev) => ({ ...prev, [transferIdHex]: t }))

    try {
      const offerJson = buildTransferOffer(transferId, file.name, file.size)
      m.send(peer.ed25519Pub, INNER_TYPE_JSON_CONTROL, new TextEncoder().encode(offerJson))
    } catch (err) {
      console.warn('sendFile: transfer-offer send failed:', err)
      const rolledBack = { ...outboundRef.current }
      delete rolledBack[transferIdHex]
      outboundRef.current = rolledBack
      setOutbound((prev) => {
        const next = { ...prev }
        delete next[transferIdHex]
        return next
      })
    }
  }, [])

  // acceptIncomingTransfer is the click-on-Accept handler in the
  // IncomingTransferOffers section: send transfer-accept and flip the
  // inbound state to 'streaming' so subsequent chunks land in the
  // chunks map. The wire send happens BEFORE setInbound — the updater
  // is pure (React may invoke it more than once under StrictMode /
  // concurrent rendering, and m.send is not idempotent). Reads from
  // inboundRef so the pre-send status check sees the latest committed
  // state without going through React's batched setState pipeline.
  //
  // Click-debounce: a fast double-click would otherwise dispatch two
  // handlers in the same render frame (before React commits the first
  // setInbound and the inbound→inboundRef sync effect runs), with both
  // observing status='offered' and both calling m.send. We pre-mutate
  // inboundRef synchronously so click N+1 fails the `cur.status !==
  // 'offered'` gate. Refs are explicitly outside React's tracked
  // state, so this direct mutation is well-defined; setInbound below
  // catches up with the same transition through the normal pipeline.
  const abortOfferLocal = useCallback(
    (transferIdHex: string, cur: InboundTransfer, reason: string) => {
      clearInboundIdle(transferIdHex)
      const aborted: InboundTransfer = {
        ...cur,
        status: 'aborted',
        rejectReason: reason,
      }
      inboundRef.current = {
        ...inboundRef.current,
        [transferIdHex]: aborted,
      }
      inboundDataRef.current.delete(transferIdHex)
      inboundAckRef.current.delete(transferIdHex)
      setInbound((prev) => {
        const c2 = prev[transferIdHex]
        if (!c2 || (c2.status !== 'offered' && c2.status !== 'streaming')) {
          return prev
        }
        return { ...prev, [transferIdHex]: aborted }
      })
    },
    [clearInboundIdle],
  )

  const acceptIncomingTransfer = useCallback((transferIdHex: string) => {
    void (async () => {
      const m = messengerRef.current
      if (!m) return
      const cur = inboundRef.current[transferIdHex]
      if (!cur || cur.status !== 'offered') return

      // Pre-claim so a double-click cannot start two accepts.
      inboundRef.current = {
        ...inboundRef.current,
        [transferIdHex]: { ...cur, status: 'streaming' },
      }

      const useOpfs = OPFS_OK && !!receiveWorkerRef.current
      const memoryFallback = !useOpfs

      // Capacity ads so a new sender can negotiate big chunks + windowing.
      const maxChunk = Math.min(
        MAX_CHUNK_BYTES,
        relayMaxChunkRef.current > 0 ? relayMaxChunkRef.current : MAX_CHUNK_BYTES,
      )
      const windowBytes = DEFAULT_WINDOW_BYTES
      const chunkForWindow = negotiateChunkSize(
        PREFERRED_CHUNK_SIZE,
        relayMaxChunkRef.current,
        maxChunk,
      )
      const effWindow = effectiveWindow(windowBytes, chunkForWindow)

      // Paint streaming (+ optional RAM warning) before any heavy work so
      // the user sees feedback, then start receiving.
      const receiveWarning =
        memoryFallback && cur.totalBytes >= MEMORY_WARN_BYTES
          ? diskReceiveBlockedReason() +
            ' Receiving in memory instead — the tab may run out of RAM on very large files.'
          : undefined

      const streamingPaint: InboundTransfer = {
        ...cur,
        status: 'streaming',
        memoryFallback,
        receiveWarning,
      }
      inboundRef.current = {
        ...inboundRef.current,
        [transferIdHex]: streamingPaint,
      }
      setInbound((prev) => {
        const c2 = prev[transferIdHex]
        if (!c2 || (c2.status !== 'offered' && c2.status !== 'streaming')) {
          return prev
        }
        return { ...prev, [transferIdHex]: streamingPaint }
      })
      // Two rAFs: one after style flush, one after the next paint, so the
      // warning is visible before we start accepting chunks / OPFS open.
      await new Promise<void>((r) => {
        requestAnimationFrame(() => requestAnimationFrame(() => r()))
      })

      if (!useOpfs) {
        if (cur.totalBytes >= MEMORY_WARN_BYTES) {
          console.warn(
            'transfer-accept: OPFS path unavailable; receiving in memory',
            cur.totalBytes,
            'secureContext=',
            typeof window !== 'undefined' && window.isSecureContext,
          )
        }
        // Growing sink — no up-front totalBytes alloc (avoids OOM-at-accept).
        let asm: InboundAssembler
        try {
          asm = newInboundAssembler(cur.totalBytes)
        } catch (err) {
          console.warn('transfer-accept: assembler setup failed:', err)
          abortOfferLocal(
            transferIdHex,
            cur,
            'Could not start in-memory receive. Try the TUI client.',
          )
          return
        }
        inboundDataRef.current.set(transferIdHex, asm)
      } else {
        // Wait for the worker to open the on-disk sink before we tell the
        // peer to stream — avoids accepting into a failed OPFS open.
        const rw = receiveWorkerRef.current!
        const opened = await new Promise<boolean>((resolve) => {
          const onMsg = (ev: MessageEvent) => {
            const msg = ev.data as { type?: string; transferIdHex?: string }
            if (msg.transferIdHex !== transferIdHex) return
            if (msg.type === 'startReady') {
              rw.removeEventListener('message', onMsg)
              resolve(true)
            } else if (msg.type === 'startFailed' || msg.type === 'aborted') {
              rw.removeEventListener('message', onMsg)
              resolve(false)
            }
          }
          rw.addEventListener('message', onMsg)
          rw.postMessage({
            type: 'start',
            transferIdHex,
            peerHex: cur.peerHex,
            totalBytes: cur.totalBytes,
            mode: 'opfs',
            windowBytes: effWindow,
          })
          // Don't hang forever if the worker is wedged.
          setTimeout(() => {
            rw.removeEventListener('message', onMsg)
            resolve(false)
          }, 15_000)
        })
        if (!opened) {
          abortOfferLocal(
            transferIdHex,
            cur,
            'Could not open on-disk storage for this receive (OPFS). Try again or use the TUI client.',
          )
          return
        }
      }

      // Re-check still streaming claim (peer-left / reject race).
      if (inboundRef.current[transferIdHex]?.status !== 'streaming') return

      inboundAckRef.current.set(transferIdHex, { window: effWindow, lastAcked: 0 })
      // Start receive-stall clock: if the sender never streams (or hangs
      // mid-transfer), abort after STALL_TIMEOUT_MS without progress.
      armInboundIdle(transferIdHex)
      try {
        const transferId = hexToBytes(transferIdHex)
        const peerEd25519Pub = hexToBytes(cur.peerHex)
        const acceptJson = buildTransferAccept(transferId, {
          maxChunkBytes: maxChunk,
          windowBytes,
        })
        m.send(
          peerEd25519Pub,
          INNER_TYPE_JSON_CONTROL,
          new TextEncoder().encode(acceptJson),
        )
      } catch (err) {
        console.warn('transfer-accept send failed:', err)
        abortOfferLocal(transferIdHex, cur, 'Failed to send accept')
        return
      }
    })()
  }, [abortOfferLocal, armInboundIdle])

  // rejectIncomingTransfer is the click-on-Reject handler. We DROP the
  // inbound entry entirely on reject (no need to keep state for an
  // explicitly-rejected offer); the sender's UI will surface the
  // rejection from the transfer-reject envelope they receive back.
  // Same send-then-pure-setInbound + ref-pre-claim pattern as
  // acceptIncomingTransfer.
  const rejectIncomingTransfer = useCallback((transferIdHex: string) => {
    const m = messengerRef.current
    if (!m) return
    const cur = inboundRef.current[transferIdHex]
    if (!cur || cur.status !== 'offered') return
    const claimed = { ...inboundRef.current }
    delete claimed[transferIdHex]
    inboundRef.current = claimed
    try {
      const transferId = hexToBytes(transferIdHex)
      const peerEd25519Pub = hexToBytes(cur.peerHex)
      const rejectJson = buildTransferReject(transferId)
      m.send(peerEd25519Pub, INNER_TYPE_JSON_CONTROL, new TextEncoder().encode(rejectJson))
    } catch (err) {
      console.warn('transfer-reject send failed:', err)
      // Roll back the optimistic delete so the user can retry.
      inboundRef.current = { ...inboundRef.current, [transferIdHex]: cur }
      return
    }
    setInbound((prev) => {
      const c2 = prev[transferIdHex]
      if (!c2 || c2.status !== 'offered') return prev
      const next = { ...prev }
      delete next[transferIdHex]
      return next
    })
  }, [])

  // dismissTransfer removes a completed/rejected/aborted transfer from
  // the UI. For inbound 'done' transfers it also revokes the blob URL so
  // the OS-tracked blob memory is released; the user must save the file
  // BEFORE clicking dismiss.
  const dismissTransfer = useCallback(
    (kind: 'in' | 'out', transferIdHex: string) => {
      if (kind === 'out') {
        setOutbound((prev) => {
          const next = { ...prev }
          delete next[transferIdHex]
          return next
        })
      } else {
        // Drop any lingering assembler (defensive — a terminal transfer's
        // assembler was already dropped on done/abort, but a dismiss of a
        // still-streaming transfer would leave its buffer pinned).
        clearInboundIdle(transferIdHex)
        inboundDataRef.current.delete(transferIdHex)
        inboundAckRef.current.delete(transferIdHex)
        setInbound((prev) => {
          const cur = prev[transferIdHex]
          if (cur?.blobUrl) URL.revokeObjectURL(cur.blobUrl)
          const next = { ...prev }
          delete next[transferIdHex]
          return next
        })
      }
    },
    [clearInboundIdle],
  )

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-title">
          <img className="app-logo" src="/logo.png" alt="" width={40} height={40} />
          LemurPouch
        </h1>
        <ThemeToggle />
      </header>
      <ConnectionView
        state={state}
        peers={peers}
        invitesIn={invitesIn}
        invitesOut={invitesOut}
        friends={friends}
        notices={notices}
        outbound={outbound}
        inbound={inbound}
        onInvite={sendInvite}
        onAccept={sendAccept}
        onReject={sendReject}
        onDismissNotice={dismissNotice}
        onSendFile={sendFile}
        onAcceptTransfer={acceptIncomingTransfer}
        onRejectTransfer={rejectIncomingTransfer}
        onDismissTransfer={dismissTransfer}
      />
      <Footer />
    </div>
  )
}

function Footer() {
  return (
    <footer className="app-footer">
      Built with <span aria-label="love">❤️</span> by{' '}
      <a href="https://aneesiqbal.ai/" target="_blank" rel="noopener noreferrer">
        Anees Iqbal (@steelbrain)
      </a>
    </footer>
  )
}

interface FriendshipUIProps {
  peers: PeerRecord[]
  invitesIn: string[]
  invitesOut: string[]
  friends: string[]
  notices: FriendshipNotice[]
  outbound: Record<string, OutboundTransfer>
  inbound: Record<string, InboundTransfer>
  onInvite: (peer: PeerRecord) => void
  onAccept: (peerHex: string) => void
  onReject: (peerHex: string) => void
  onDismissNotice: (id: number) => void
  onSendFile: (peer: PeerRecord, file: File) => void
  onAcceptTransfer: (transferIdHex: string) => void
  onRejectTransfer: (transferIdHex: string) => void
  onDismissTransfer: (kind: 'in' | 'out', transferIdHex: string) => void
}

function ConnectionView({ state, ...ui }: { state: State } & FriendshipUIProps) {
  switch (state.kind) {
    case 'connecting':
      return <p className="muted">Connecting…</p>
    case 'closed':
      return <p>{closedMessage(state.code, state.reason)}</p>
    case 'error':
      return (
        <div className="error-banner">
          Connection failed: <code>{state.message}</code>
        </div>
      )
    case 'connected':
      return (
        <>
          <p>
            Connected. The relay sees you at <code>{state.you.ip}:{state.you.port}</code>.
          </p>
          <section className="card card--accent">
            <h2>Your fingerprint</h2>
            <p>
              <span className="fingerprint">{fingerprint(state.identity.ed25519Pub)}</span>
            </p>
            <p className="muted">
              Six BIP-39 words derived from your Ed25519 public key. Both
              peers verify this fingerprint out-of-band; it authenticates the
              Ed25519 identity, which signs the X25519 key whose ECDH derives
              the per-friendship session keys.
            </p>
          </section>
          <NoticeList notices={ui.notices} onDismiss={ui.onDismissNotice} />
          <IncomingInvites
            invitesIn={ui.invitesIn}
            friends={ui.friends}
            peers={ui.peers}
            onAccept={ui.onAccept}
            onReject={ui.onReject}
          />
          <IncomingTransferOffers
            inbound={ui.inbound}
            onAccept={ui.onAcceptTransfer}
            onReject={ui.onRejectTransfer}
          />
          <TransfersList
            outbound={ui.outbound}
            inbound={ui.inbound}
            onDismiss={ui.onDismissTransfer}
          />
          <PeerList
            peers={ui.peers}
            invitesIn={ui.invitesIn}
            invitesOut={ui.invitesOut}
            friends={ui.friends}
            onInvite={ui.onInvite}
            onSendFile={ui.onSendFile}
          />
        </>
      )
  }
}

interface PeerListProps {
  peers: PeerRecord[]
  invitesIn: string[]
  invitesOut: string[]
  friends: string[]
  onInvite: (peer: PeerRecord) => void
  onSendFile: (peer: PeerRecord, file: File) => void
}

function PeerList({ peers, invitesIn, invitesOut, friends, onInvite, onSendFile }: PeerListProps) {
  if (peers.length === 0) {
    return (
      <section className="card">
        <p className="muted">
          No other peers on the relay yet — open this URL in another tab to see
          another row appear.
        </p>
      </section>
    )
  }
  return (
    <section className="card">
      <h2>Other peers ({peers.length})</h2>
      <ul className="row-list">
        {peers.map((p) => {
          const peerHex = bytesToHex(p.ed25519Pub)
          // Render-state precedence:
          //   friend > incoming-invite > outgoing-invite > available
          // friend wins because mutual-friendship trumps any stale invite
          // state; incoming wins over outgoing because the IncomingInvites
          // section above is the action surface for that case.
          const isFriend = friends.includes(peerHex)
          const isInviteIn = invitesIn.includes(peerHex)
          const isInviteOut = invitesOut.includes(peerHex)
          return (
            <li key={peerHex} className="row">
              <span className="fingerprint fingerprint--small">
                {fingerprint(p.ed25519Pub)}
              </span>
              <span className="muted">
                at {p.ip}:{p.port}
              </span>
              <span className="spacer" />
              {isFriend && <span className="badge badge--success">Friend</span>}
              {isFriend && <SendFileButton peer={p} onSendFile={onSendFile} />}
              {!isFriend && isInviteIn && (
                <span className="muted">(see invite above)</span>
              )}
              {!isFriend && !isInviteIn && isInviteOut && (
                <button type="button" className="btn--small" disabled>
                  Pending…
                </button>
              )}
              {!isFriend && !isInviteIn && !isInviteOut && (
                <button
                  type="button"
                  className="btn--small btn--primary"
                  onClick={() => onInvite(p)}
                >
                  Invite
                </button>
              )}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

function IncomingInvites({
  invitesIn,
  friends,
  peers,
  onAccept,
  onReject,
}: {
  invitesIn: string[]
  friends: string[]
  peers: PeerRecord[]
  onAccept: (peerHex: string) => void
  onReject: (peerHex: string) => void
}) {
  // Filter out any invitesIn entry for a peer we already consider a
  // friend. The reciprocal-cleanup paths in sendAccept and the
  // accept-from handler keep these in sync, but this is the
  // last-line defense against any race or bug that leaves a stale
  // entry — without it, IncomingInvites would render Accept/Reject
  // for an established friendship.
  const renderable = invitesIn.filter((h) => !friends.includes(h))
  if (renderable.length === 0) return null
  return (
    <section className="card card--warning">
      <h2>
        Incoming invite{renderable.length > 1 ? 's' : ''} ({renderable.length})
      </h2>
      <ul className="row-list">
        {renderable.map((peerHex) => {
          // hexToBytes is well-defined for our hex input (always 64 chars,
          // produced by bytesToHex on the relay frame); the cost is per
          // render but trivial for typical invite-list sizes.
          const ed25519Pub = hexToBytes(peerHex)
          const peer = peers.find((p) => bytesEqual(p.ed25519Pub, ed25519Pub))
          return (
            <li key={peerHex} className="row">
              <span className="fingerprint fingerprint--small">
                {fingerprint(ed25519Pub)}
              </span>
              {peer ? (
                <span className="muted">
                  at {peer.ip}:{peer.port}
                </span>
              ) : (
                // Edge case: invite-from arrived before we saw peer-joined
                // for the sender, or after they peer-left. Reject still
                // works (it's just a relay-side directive that needs no
                // peer state), but Accept needs the peer's X25519 to
                // derive session keys — disable it until peer-joined
                // brings the record in. Without this gate the friendship
                // would be recorded with no keys and subsequent envelopes
                // would silently fail to decrypt.
                <span className="muted">(peer not in directory)</span>
              )}
              <span className="spacer" />
              <button
                type="button"
                className="btn--small btn--primary"
                onClick={() => onAccept(peerHex)}
                disabled={!peer}
                title={peer ? undefined : 'waiting for peer record'}
              >
                Accept
              </button>
              <button
                type="button"
                className="btn--small"
                onClick={() => onReject(peerHex)}
              >
                Reject
              </button>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

function NoticeList({
  notices,
  onDismiss,
}: {
  notices: FriendshipNotice[]
  onDismiss: (id: number) => void
}) {
  if (notices.length === 0) return null
  return (
    <section style={{ marginTop: '1.25rem' }}>
      {notices.map((n) => (
        <div key={n.id} className="notice">
          <span className="notice__text">{noticeText(n)}</span>
          <button
            type="button"
            className="btn--small btn--ghost"
            onClick={() => onDismiss(n.id)}
          >
            dismiss
          </button>
        </div>
      ))}
    </section>
  )
}

// SendFileButton wraps a hidden <input type="file"> in a styled
// <label>. Clicking the label triggers the input's native picker via
// the label-input association; selecting one or more files fires
// onChange, and we reset value="" so picking the same files again
// still triggers onChange. Per-friend instance: clicking opens the
// picker for that specific friend; multi-select fans out into one
// onSendFile call per file (each becomes an independent transfer
// with its own transferId, so the recipient gets one offer per file).
function SendFileButton({
  peer,
  onSendFile,
}: {
  peer: PeerRecord
  onSendFile: (peer: PeerRecord, file: File) => void
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  return (
    <label className="file-button">
      Send file
      <input
        ref={inputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={(e) => {
          const files = e.target.files
          if (files) {
            for (const f of Array.from(files)) onSendFile(peer, f)
          }
          // Reset so the next pick of the SAME file still fires onChange
          // (browsers de-dup against the previous selection otherwise).
          if (inputRef.current) inputRef.current.value = ''
        }}
      />
    </label>
  )
}

// IncomingTransferOffers shows the user's pending decision queue —
// transfers that arrived as transfer-offer envelopes but haven't been
// Accepted or Rejected yet. Clicking Accept sends transfer-accept and
// flips the inbound entry into 'streaming' state so subsequent chunks
// land. Clicking Reject sends transfer-reject and drops the entry.
function IncomingTransferOffers({
  inbound,
  onAccept,
  onReject,
}: {
  inbound: Record<string, InboundTransfer>
  onAccept: (transferIdHex: string) => void
  onReject: (transferIdHex: string) => void
}) {
  const offered = Object.values(inbound).filter((t) => t.status === 'offered')
  if (offered.length === 0) return null
  const largeWithoutDisk =
    !OPFS_OK && offered.some((t) => t.totalBytes > MEMORY_WARN_BYTES)
  return (
    <section className="card card--success">
      <h2>
        Incoming transfer{offered.length > 1 ? 's' : ''} ({offered.length})
      </h2>
      {largeWithoutDisk && (
        <p className="muted" style={{ marginBottom: '0.75rem' }}>
          On-disk browser storage (OPFS) needs a secure context (
          <code>https://</code> or <code>http://localhost</code>) — not plain{' '}
          <code>http://</code> on a LAN IP. Large accepts will stream into
          memory and may exhaust tab RAM; prefer the LemurPouch TUI (
          <code>--connect</code>) for multi‑GB files.
        </p>
      )}
      <ul className="row-list">
        {offered.map((t) => (
          <li key={t.transferIdHex} className="row">
            <span className="fingerprint fingerprint--small">
              {fingerprint(hexToBytes(t.peerHex))}
            </span>
            <span>wants to send</span>
            <strong>{t.filename}</strong>
            <span className="muted">({formatBytes(t.totalBytes)})</span>
            <span className="spacer" />
            <button
              type="button"
              className="btn--small btn--primary"
              onClick={() => onAccept(t.transferIdHex)}
            >
              Accept
            </button>
            <button
              type="button"
              className="btn--small"
              onClick={() => onReject(t.transferIdHex)}
            >
              Reject
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}

// TransferRow is the unified-shape display for one in-flight or
// completed transfer (sender or receiver). Produced by TransfersList
// from the outbound + inbound maps so both directions render with the
// same layout.
interface TransferRow {
  kind: 'in' | 'out'
  transferIdHex: string
  peerHex: string
  filename: string
  totalBytes: number
  doneBytes: number
  status: OutboundTransfer['status'] | InboundTransfer['status']
  // Set on inbound 'done' transfers — link target for the Save button.
  blobUrl?: string
  // Set on outbound 'rejected' transfers when the recipient included one.
  rejectReason?: string
  rateBps?: number
  memoryFallback?: boolean
  receiveWarning?: string
}

function TransfersList({
  outbound,
  inbound,
  onDismiss,
}: {
  outbound: Record<string, OutboundTransfer>
  inbound: Record<string, InboundTransfer>
  onDismiss: (kind: 'in' | 'out', transferIdHex: string) => void
}) {
  const rows: TransferRow[] = []
  for (const t of Object.values(outbound)) {
    rows.push({
      kind: 'out',
      transferIdHex: t.transferIdHex,
      peerHex: t.peerHex,
      filename: t.filename,
      totalBytes: t.totalBytes,
      doneBytes: t.sentBytes,
      status: t.status,
      rejectReason: t.rejectReason,
      rateBps: t.rateBps,
    })
  }
  for (const t of Object.values(inbound)) {
    // 'offered' is rendered by IncomingTransferOffers; skip here so we
    // don't double-render.
    if (t.status === 'offered') continue
    rows.push({
      kind: 'in',
      transferIdHex: t.transferIdHex,
      peerHex: t.peerHex,
      filename: t.filename,
      totalBytes: t.totalBytes,
      doneBytes: t.receivedBytes,
      status: t.status,
      blobUrl: t.blobUrl,
      rateBps: t.rateBps,
      memoryFallback: t.memoryFallback,
      receiveWarning: t.receiveWarning,
      rejectReason: t.rejectReason,
    })
  }
  if (rows.length === 0) return null
  // Newest at the top (transfer_id is random, so we sort by status
  // priority: in-flight first, then completed — keeps the user's
  // attention on what's still happening).
  const order: Record<TransferRow['status'], number> = {
    streaming: 0,
    'awaiting-decision': 1,
    done: 2,
    rejected: 3,
    aborted: 4,
    offered: 5, // unreachable here but the union demands it
  }
  rows.sort((a, b) => order[a.status] - order[b.status])

  return (
    <section className="card">
      <h2>Transfers ({rows.length})</h2>
      <div>
        {rows.map((r) => (
          <TransferRowView key={`${r.kind}:${r.transferIdHex}`} row={r} onDismiss={onDismiss} />
        ))}
      </div>
    </section>
  )
}

function TransferRowView({
  row: r,
  onDismiss,
}: {
  row: TransferRow
  onDismiss: (kind: 'in' | 'out', transferIdHex: string) => void
}) {
  const direction = r.kind === 'out' ? '→' : '←'
  const peerWords = fingerprint(hexToBytes(r.peerHex))
  const pct =
    r.totalBytes > 0
      ? Math.min(100, Math.floor((r.doneBytes / r.totalBytes) * 100))
      : r.status === 'done'
        ? 100
        : 0
  const showBar = r.status === 'streaming' || r.status === 'awaiting-decision'
  const settled =
    r.status === 'done' || r.status === 'rejected' || r.status === 'aborted'

  return (
    <div className="transfer-row">
      <div className="row">
        <span className="muted">
          {direction} {r.kind === 'out' ? 'to' : 'from'}
        </span>
        <span className="fingerprint fingerprint--small">{peerWords}</span>
        <strong>{r.filename}</strong>
        <span className="muted">
          {formatBytes(r.doneBytes)} / {formatBytes(r.totalBytes)}
        </span>
        {r.status === 'streaming' && r.rateBps !== undefined && r.rateBps > 0 && (
          <span className="muted">
            {formatRate(r.rateBps)}
            {' · ETA '}
            {formatEta(etaSeconds(r.totalBytes - r.doneBytes, r.rateBps))}
          </span>
        )}
        <span className="spacer" />
        <TransferStatusBadge status={r.status} />
      </div>
      {showBar && (
        <div className="progress" aria-label="progress">
          <div
            className={
              r.kind === 'in' ? 'progress__fill progress__fill--success' : 'progress__fill'
            }
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
      {r.status === 'streaming' && r.receiveWarning && (
        <p className="muted" style={{ marginTop: '0.3rem' }}>
          {r.receiveWarning}
        </p>
      )}
      {r.memoryFallback &&
        r.status === 'streaming' &&
        !r.receiveWarning &&
        r.totalBytes >= MEMORY_WARN_BYTES && (
          <p className="muted" style={{ marginTop: '0.3rem' }}>
            Large receive in memory (OPFS unavailable) — may use a lot of RAM.
          </p>
        )}
      {r.status === 'rejected' && r.rejectReason && (
        <p className="muted" style={{ marginTop: '0.3rem' }}>
          Reason: {r.rejectReason}
        </p>
      )}
      {r.status === 'aborted' && r.rejectReason && (
        <p className="muted" style={{ marginTop: '0.3rem' }}>
          {r.rejectReason}
        </p>
      )}
      {settled && (
        <div className="row" style={{ marginTop: '0.5rem' }}>
          {r.kind === 'in' && r.status === 'done' && r.blobUrl && (
            <a href={r.blobUrl} download={r.filename}>
              Save
            </a>
          )}
          <span className="spacer" />
          <button
            type="button"
            className="btn--small btn--ghost"
            onClick={() => onDismiss(r.kind, r.transferIdHex)}
          >
            dismiss
          </button>
        </div>
      )}
    </div>
  )
}

function TransferStatusBadge({ status }: { status: TransferRow['status'] }) {
  const variants: Record<TransferRow['status'], string> = {
    streaming: 'badge--accent',
    'awaiting-decision': 'badge--warning',
    done: 'badge--success',
    rejected: 'badge--danger',
    aborted: 'badge--neutral',
    offered: 'badge--warning', // unreachable here but the union demands it
  }
  return <span className={`badge ${variants[status]}`}>{status}</span>
}

// ThemeToggle flips between light and dark by writing data-theme="…"
// onto <html> and persisting the choice in a cookie. Initial state
// follows the OS via prefers-color-scheme; the first click pins the
// opposite mode and from then on the user's choice wins until the
// cookie expires (1 year) or the user clears it. Hidden from screen
// readers via aria-pressed + aria-label so the only thing announced
// is "Switch to dark/light mode". Cookie-read logic is mirrored in
// index.html's pre-hydration script — keep them in sync.
type ThemeChoice = 'light' | 'dark' | null // null = follow system

const THEME_COOKIE = 'theme'
const THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 // 1 year

function readStoredTheme(): ThemeChoice {
  if (typeof document === 'undefined') return null
  const re = new RegExp(`(?:^|;\\s*)${THEME_COOKIE}=(light|dark)(?:;|$)`)
  const match = document.cookie.match(re)
  return match ? (match[1] as 'light' | 'dark') : null
}

function writeStoredTheme(theme: ThemeChoice): void {
  if (typeof document === 'undefined') return
  const base = `${THEME_COOKIE}=`
  const attrs = '; Path=/; SameSite=Lax'
  if (theme === null) {
    document.cookie = `${base}; Max-Age=0${attrs}`
  } else {
    document.cookie = `${base}${theme}; Max-Age=${THEME_COOKIE_MAX_AGE}${attrs}`
  }
}

function applyThemeAttribute(theme: ThemeChoice): void {
  if (typeof document === 'undefined') return
  if (theme === null) {
    document.documentElement.removeAttribute('data-theme')
  } else {
    document.documentElement.setAttribute('data-theme', theme)
  }
}

function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeChoice>(readStoredTheme)

  useEffect(() => {
    applyThemeAttribute(theme)
    writeStoredTheme(theme)
  }, [theme])

  // Determine the currently-rendered scheme so we can show the icon
  // representing the *destination* of a click (sun = "switch to light",
  // moon = "switch to dark").
  const prefersDark =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  const effective: 'light' | 'dark' = theme ?? (prefersDark ? 'dark' : 'light')
  const next: 'light' | 'dark' = effective === 'dark' ? 'light' : 'dark'

  return (
    <button
      type="button"
      className="btn--icon btn--ghost"
      onClick={() => setTheme(next)}
      title={`Switch to ${next} mode`}
      aria-label={`Switch to ${next} mode`}
      aria-pressed={effective === 'dark'}
    >
      {effective === 'dark' ? <SunIcon /> : <MoonIcon />}
    </button>
  )
}

function SunIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </svg>
  )
}

function MoonIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  )
}

// noticeText composes the user-facing notification copy. Each branch
// mirrors a wireproto.TypeXxx discriminator; the assertNever default makes
// adding a new variant to FriendshipNotice['kind'] without a case here a
// TypeScript error rather than a silent undefined return.
function noticeText(n: FriendshipNotice): string {
  const words = fingerprint(hexToBytes(n.peerHex))
  switch (n.kind) {
    case TYPE_ACCEPT_FROM:
      return `${words} accepted your invite — you're now friends.`
    case TYPE_REJECT_FROM:
      return `${words} rejected your invite.`
    case TYPE_INVITE_DEFERRED:
      return `Your queued invite to ${words} is now active.`
    case TYPE_INVITE_AUTO_REJECTED:
      return `Your invite was auto-rejected: ${words} (or another peer at their IP) previously rejected an invite from your IP.`
    default:
      assertNever(n.kind)
  }
}

// closedMessage renders a human-readable disconnect message. Common codes
// get tailored copy; 1008 in particular is the Go relay's "replaced by
// newer connection" signal.
function closedMessage(code: number, reason: string): string {
  switch (code) {
    case CLOSE_NORMAL:
      return 'Disconnected — the relay shut down or your tab is closing.'
    case CLOSE_GOING_AWAY:
      return 'Disconnected — the relay went away.'
    case CLOSE_ABNORMAL:
      return 'Disconnected — the network or relay dropped. Try refreshing.'
    case CLOSE_POLICY_VIOLATION:
      return (
        'Disconnected — your session was replaced by another connection of ' +
        'the same identity (this is likely the older tab; the newer tab is fine).'
      )
    default:
      return `Disconnected from relay (code ${code}${reason ? `: ${reason}` : ''}).`
  }
}

// errorMessage prefers a structured code over the raw message when the
// failure is a known protocol-level rejection. RelayClosedError is
// reformatted with closedMessage so a handshake-time close (e.g. the
// relay displacing a stale duplicate during the fast-reconnect window)
// gets the same friendly UI as a post-handshake close.
function errorMessage(err: unknown): string {
  if (err instanceof RelayClosedError) return closedMessage(err.code, err.reason)
  if (err instanceof RelayRejectedError) return `relay said: ${err.code} (${err.message})`
  if (err instanceof WireProtocolError) return err.message
  if (err instanceof Error) return err.message
  return String(err)
}

// isPeerBindingValid verifies that a peer's advertised X25519 key is
// signed by the same Ed25519 identity their fingerprint is derived from.
// Without this check the relay (or anyone in its position) could swap in
// a forged X25519 key while keeping the legitimate Ed25519 fingerprint,
// defeating the MITM resistance the binding signature exists to provide.
// See AGENTS.md "Transfer Flow" step 3 and crypto/index.ts verifyBinding.
// Logged at warn level so a tampering relay leaves a developer-console
// breadcrumb; the peer is silently dropped from the user-facing list
// because there's no UX yet for "the relay is misbehaving."
function isPeerBindingValid(peer: PeerRecord): boolean {
  if (verifyBinding(peer.ed25519Pub, peer.x25519Pub, peer.sigBinding)) return true
  console.warn(
    'dropping peer with invalid sig_binding (relay tampering or bug):',
    bytesToHex(peer.ed25519Pub).slice(0, 16),
  )
  return false
}

// upsertPeer replaces any existing entry with the same ed25519_pub and
// appends. Used by peer-joined: a re-announce of an existing identity
// (e.g. after a same-identity reconnect) updates IP/port atomically.
function upsertPeer(prev: PeerRecord[], peer: PeerRecord): PeerRecord[] {
  return [...prev.filter((p) => !bytesEqual(p.ed25519Pub, peer.ed25519Pub)), peer]
}

// dedupPeers keeps the last occurrence of any duplicate ed25519_pub in a
// peer-list payload. The Go relay shouldn't emit duplicates, but a
// defensive de-dup avoids React duplicate-key warnings if it ever does.
function dedupPeers(peers: PeerRecord[]): PeerRecord[] {
  const seen: PeerRecord[] = []
  for (const p of peers) {
    const idx = seen.findIndex((q) => bytesEqual(q.ed25519Pub, p.ed25519Pub))
    if (idx >= 0) seen.splice(idx, 1)
    seen.push(p)
  }
  return seen
}

// assertNever is a TypeScript exhaustiveness helper — receiving a value
// typed as `never` proves all union variants were handled. The throw is a
// runtime safety net in case a non-TS caller bypasses the type system.
function assertNever(x: never): never {
  throw new Error(`unhandled discovery variant: ${JSON.stringify(x)}`)
}

// bytesEqual is a constant-time-not-required byte comparison used purely
// for relay-echo sanity checks and peer-list bookkeeping. Deliberately
// local; the crypto module keeps its own internal helper.
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
