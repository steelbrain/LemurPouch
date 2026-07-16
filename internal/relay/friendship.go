package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// friendshipWriteTimeout caps how long a single async friendship-notification
// write to a peer is allowed to take before we give up. Writes are best-effort
// — a slow or broken peer will be cleaned up by their own goroutine's
// disconnect path — but we still want a bounded ceiling so a queue of
// goroutines can't accumulate against a wedged conn.
const friendshipWriteTimeout = 5 * time.Second

// FriendshipManager owns the per-(senderIP, recipient) invite state, the
// per-recipient rejection state, and the mutual-friendship set, as
// described in AGENTS.md "Consent Model > Tier 1: Friendship" and
// "Anti-Abuse: Per-IP Rate Limiting".
//
// All state is in-memory and session-scoped — AGENTS.md "Session Lifetime"
// — so a relay restart drops every invite, rejection, and friendship.
//
// The user-opt-in-from-log feature ("the recipient can review the log and
// opt-in to accept invites from that IP, which unblocks subsequent
// invites") is deferred to a future commit; today an IP that's been
// rejected stays rejected for the session.
type FriendshipManager struct {
	mu sync.Mutex

	// pairs maps (senderIP, recipient_ed25519_hex) → state. The IP is the
	// abuse-budget anchor: identity is session-scoped and easy to churn,
	// so multiple daemons sharing one IP collectively get one active
	// pending invite at a time.
	pairs map[pairInvitesKey]*pairState

	// friends is the set of established mutual friendships, keyed by
	// lex-sorted concatenation of the two ed25519 pubs.
	friends map[pairKey]struct{}
}

type pairInvitesKey struct {
	senderIP     string
	recipientHex string // hex(recipient.Ed25519Pub)
}

type pairState struct {
	// rejected is true once the recipient has rejected an invite from this
	// IP. Subsequent invites are auto-rejected and logged (AGENTS.md
	// "rejection log"), and the queue is cleared.
	rejected bool
	active   *pendingInvite
	queued   []*pendingInvite
}

type pendingInvite struct {
	sender           *Peer  // the inviter; sender.conn is the originating WebSocket
	recipientEd25519 []byte // copy of the target identity (so disconnect cleanup works)
}

// pairKey is the lex-sorted concatenation of two 32-byte ed25519 pubs.
// Using a fixed-size array makes it a comparable map key without
// allocating a wrapper struct.
type pairKey [64]byte

func makePairKey(a, b []byte) pairKey {
	var k pairKey
	if bytes.Compare(a, b) < 0 {
		copy(k[:32], a)
		copy(k[32:], b)
	} else {
		copy(k[:32], b)
		copy(k[32:], a)
	}
	return k
}

// NewFriendshipManager returns an empty FriendshipManager.
func NewFriendshipManager() *FriendshipManager {
	return &FriendshipManager{
		pairs:   make(map[pairInvitesKey]*pairState),
		friends: make(map[pairKey]struct{}),
	}
}

// Dispatch routes a post-handshake text frame from sender to the right
// FriendshipManager method based on its type discriminator. Unknown types
// are silently ignored so forward-compatibility additions to the wire
// protocol (e.g. an envelope frame from a future layer) don't disrupt
// connected peers. Malformed JSON is also ignored — we trust the per-conn
// SetReadLimit guard to keep these payloads small enough to parse.
func (fm *FriendshipManager) Dispatch(hub *Hub, sender *Peer, data []byte) {
	msgType, err := wireproto.PeekType(data)
	if err != nil {
		return
	}
	switch msgType {
	case wireproto.TypeInvite, wireproto.TypeAccept, wireproto.TypeReject:
		// Shape is identical for the three c2s directives: {type, to}.
		var msg wireproto.FriendshipDirective
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		switch msgType {
		case wireproto.TypeInvite:
			fm.HandleInvite(hub, sender, msg.To)
		case wireproto.TypeAccept:
			fm.HandleAccept(hub, sender, msg.To)
		case wireproto.TypeReject:
			fm.HandleReject(hub, sender, msg.To)
		}
	default:
		// Ignore everything else for forward compat.
	}
}

// AreFriends reports whether two peers have an established mutual
// friendship in this session. Symmetric in (a, b).
func (fm *FriendshipManager) AreFriends(a, b []byte) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	_, ok := fm.friends[makePairKey(a, b)]
	return ok
}

// HandleInvite processes an `invite` directive from sender targeting
// recipientEd25519. Self-invites and invites to non-connected peers are
// dropped silently. Per AGENTS.md "Per-IP Rate Limiting":
//   - If sender's IP has previously had an invite to this recipient
//     rejected, the new invite is auto-rejected and logged: an
//     invite-auto-rejected notification flows back to sender.
//   - If there's already an active pending invite from this IP to this
//     recipient, the new invite is queued; sender hears nothing yet.
//   - Otherwise the invite becomes active and an invite-from notification
//     is forwarded to recipient.
func (fm *FriendshipManager) HandleInvite(hub *Hub, sender *Peer, recipientEd25519 []byte) {
	if len(recipientEd25519) != 32 || bytes.Equal(sender.Record.Ed25519Pub, recipientEd25519) {
		return
	}

	key := pairInvitesKey{
		senderIP:     sender.Record.IP,
		recipientHex: hex.EncodeToString(recipientEd25519),
	}

	fm.mu.Lock()
	// Look up the recipient *under* fm.mu. OnPeerDisconnect also runs under
	// fm.mu, so this serializes "is recipient connected?" with "drop pair
	// states for recipient", closing the race where recipient disconnects
	// between an unprotected lookup and our pair-state mutation (which
	// would orphan the new state — OnPeerDisconnect already ran). The lock
	// order is fm.mu then hub.mu (RLock); no other code path takes them in
	// the reverse order.
	recipient := hub.lookup(recipientEd25519)
	if recipient == nil {
		fm.mu.Unlock()
		return // recipient not connected; silently drop
	}
	if _, ok := fm.friends[makePairKey(sender.Record.Ed25519Pub, recipientEd25519)]; ok {
		fm.mu.Unlock()
		return // already friends; no-op
	}
	// Cross-bucket dedup by sender identity. fm.pairs is bucketed by
	// (senderIP, recipientHex), so a same-identity reconnect from a new
	// IP would otherwise create a parallel bucket containing a SECOND
	// in-flight invite from the same identity to the same recipient.
	// Both buckets' actives would surface to the recipient, and accepting
	// either would orphan the other bucket's active — blocking later
	// invites from other senders at the orphan's IP. Identity is
	// ed25519_pub (AGENTS.md "Reconnect Rules"), so dedup at that level.
	recipientHex := key.recipientHex
	for k, s := range fm.pairs {
		if k.recipientHex != recipientHex {
			continue
		}
		if s.active != nil && bytes.Equal(s.active.sender.Record.Ed25519Pub, sender.Record.Ed25519Pub) {
			fm.mu.Unlock()
			return
		}
		for _, q := range s.queued {
			if bytes.Equal(q.sender.Record.Ed25519Pub, sender.Record.Ed25519Pub) {
				fm.mu.Unlock()
				return
			}
		}
	}
	state := fm.pairs[key]
	if state == nil {
		state = &pairState{}
		fm.pairs[key] = state
	}
	invite := &pendingInvite{sender: sender, recipientEd25519: append([]byte(nil), recipientEd25519...)}

	switch {
	case state.rejected:
		fm.mu.Unlock()
		// "invite-auto-rejected" tells the sender their invite was
		// dropped because of a prior rejection from this recipient.
		// "from" is the recipient (the originator of the rejection).
		// Re-resolve the sender's conn at write time via
		// writeAsyncToIdentity: between this Unlock and the goroutine
		// running, a same-identity reconnect could displace
		// sender.conn with a fresh WebSocket, and writing through the
		// captured pointer would land on the closed old conn.
		writeAsyncToIdentity(hub, sender.Record.Ed25519Pub, mustMarshalInviteAutoRejected(recipientEd25519))
		return
	case state.active != nil:
		// Queue. Sender hears nothing yet; they'll get invite-deferred
		// when this becomes the next active invite (after the current
		// active is accepted) or invite-auto-rejected (if the current
		// active is rejected).
		// (Same-sender dedup happens above the switch — by the time we
		// get here, the new invite is from an identity that is not
		// already active or queued for this recipient.)
		state.queued = append(state.queued, invite)
		fm.mu.Unlock()
		return
	default:
		state.active = invite
		fm.mu.Unlock()
		// Same displacement-race rationale as the auto-rejected path
		// above: re-resolve the recipient's conn at write time.
		writeAsyncToIdentity(hub, recipientEd25519, mustMarshalInviteFrom(sender.Record.Ed25519Pub))
	}
}

// HandleAccept processes an `accept` directive from responder targeting
// originatorEd25519. Establishes the friendship, forwards accept-from to
// the originator, and surfaces the next queued invite from the same
// (originatorIP, responder) pair (if any) as the new active invite.
func (fm *FriendshipManager) HandleAccept(hub *Hub, responder *Peer, originatorEd25519 []byte) {
	fm.handleResponse(hub, responder, originatorEd25519, true)
}

// HandleReject processes a `reject` directive. Forwards reject-from to
// the originator, marks the (originatorIP, responder) pair as rejected so
// future invites from that IP are auto-rejected, and auto-rejects every
// currently-queued invite (each gets invite-auto-rejected).
func (fm *FriendshipManager) HandleReject(hub *Hub, responder *Peer, originatorEd25519 []byte) {
	fm.handleResponse(hub, responder, originatorEd25519, false)
}

func (fm *FriendshipManager) handleResponse(hub *Hub, responder *Peer, originatorEd25519 []byte, accept bool) {
	if len(originatorEd25519) != 32 {
		return
	}

	// Each enqueued write is keyed by recipient identity (not conn) so the
	// final dispatch below can re-resolve to the *current* live conn via
	// writeAsyncToIdentity. Capturing conns here would be displacement-
	// unsafe: a same-identity reconnect between this enqueue and the
	// post-unlock dispatch would leave us writing to the closed old conn,
	// silently dropping the friendship notification.
	type asyncWrite struct {
		identity []byte
		frame    []byte
	}
	var writes []asyncWrite

	fm.mu.Lock()
	// Look up the originator under fm.mu so OnPeerDisconnect (also under
	// fm.mu) can't run between lookup and our state read. The returned
	// *Peer is used only as a "is the originator still connected" gate;
	// we never capture its conn or its current IP. The conn re-resolution
	// happens at write dispatch time via writeAsyncToIdentity.
	if hub.lookup(originatorEd25519) == nil {
		fm.mu.Unlock()
		return // originator gone; nothing to forward
	}

	// Find the pair-state holding the active invite from this originator
	// to this responder. The state's senderIP key is whatever the
	// originator's IP was AT INVITE TIME — looking it up by the
	// originator's CURRENT Peer.IP misses the entry whenever the
	// originator reconnected from a different IP since invite time.
	// Per AGENTS.md "Reconnect Rules" (post identity-model fix), a
	// same-key reconnect from any IP is the same peer, so accept/reject
	// must locate the in-flight invite by identity.
	recipientHex := hex.EncodeToString(responder.Record.Ed25519Pub)
	var state *pairState
	for k, s := range fm.pairs {
		if k.recipientHex != recipientHex {
			continue
		}
		if s.active != nil && bytes.Equal(s.active.sender.Record.Ed25519Pub, originatorEd25519) {
			state = s
			break
		}
	}
	if state == nil {
		// No matching active invite — accept/reject without a pending
		// invite from this originator is a no-op. Covers the
		// already-friends case (active was cleared on prior accept) and
		// the post-disconnect-of-original-sender case.
		fm.mu.Unlock()
		return
	}

	if accept {
		// Establish friendship.
		fm.friends[makePairKey(responder.Record.Ed25519Pub, originatorEd25519)] = struct{}{}
		writes = append(writes, asyncWrite{
			identity: originatorEd25519,
			frame:    mustMarshalAcceptFrom(responder.Record.Ed25519Pub),
		})
		// promoteNext clears state.active and surfaces the next queued
		// invite (if any) as the new active. Skips queued invites whose
		// sender is now already friends with `recipient` (e.g. the
		// sender we just accepted had stacked a duplicate before
		// HandleInvite's dedup landed). A stale promote would surface
		// a bogus invite-from for an established friendship and block
		// subsequent same-IP invites from other senders behind it.
		promoteNext := func(st *pairState, recipient []byte) {
			st.active = nil
			for len(st.queued) > 0 {
				next := st.queued[0]
				// Clear the head slot before reslicing so the
				// displaced *pendingInvite (and the *Peer it pins)
				// can be GC'd promptly — the underlying array would
				// otherwise retain the pointer past len(st.queued).
				st.queued[0] = nil
				st.queued = st.queued[1:]
				if _, alreadyFriends := fm.friends[makePairKey(next.sender.Record.Ed25519Pub, recipient)]; alreadyFriends {
					continue
				}
				st.active = next
				writes = append(writes, asyncWrite{
					identity: recipient,
					frame:    mustMarshalInviteFrom(next.sender.Record.Ed25519Pub),
				})
				writes = append(writes, asyncWrite{
					identity: next.sender.Record.Ed25519Pub,
					frame:    mustMarshalInviteDeferred(recipient),
				})
				break
			}
		}
		promoteNext(state, responder.Record.Ed25519Pub)
		// Reciprocal cleanup: if responder had an in-flight invite to
		// originator (the "I invited them too" case), clear it here so
		// the now-moot active doesn't block later same-IP invites to
		// originator behind a friendship that's already established.
		// Per cross-bucket dedup in HandleInvite at most one bucket
		// holds (recipientHex=hex(originator), active.sender=responder),
		// so the iteration breaks on the first match.
		originatorHex := hex.EncodeToString(originatorEd25519)
		for k, s := range fm.pairs {
			if k.recipientHex != originatorHex {
				continue
			}
			if s.active != nil && bytes.Equal(s.active.sender.Record.Ed25519Pub, responder.Record.Ed25519Pub) {
				promoteNext(s, originatorEd25519)
				break
			}
		}
		// Don't delete the state even if everything is empty — accepted
		// pairs leave a friendship behind that subsequent invites from
		// the same IP need to dedupe against.
	} else {
		// Reject. Forward to originator, mark IP rejected, auto-reject
		// every queued invite.
		writes = append(writes, asyncWrite{
			identity: originatorEd25519,
			frame:    mustMarshalRejectFrom(responder.Record.Ed25519Pub),
		})
		state.rejected = true
		state.active = nil
		queued := state.queued
		state.queued = nil
		for _, q := range queued {
			writes = append(writes, asyncWrite{
				identity: q.sender.Record.Ed25519Pub,
				frame:    mustMarshalInviteAutoRejected(responder.Record.Ed25519Pub),
			})
		}
	}
	fm.mu.Unlock()

	for _, w := range writes {
		writeAsyncToIdentity(hub, w.identity, w.frame)
	}
}

// OnPeerDisconnect drops every reference to a peer that has gone away:
// established friendships involving them, pair states where they were
// the recipient, and active or queued invites where they were the sender.
//
// When the disconnected peer was the active sender of a pair-state and
// the queue still has surviving non-already-friends entries, promote
// the next one to active and emit invite-from (to the recipient) +
// invite-deferred (to the new active sender). Without this, queued
// senders behind the dropped one sit in "Pending..." indefinitely with
// no invite-from ever reaching the recipient.
func (fm *FriendshipManager) OnPeerDisconnect(hub *Hub, peerEd25519 []byte) {
	if len(peerEd25519) != 32 {
		return
	}
	peerHex := hex.EncodeToString(peerEd25519)

	type asyncWrite struct {
		identity []byte
		frame    []byte
	}
	var writes []asyncWrite

	fm.mu.Lock()

	for k := range fm.friends {
		if bytes.Equal(k[:32], peerEd25519) || bytes.Equal(k[32:], peerEd25519) {
			delete(fm.friends, k)
		}
	}

	for k, state := range fm.pairs {
		// Drop the entire state if the recipient disconnected.
		if k.recipientHex == peerHex {
			delete(fm.pairs, k)
			continue
		}
		// Was the active sender this peer? Track separately so the
		// promote step below only runs when the active was cleared
		// by THIS disconnect (not because some other path had
		// already cleared it).
		activeWasDisconnected := state.active != nil &&
			bytes.Equal(state.active.sender.Record.Ed25519Pub, peerEd25519)
		if activeWasDisconnected {
			state.active = nil
		}
		// Filter the queue in place. The trailing slots after the new
		// length still hold pointers into the backing array, so zero
		// them out before reslicing — otherwise the dropped peer's
		// *Peer (and through it the *websocket.Conn) stays reachable
		// from this state until the next queue churn or recipient
		// disconnect, defeating GC.
		filtered := state.queued[:0]
		for _, q := range state.queued {
			if !bytes.Equal(q.sender.Record.Ed25519Pub, peerEd25519) {
				filtered = append(filtered, q)
			}
		}
		for i := len(filtered); i < len(state.queued); i++ {
			state.queued[i] = nil
		}
		state.queued = filtered

		if activeWasDisconnected {
			// The recipientHex was created by hex.EncodeToString so a
			// decode failure is structurally impossible; ignore the
			// error and skip the promote on the off chance.
			recipientBytes, _ := hex.DecodeString(k.recipientHex)
			for len(state.queued) > 0 && recipientBytes != nil {
				next := state.queued[0]
				state.queued[0] = nil
				state.queued = state.queued[1:]
				if _, ok := fm.friends[makePairKey(next.sender.Record.Ed25519Pub, recipientBytes)]; ok {
					continue
				}
				state.active = next
				writes = append(writes, asyncWrite{
					identity: recipientBytes,
					frame:    mustMarshalInviteFrom(next.sender.Record.Ed25519Pub),
				})
				writes = append(writes, asyncWrite{
					identity: next.sender.Record.Ed25519Pub,
					frame:    mustMarshalInviteDeferred(recipientBytes),
				})
				break
			}
		}

		// Garbage-collect empty non-rejected states.
		if state.active == nil && len(state.queued) == 0 && !state.rejected {
			delete(fm.pairs, k)
		}
	}
	fm.mu.Unlock()

	for _, w := range writes {
		writeAsyncToIdentity(hub, w.identity, w.frame)
	}
}

// writeAsyncToIdentity dispatches a WebSocket write to whatever conn
// is currently registered for the given identity. The hub.lookup
// happens INSIDE the goroutine so a same-identity displacement (a
// fresh connection replacing the *Peer between the caller's lookup
// and the actual write — see Hub.add in relay.go) is observed and
// the notification hits the live conn rather than the closed
// displaced one. If the identity is no longer registered at write
// time, the notification is silently dropped.
//
// The caller's request ctx is deliberately NOT used — friendship
// notifications cross peer boundaries (e.g. an accept-from forwarded
// to the originator inside the responder's Dispatch goroutine), so
// tying the write to the dispatching peer's request ctx would let
// their disconnect cancel a write that's still useful to the
// recipient. We use a fresh background context with
// friendshipWriteTimeout instead, mirroring the peer-left broadcast
// pattern in HandleWebSocket's defer chain.
func writeAsyncToIdentity(hub *Hub, ed25519Pub []byte, frame []byte) {
	// Defensive copy: the caller's []byte may be backed by a buffer
	// the closure shouldn't pin / racing readers shouldn't observe
	// after we exit. 32 bytes is cheap.
	idCopy := append([]byte(nil), ed25519Pub...)
	go func() {
		peer := hub.lookup(idCopy)
		if peer == nil {
			return // identity gone; drop the notification
		}
		ctx, cancel := context.WithTimeout(context.Background(), friendshipWriteTimeout)
		defer cancel()
		if err := peer.conn.Write(ctx, websocket.MessageText, frame); err != nil {
			log.Printf("friendship write: %v", err)
		}
	}()
}

// lookup returns the peer registered with the given ed25519_pub, or nil
// if no such peer is connected. Defined here (rather than relay.go) so the
// friendship layer can land in its own file without touching the
// connection-handshake/discovery code; methods are file-agnostic in Go.
func (h *Hub) lookup(ed25519Pub []byte) *Peer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.peers[hexKey(ed25519Pub)]
}

// must* helpers panic on marshal failure — these wireproto helpers can
// only fail if encoding/json itself can't marshal a primitive struct,
// which is functionally impossible. Avoiding the err-return boilerplate
// keeps the call sites in HandleInvite/HandleAccept/HandleReject clean.
func mustMarshalInviteFrom(from []byte) []byte {
	b, err := wireproto.MarshalInviteFrom(from)
	if err != nil {
		panic(err)
	}
	return b
}

func mustMarshalAcceptFrom(from []byte) []byte {
	b, err := wireproto.MarshalAcceptFrom(from)
	if err != nil {
		panic(err)
	}
	return b
}

func mustMarshalRejectFrom(from []byte) []byte {
	b, err := wireproto.MarshalRejectFrom(from)
	if err != nil {
		panic(err)
	}
	return b
}

func mustMarshalInviteDeferred(from []byte) []byte {
	b, err := wireproto.MarshalInviteDeferred(from)
	if err != nil {
		panic(err)
	}
	return b
}

func mustMarshalInviteAutoRejected(from []byte) []byte {
	b, err := wireproto.MarshalInviteAutoRejected(from)
	if err != nil {
		panic(err)
	}
	return b
}
