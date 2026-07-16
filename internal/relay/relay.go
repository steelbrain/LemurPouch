// Package relay implements the LemurPouch relay's HTTP+WebSocket server:
// the connection-handshake handler, the in-memory peer hub, and the route
// registration that main.go composes with the embedded frontend. See
// AGENTS.md "High-Level Architecture" and "Wire Protocol > Cleartext Control".
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/cryptoid"
	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// handshakeReadTimeout caps how long the relay will wait for the client's
// IdentifyMsg after sending a ChallengeMsg. A slow or non-responsive
// connection is dropped rather than holding a goroutine indefinitely.
//
// Stored as an atomic so tests in package relay can lower it (via
// atomic.Store) to exercise the timeout path without slowing the suite,
// and the read on the handshake path stays race-free under -race.
// Production code must not mutate it.
var handshakeReadTimeout atomic.Int64

func init() {
	handshakeReadTimeout.Store(int64(10 * time.Second))
}

// Hub holds the live peer map for a relay process. All state is in-memory
// and session-scoped — AGENTS.md "Session Lifetime" — so a relay restart
// drops every identity, friendship, and queued invite.
//
// broadcastMu serializes the discovery-side join and leave sequences so a
// leaver's peer-left can't interleave with a joiner's (snapshot → write
// peer-list → broadcast peer-joined). Without this serialization, a
// just-departed peer X could appear in joiner Y's snapshot, X's peer-left
// could be broadcast to Y BEFORE Y receives its peer-list, and Y's TS-side
// wholesale `setPeers(parsePeerList(...).peers)` would re-introduce X
// permanently. The mutex is held only across the snapshot+self-write+
// broadcast sequence — not across the per-target conn.Write fan-out, which
// runs concurrently to keep one slow peer from head-of-line-blocking
// others. broadcastMu is intentionally separate from mu (the peer-map
// lock) so reads of the peer map (e.g. PeerCount) aren't blocked by
// in-flight broadcasts.
//
// TODO: a stress test for the snapshot-vs-peer-left race would need a
// hub-internal hook between snapshot and write to be reliably reproducible;
// skipped for now.
type Hub struct {
	mu          sync.RWMutex
	peers       map[string]*Peer
	broadcastMu sync.Mutex
	// fm owns friendship state (per-IP queue, mutual-friendship set,
	// rejection log). Always non-nil; allocated by NewHub. Lowercase so
	// access is restricted to package relay; tests in this package can
	// introspect.
	fm *FriendshipManager
}

// Peer is a connected client that has completed the connection handshake.
//
// Record's slice fields (Ed25519Pub, X25519Pub, SigBinding) are treated as
// read-only after construction — mirroring cryptoid.Identity's "treat as
// read-only" convention. The hub does not deep-copy; callers must not
// mutate the underlying byte slices.
type Peer struct {
	Record wireproto.PeerRecord
	// conn is the underlying WebSocket. Used by (*Hub).add to close a
	// displaced peer, by (*Hub).broadcastExcept for peer-list /
	// peer-joined / peer-left fan-out, by FriendshipManager via
	// writeAsyncToIdentity for invite/accept/reject notifications, and
	// by (*Hub).forwardEnvelope for encrypted envelope routing.
	//
	// *websocket.Conn's Write methods are concurrency-safe per
	// coder/websocket's documentation, so multiple goroutines can fan
	// writes out without a per-peer mutex. We still serialize inside the
	// hub for read patterns (no concurrent Read on a single conn).
	conn *websocket.Conn
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{
		peers: make(map[string]*Peer),
		fm:    NewFriendshipManager(),
	}
}

// PeerCount returns the number of currently-connected peers. Mostly useful
// for tests and logging.
func (h *Hub) PeerCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.peers)
}

// add registers a peer in the hub. If a peer with the same ed25519_pub is
// already connected (e.g. a stale session whose TCP connection didn't drop
// cleanly), the older entry is replaced — the new connection wins, and the
// displaced peer's WebSocket is closed off the hub lock so the close
// handshake doesn't block other hub ops. The pointer-equality check in
// remove() prevents the displaced goroutine's deferred unregister from
// clobbering the new entry.
//
// Displacement is observed by other peers as a fresh peer-joined for the
// same identity with new IP/Port — there is no separate displacement
// notification. Receivers must be idempotent over peer-joined for an
// already-known identity (i.e. update the IP/Port in place).
//
// Broadcasts (peer-joined / peer-left / forwarded messages) must be queued
// for delivery outside h.mu — never call conn.Write while holding the hub
// lock, or one slow peer head-of-line-blocks every other message.
func (h *Hub) add(p *Peer) {
	key := hexKey(p.Record.Ed25519Pub)
	h.mu.Lock()
	displaced := h.peers[key]
	h.peers[key] = p
	h.mu.Unlock()
	if displaced != nil {
		go displaced.conn.Close(websocket.StatusPolicyViolation, "replaced by newer connection")
	}
}

// remove deletes a peer from the hub if (and only if) the entry currently
// points at this exact peer. This avoids the race where a fresh connection
// for the same identity replaces an old one (via add) and then the old
// goroutine's deferred remove unregisters the new entry.
//
// Returns true if the removal happened (we owned the entry); false if the
// entry was either absent or owned by a newer connection that displaced us.
// The caller uses this to decide whether to broadcast peer-left — a
// displaced peer must NOT announce its departure because the identity is
// still live via the new connection.
func (h *Hub) remove(p *Peer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hexKey(p.Record.Ed25519Pub)
	if h.peers[key] == p {
		delete(h.peers, key)
		return true
	}
	return false
}

// snapshot returns a copy of every peer's PeerRecord in the hub, optionally
// excluding one (typically the requesting peer's own key, so the receiver
// doesn't see its own row in the peer-list it just received). Snapshots
// happen under the read lock and the slice is returned to the caller —
// broadcasts and writes must happen outside the lock to avoid head-of-line
// blocking by a slow peer.
func (h *Hub) snapshot(excludeKey string) []wireproto.PeerRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]wireproto.PeerRecord, 0, len(h.peers))
	for k, p := range h.peers {
		if k == excludeKey {
			continue
		}
		out = append(out, p.Record)
	}
	return out
}

// broadcastWriteTimeout caps how long a single per-target broadcast write
// can block. Each goroutine spawned by broadcastExcept derives a fresh
// context.WithTimeout(context.Background(), broadcastWriteTimeout) so a
// flaky peer can't park a goroutine forever even if the caller's request
// context is canceled before the goroutine runs.
const broadcastWriteTimeout = 5 * time.Second

// broadcastExcept writes a JSON frame to every connected peer except one
// (typically the announcer of a peer-joined or the leaver of a peer-left).
// Writes happen concurrently per-target so a slow peer doesn't head-of-line-
// block the others. The function returns immediately after fan-out —
// broadcasts are best-effort, so we don't wait for individual targets to
// finish. Errors are logged but otherwise ignored; broken peers will be
// dropped by their own goroutine's disconnect path.
//
// Each per-target goroutine derives its own bounded context (rooted in
// context.Background, capped by broadcastWriteTimeout) rather than
// inheriting the caller's request context, because (a) the joiner's
// r.Context() can end before the fan-out goroutines finish, and (b) the
// leaver's deferred broadcast runs after r.Context() has already been
// canceled. The broadcastWriteTimeout is the only thing keeping a flaky
// peer from holding a goroutine indefinitely.
func (h *Hub) broadcastExcept(frame []byte, excludeKey string) {
	h.mu.RLock()
	targets := make([]*websocket.Conn, 0, len(h.peers))
	for k, p := range h.peers {
		if k == excludeKey {
			continue
		}
		targets = append(targets, p.conn)
	}
	h.mu.RUnlock()
	for _, c := range targets {
		go func(c *websocket.Conn) {
			writeCtx, cancel := context.WithTimeout(context.Background(), broadcastWriteTimeout)
			defer cancel()
			if err := c.Write(writeCtx, websocket.MessageText, frame); err != nil {
				log.Printf("hub broadcast write: %v", err)
			}
		}(c)
	}
}

// writeTo sends a single frame to the peer identified by hex(ed25519_pub).
// The peer lookup happens under the read lock; the conn is captured and the
// lock is released before the actual Write so a slow peer doesn't block hub
// ops. Returns an error if the peer is not connected or the write fails.
//
// This is the canonical single-target send helper — peer-list (in
// HandleWebSocket) and the upcoming friendship + envelope-routing layers all
// route through it so the lock-and-write encapsulation lives in one place.
//
// Callers are responsible for passing a bounded ctx — see the peer-list
// call site, which derives a context.WithTimeout(context.Background(),
// broadcastWriteTimeout) so a flaky target can't park a hub-wide critical
// section (the join sequence holds broadcastMu across this Write).
func (h *Hub) writeTo(ctx context.Context, key string, frame []byte) error {
	h.mu.RLock()
	p, ok := h.peers[key]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("writeTo: peer %s not connected", key)
	}
	return p.conn.Write(ctx, websocket.MessageText, frame)
}

func hexKey(b []byte) string { return hex.EncodeToString(b) }

// AcceptOptions returns the websocket.AcceptOptions the relay uses for
// incoming WebSocket upgrades.
//
// InsecureSkipVerify disables the same-origin check on the WebSocket
// upgrade. The relay is meant to be reached from arbitrary LAN clients
// (a browser visiting http://192.168.1.5:8080/ on another machine
// makes a WebSocket Origin that no fixed allowlist could enumerate),
// so origin checking would block the actual use case. The trade-off is
// that a malicious cross-origin page in a user's browser could open a
// WebSocket to a relay running on the same machine — but per
// AGENTS.md "MITM Resistance" the security guarantees ride entirely on
// fingerprint verification + per-friendship + per-transfer consent,
// none of which an Origin spoof can bypass: a malicious page would
// just appear as a fresh peer with a random fingerprint, which the
// human user has to verify out-of-band before accepting any invite.
func AcceptOptions() *websocket.AcceptOptions {
	return &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	}
}

// HandleWebSocket returns the /ws handler for the relay. The returned
// http.HandlerFunc is the server's only stateful endpoint.
func HandleWebSocket(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, AcceptOptions())
		if err != nil {
			log.Printf("ws accept from %s: %v", r.RemoteAddr, err)
			return
		}
		defer conn.CloseNow()

		// Cap inbound frames for the connection's lifetime. Sized to fit
		// the largest negotiated envelope: MaxChunkBytes raw chunk data
		// plus envelope header/tag + chunk header, with headroom
		// (wireproto.ReadLimit = 4 MiB). Trade-off: per-conn transient
		// buffer exposure is ReadLimit × connections; acceptable for a
		// LAN relay. See AGENTS.md "Flow Control & Negotiated Limits".
		conn.SetReadLimit(int64(wireproto.ReadLimit))

		ctx := r.Context()

		peer, err := handshake(ctx, conn, r.RemoteAddr)
		if err != nil {
			log.Printf("handshake from %s: %v", r.RemoteAddr, err)
			// Send a close frame so the client can distinguish a
			// relay-rejected handshake from a transport-level drop.
			// Best-effort: if the conn is already torn down, Close
			// returns an error we can safely ignore — the deferred
			// CloseNow above guarantees the underlying conn is closed.
			_ = conn.Close(websocket.StatusPolicyViolation, "handshake failed")
			return
		}

		hub.add(peer)
		selfKey := hexKey(peer.Record.Ed25519Pub)
		// Combined remove + friendship-cleanup + broadcast: only
		// announce peer-left if we actually owned the entry. A
		// displaced peer (same identity, newer connection won the
		// race) must NOT broadcast peer-left because the identity is
		// still live via the new connection. The friendship-state
		// cleanup is symmetric — a displaced peer's invites and
		// friendships still belong to the live connection's identity
		// (same ed25519_pub), so OnPeerDisconnect must only fire when
		// remove() reports we owned the entry.
		//
		// The peer-left broadcast is serialized against the join
		// sequence below via hub.broadcastMu so a leaver's peer-left
		// can't interleave with an in-flight (snapshot → write
		// peer-list → broadcast peer-joined). See Hub.broadcastMu.
		defer func() {
			if !hub.remove(peer) {
				return
			}
			hub.fm.OnPeerDisconnect(hub, peer.Record.Ed25519Pub)
			msg, err := wireproto.MarshalPeerLeft(wireproto.PeerLeftMsg{
				Ed25519Pub: peer.Record.Ed25519Pub,
			})
			if err != nil {
				log.Printf("marshal peer-left: %v", err)
				return
			}
			// broadcastExcept owns its own per-write timeout
			// (broadcastWriteTimeout); we don't need to pass a ctx
			// here, which is fine because r.Context() is already
			// canceled by the time this defer fires.
			hub.broadcastMu.Lock()
			hub.broadcastExcept(msg, selfKey)
			hub.broadcastMu.Unlock()
		}()

		log.Printf(
			"peer joined: %s (%s)",
			r.RemoteAddr, selfKey[:16],
		)

		// Discovery — AGENTS.md "Wire Protocol > Cleartext Control".
		//
		// Push the current peer-list to the new peer (excluding itself,
		// so the receiver doesn't have to filter), then broadcast a
		// peer-joined to every other peer.
		//
		// Ordering matters for peer-list vs peer-left: a peer X present
		// in the snapshot must not be told "X left" before this peer
		// receives its peer-list (otherwise the TS-side wholesale
		// setPeers(parsePeerList(...)) re-introduces X). hub.broadcastMu
		// guarantees this by serializing the join sequence (snapshot →
		// write peer-list → broadcast peer-joined) against any in-flight
		// peer-left broadcast.
		//
		// peer-list vs peer-joined ordering relative to each other is
		// NOT load-bearing — receivers must be idempotent over a
		// peer-joined for an identity already in their list — but doing
		// peer-list first means the new peer sees the world before it
		// announces itself.
		hub.broadcastMu.Lock()
		peerList, err := wireproto.MarshalPeerList(wireproto.PeerListMsg{
			Peers: hub.snapshot(selfKey),
		})
		if err != nil {
			log.Printf("marshal peer-list for %s: %v", r.RemoteAddr, err)
		} else {
			// Bound the peer-list write the same way broadcastExcept
			// bounds each fan-out write: a flaky new peer must not be
			// allowed to park broadcastMu (hub-wide for the join/leave
			// sequence) for longer than broadcastWriteTimeout. Rooted
			// in context.Background, not r.Context(), so a request ctx
			// that outlives broadcastWriteTimeout doesn't extend this
			// critical section. The caller's ctx isn't useful here —
			// we already own the conn and the timeout is the only
			// thing we care about.
			writeCtx, cancel := context.WithTimeout(context.Background(), broadcastWriteTimeout)
			writeErr := hub.writeTo(writeCtx, selfKey, peerList)
			cancel()
			if writeErr != nil {
				log.Printf("write peer-list to %s: %v", r.RemoteAddr, writeErr)
				hub.broadcastMu.Unlock()
				return
			}
		}

		peerJoined, err := wireproto.MarshalPeerJoined(wireproto.PeerJoinedMsg{Peer: peer.Record})
		if err != nil {
			log.Printf("marshal peer-joined for %s: %v", r.RemoteAddr, err)
		} else {
			// broadcastExcept derives its own per-target writeCtx
			// (broadcastWriteTimeout) so a flaky peer can't block
			// the fan-out goroutine forever, regardless of the
			// caller's ctx lifetime.
			hub.broadcastExcept(peerJoined, selfKey)
		}
		hub.broadcastMu.Unlock()

		// Park the connection: read each post-handshake frame and
		// dispatch by frame type. Text frames are friendship directives
		// (invite/accept/reject) handled by FriendshipManager. Binary
		// frames are encrypted envelopes — the relay forwards them
		// opaquely (AGENTS.md "Encrypted Envelopes"). Other frame types
		// (none today, but reserved by the WebSocket spec) are silently
		// dropped for forward compat.
		for {
			msgType, data, err := conn.Read(ctx)
			if err != nil {
				log.Printf(
					"peer %s (%s) disconnected: %v",
					r.RemoteAddr, hexKey(peer.Record.Ed25519Pub)[:16], err,
				)
				return
			}
			switch msgType {
			case websocket.MessageText:
				hub.fm.Dispatch(hub, peer, data)
			case websocket.MessageBinary:
				hub.forwardEnvelope(peer, data)
			}
		}
	}
}

// handshake runs the connection-time challenge/identify/welcome exchange
// described in AGENTS.md "Connection Handshake". On success the returned
// Peer carries the relay's view of the connected client (the IdentifyMsg
// fields plus the IP/port observed from remoteAddr).
func handshake(ctx context.Context, conn *websocket.Conn, remoteAddr string) (*Peer, error) {
	// 1. Send challenge.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	challenge, err := wireproto.MarshalChallenge(wireproto.ChallengeMsg{Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("marshal challenge: %w", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, challenge); err != nil {
		return nil, fmt.Errorf("write challenge: %w", err)
	}

	// 2. Read identify (with a bounded timeout so a stalled handshake
	// doesn't hold a goroutine forever).
	//
	// We deliberately do NOT pass a context-with-timeout to conn.Read:
	// coder/websocket's Read-timeout path calls c.close() on cancellation
	// (see github.com/coder/websocket/conn.go setupReadTimeout) which
	// tears down the TCP conn without sending a Close frame. Instead, we
	// arm a time.AfterFunc that calls conn.Close(StatusPolicyViolation,
	// ...) — that sends a real Close frame so the client can distinguish
	// a relay-rejected handshake from a transport-level drop. The Read
	// returns shortly after with the resulting close error.
	//
	// `closed` guards the timer's Close call against a late fire that
	// races with a successful Read: timer.Stop() returns false if the
	// AfterFunc goroutine already started, in which case the goroutine
	// would otherwise tear down the connection AFTER the handshake
	// succeeded — killing the welcome write that follows. Both sides
	// race for the CompareAndSwap: whichever wins owns the post-Read
	// behavior. If the timer goroutine wins, it issues conn.Close and
	// we surface a handshake-timeout error regardless of whether Read
	// happened to return data first; if Read wins, the timer's
	// CompareAndSwap fails and the goroutine returns without touching
	// the connection.
	var closed atomic.Bool
	timer := time.AfterFunc(time.Duration(handshakeReadTimeout.Load()), func() {
		if !closed.CompareAndSwap(false, true) {
			return
		}
		_ = conn.Close(websocket.StatusPolicyViolation, "handshake timeout")
	})
	msgType, data, err := conn.Read(ctx)
	mainWon := closed.CompareAndSwap(false, true)
	timer.Stop()
	if !mainWon {
		// Timer goroutine fired before we could claim ownership; it has
		// either initiated the close or is about to. Treat as timeout
		// regardless of what Read returned, and let the deferred
		// CloseNow in HandleWebSocket finish teardown.
		return nil, fmt.Errorf("read identify: handshake timeout")
	}
	if err != nil {
		// On timeout (or any other read error here), the deferred
		// CloseNow in HandleWebSocket drops the connection without
		// sending an ErrorMsg. The client sees a clean WebSocket
		// close. This is intentional: identifying-as-malicious peers
		// shouldn't get a courtesy reply.
		return nil, fmt.Errorf("read identify: %w", err)
	}
	if msgType != websocket.MessageText {
		sendError(ctx, conn, wireproto.ErrCodeMalformed, "expected text frame for identify")
		return nil, fmt.Errorf("expected text frame, got %s", msgType)
	}

	typeField, err := wireproto.PeekType(data)
	if err != nil {
		sendError(ctx, conn, wireproto.ErrCodeMalformed, "could not parse JSON")
		return nil, fmt.Errorf("peek type: %w", err)
	}
	if typeField != wireproto.TypeIdentify {
		sendError(ctx, conn, wireproto.ErrCodeMalformed,
			fmt.Sprintf("expected %q, got %q", wireproto.TypeIdentify, typeField))
		return nil, fmt.Errorf("expected %q, got %q", wireproto.TypeIdentify, typeField)
	}

	var identify wireproto.IdentifyMsg
	if err := json.Unmarshal(data, &identify); err != nil {
		sendError(ctx, conn, wireproto.ErrCodeMalformed, "unmarshal identify")
		return nil, fmt.Errorf("unmarshal identify: %w", err)
	}

	// 3. Verify both signatures. cryptoid's Verify functions are
	// length-safe — they return false rather than panicking on
	// malformed-length keys — so we don't need a separate length check.
	if !cryptoid.VerifyLiveness(identify.Ed25519Pub, nonce, identify.SigLiveness) {
		sendError(ctx, conn, wireproto.ErrCodeInvalidSignature, "sig_liveness verification failed")
		return nil, errors.New("sig_liveness verification failed")
	}
	if !cryptoid.VerifyBinding(identify.Ed25519Pub, identify.X25519Pub, identify.SigBinding) {
		sendError(ctx, conn, wireproto.ErrCodeInvalidSignature, "sig_binding verification failed")
		return nil, errors.New("sig_binding verification failed")
	}

	// 4. Build the peer record from the identified keys + observed remote
	// address. The IP and ephemeral port are the relay's view; the peer's
	// claim is irrelevant here.
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		sendError(ctx, conn, wireproto.ErrCodeInternal, "could not parse remote address")
		return nil, fmt.Errorf("split remote addr %q: %w", remoteAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		sendError(ctx, conn, wireproto.ErrCodeInternal, "could not parse remote address")
		return nil, fmt.Errorf("parse remote port %q: %w", portStr, err)
	}
	record := wireproto.PeerRecord{
		Ed25519Pub: identify.Ed25519Pub,
		X25519Pub:  identify.X25519Pub,
		SigBinding: identify.SigBinding,
		IP:         host,
		Port:       port,
	}

	// 5. Send welcome, advertising the max raw chunk size this relay will
	// forward so clients can negotiate above the legacy 64 KiB floor.
	welcome, err := wireproto.MarshalWelcome(wireproto.WelcomeMsg{
		You: record,
		Limits: &wireproto.WelcomeLimits{
			MaxChunkBytes: wireproto.MaxChunkBytes,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal welcome: %w", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, welcome); err != nil {
		return nil, fmt.Errorf("write welcome: %w", err)
	}

	return &Peer{Record: record, conn: conn}, nil
}

// sendError marshals and writes an ErrorMsg to the client. Errors here are
// best-effort — if the connection is already broken, there's nothing useful
// the relay can do beyond logging.
func sendError(ctx context.Context, conn *websocket.Conn, code, message string) {
	msg, err := wireproto.MarshalError(wireproto.ErrorMsg{Code: code, Message: message})
	if err != nil {
		log.Printf("marshal error msg: %v", err)
		return
	}
	if err := conn.Write(ctx, websocket.MessageText, msg); err != nil {
		log.Printf("write error msg: %v", err)
	}
}
