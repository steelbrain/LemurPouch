package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/cryptoid"
	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// startTestRelay returns a ws:// URL pointing at a fresh in-process relay,
// the hub it owns, and registers cleanup with t.
func startTestRelay(t *testing.T) (string, *Hub) {
	t.Helper()
	hub := NewHub()
	srv := httptest.NewServer(HandleWebSocket(hub))
	t.Cleanup(srv.Close)
	// strings.Replace (not TrimPrefix-based concat) so a future port to
	// httptest.NewTLSServer produces "wss://..." rather than "wss://s://...".
	return strings.Replace(srv.URL, "http", "ws", 1), hub
}

// dialRelay opens a WebSocket connection to the test relay and returns the
// connection plus a context with a generous timeout. The conn is closed on
// test cleanup.
func dialRelay(t *testing.T, wsURL string) (context.Context, *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return ctx, conn
}

// readChallenge reads the relay's first message and asserts it's a ChallengeMsg.
func readChallenge(t *testing.T, ctx context.Context, conn *websocket.Conn) wireproto.ChallengeMsg {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("challenge frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypeChallenge {
		t.Fatalf("first message type = %q, want %q\nraw: %s", got, wireproto.TypeChallenge, data)
	}
	var msg wireproto.ChallengeMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	if len(msg.Nonce) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(msg.Nonce))
	}
	return msg
}

// sendIdentify marshals and sends the IdentifyMsg over the connection.
func sendIdentify(t *testing.T, ctx context.Context, conn *websocket.Conn, msg wireproto.IdentifyMsg) {
	t.Helper()
	data, err := wireproto.MarshalIdentify(msg)
	if err != nil {
		t.Fatalf("marshal identify: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write identify: %v", err)
	}
}

// buildIdentify constructs a fully-signed IdentifyMsg for the given identity
// and nonce. Mirrors what a real client does after receiving the challenge.
func buildIdentify(id *cryptoid.Identity, nonce []byte) wireproto.IdentifyMsg {
	return wireproto.IdentifyMsg{
		Ed25519Pub:  id.Ed25519Pub,
		X25519Pub:   id.X25519Pub.Bytes(),
		SigLiveness: id.SignLiveness(nonce),
		SigBinding:  id.SignBinding(),
	}
}

func TestHandshakeSuccess(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	if got := hub.PeerCount(); got != 0 {
		t.Fatalf("PeerCount before connect = %d, want 0", got)
	}

	ctx, conn := dialRelay(t, wsURL)

	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	challenge := readChallenge(t, ctx, conn)
	sendIdentify(t, ctx, conn, buildIdentify(id, challenge.Nonce))

	// Expect a welcome.
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("welcome frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypeWelcome {
		t.Fatalf("post-identify message type = %q, want %q\nraw: %s", got, wireproto.TypeWelcome, data)
	}

	var welcome wireproto.WelcomeMsg
	if err := json.Unmarshal(data, &welcome); err != nil {
		t.Fatalf("unmarshal welcome: %v", err)
	}
	if !bytes.Equal(welcome.You.Ed25519Pub, id.Ed25519Pub) {
		t.Errorf("welcome.You.Ed25519Pub mismatch")
	}
	if !bytes.Equal(welcome.You.X25519Pub, id.X25519Pub.Bytes()) {
		t.Errorf("welcome.You.X25519Pub mismatch")
	}
	if welcome.You.IP == "" {
		t.Errorf("welcome.You.IP is empty")
	}
	if welcome.You.Port == 0 {
		t.Errorf("welcome.You.Port is 0")
	}

	// Hub should now have the peer registered. Race-resilient poll: the
	// relay registers after sending welcome, so by the time Read returns
	// it's almost certainly there, but a brief retry handles scheduler jitter.
	deadline := time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 1 {
		t.Fatalf("PeerCount after welcome = %d, want 1", got)
	}

	// Closing the connection should drop the peer from the hub.
	conn.Close(websocket.StatusNormalClosure, "")
	deadline = time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after close = %d, want 0", got)
	}
}

func TestHandshakeRejectsTamperedSigLiveness(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctx, conn := dialRelay(t, wsURL)

	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	challenge := readChallenge(t, ctx, conn)

	identify := buildIdentify(id, challenge.Nonce)
	identify.SigLiveness[0] ^= 0x01 // flip a bit
	sendIdentify(t, ctx, conn, identify)

	expectErrorMsg(t, ctx, conn, wireproto.ErrCodeInvalidSignature)
	if got := hub.PeerCount(); got != 0 {
		t.Errorf("PeerCount after rejected handshake = %d, want 0", got)
	}
}

func TestHandshakeRejectsTamperedSigBinding(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctx, conn := dialRelay(t, wsURL)

	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	challenge := readChallenge(t, ctx, conn)

	identify := buildIdentify(id, challenge.Nonce)
	identify.SigBinding[0] ^= 0x01
	sendIdentify(t, ctx, conn, identify)

	expectErrorMsg(t, ctx, conn, wireproto.ErrCodeInvalidSignature)
	if got := hub.PeerCount(); got != 0 {
		t.Errorf("PeerCount after rejected handshake = %d, want 0", got)
	}
}

func TestHandshakeRejectsMalformedJSON(t *testing.T) {
	wsURL, _ := startTestRelay(t)
	ctx, conn := dialRelay(t, wsURL)
	_ = readChallenge(t, ctx, conn)

	if err := conn.Write(ctx, websocket.MessageText, []byte("{not json")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	expectErrorMsg(t, ctx, conn, wireproto.ErrCodeMalformed)
}

func TestHandshakeRejectsWrongMessageType(t *testing.T) {
	wsURL, _ := startTestRelay(t)
	ctx, conn := dialRelay(t, wsURL)
	_ = readChallenge(t, ctx, conn)

	// A welcome message is something only the relay should send; if the
	// client sends one as its first message after challenge, the relay
	// should reject it as malformed (expected an identify).
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"welcome"}`)); err != nil {
		t.Fatalf("write wrong-type: %v", err)
	}
	expectErrorMsg(t, ctx, conn, wireproto.ErrCodeMalformed)
}

// TestHandshakeReadTimeout asserts the relay drops a connection that
// receives the challenge but never sends an IdentifyMsg, within the
// configured handshakeReadTimeout.
func TestHandshakeReadTimeout(t *testing.T) {
	original := handshakeReadTimeout.Load()
	t.Cleanup(func() { handshakeReadTimeout.Store(original) })
	handshakeReadTimeout.Store(int64(100 * time.Millisecond))

	wsURL, hub := startTestRelay(t)
	ctx, conn := dialRelay(t, wsURL)

	// Read the challenge but never send identify; the relay should give up
	// after handshakeReadTimeout and close the connection.
	_ = readChallenge(t, ctx, conn)

	// Bound the test's own wait to 1s — the relay's timeout is 100ms.
	readCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, _, err := conn.Read(readCtx)
	if err == nil {
		t.Fatalf("expected error from conn.Read after handshake timeout, got nil")
	}
	// Distinguish a relay-side close (CloseStatus != -1, i.e. the relay
	// actually sent a close frame after its read timeout) from a
	// client-side context deadline (which would surface as -1).
	if status := websocket.CloseStatus(err); status == -1 {
		t.Errorf("expected relay-sent close frame after handshake timeout, got non-close error: %v", err)
	}

	// The hub must not have registered a peer for a connection that never
	// completed identification — handshake() returns before hub.add().
	if got := hub.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after handshake timeout = %d, want 0", got)
	}
}

// TestConcurrentHandshakes asserts that 32 distinct identities can complete
// the handshake in parallel and all end up registered in the hub, then all
// drop cleanly when their connections close.
func TestConcurrentHandshakes(t *testing.T) {
	const n = 32
	wsURL, hub := startTestRelay(t)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		conns   = make([]*websocket.Conn, 0, n)
		errs    = make([]error, 0)
		barrier = make(chan struct{})
	)
	// Force-close every dial on test exit so a fatal failure path doesn't
	// leave goroutines parked on conn.Read while httptest.Server.Close
	// waits on them. CloseNow on an already-closed conn is a no-op.
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.CloseNow()
		}
	})

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()

			id, err := cryptoid.GenerateIdentity()
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("GenerateIdentity: %w", err))
				mu.Unlock()
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.Cleanup(cancel)

			conn, _, err := websocket.Dial(ctx, wsURL, nil)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("websocket.Dial: %w", err))
				mu.Unlock()
				return
			}

			// Read challenge.
			typ, data, err := conn.Read(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("read challenge: %w", err))
				mu.Unlock()
				conn.CloseNow()
				return
			}
			if typ != websocket.MessageText {
				mu.Lock()
				errs = append(errs, fmt.Errorf("challenge: expected text frame, got %v", typ))
				mu.Unlock()
				conn.CloseNow()
				return
			}
			var challenge wireproto.ChallengeMsg
			if err := json.Unmarshal(data, &challenge); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("unmarshal challenge: %w", err))
				mu.Unlock()
				conn.CloseNow()
				return
			}

			// Send identify.
			identifyData, err := wireproto.MarshalIdentify(buildIdentify(id, challenge.Nonce))
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("MarshalIdentify: %w", err))
				mu.Unlock()
				conn.CloseNow()
				return
			}
			if err := conn.Write(ctx, websocket.MessageText, identifyData); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("write identify: %w", err))
				mu.Unlock()
				conn.CloseNow()
				return
			}

			// Expect welcome.
			typ, data, err = conn.Read(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("read welcome: %w", err))
				mu.Unlock()
				conn.CloseNow()
				return
			}
			if typ != websocket.MessageText {
				mu.Lock()
				errs = append(errs, fmt.Errorf("welcome: expected text frame, got %v", typ))
				mu.Unlock()
				conn.CloseNow()
				return
			}
			if got, _ := wireproto.PeekType(data); got != wireproto.TypeWelcome {
				mu.Lock()
				errs = append(errs, fmt.Errorf("post-identify type = %q, want %q", got, wireproto.TypeWelcome))
				mu.Unlock()
				conn.CloseNow()
				return
			}

			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()

			// Wait on barrier — keep the connection open until the test
			// has asserted the hub size.
			<-barrier
		}()
	}

	// Poll for all 32 peers to be registered. Connections wait on the
	// barrier so they remain registered until we release them.
	deadline := time.Now().Add(5 * time.Second)
	for hub.PeerCount() != n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Take the lock around every read of errs — the goroutines append to it
	// under mu. The race is largely theoretical (errored goroutines never
	// reach the conns append, so PeerCount won't hit n), but locking is
	// cheap and removes a -race latent risk.
	if got := hub.PeerCount(); got != n {
		close(barrier)
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("PeerCount after concurrent handshakes = %d, want %d (errs=%v)", got, n, errs)
	}
	mu.Lock()
	if len(errs) != 0 {
		errsCopy := append([]error(nil), errs...)
		mu.Unlock()
		close(barrier)
		wg.Wait()
		t.Fatalf("handshake errors: %v", errsCopy)
	}
	mu.Unlock()

	// Release the goroutines and close all connections.
	close(barrier)
	wg.Wait()
	for _, c := range conns {
		c.Close(websocket.StatusNormalClosure, "")
	}

	// Poll for the hub to drain.
	deadline = time.Now().Add(5 * time.Second)
	for hub.PeerCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after closing all conns = %d, want 0", got)
	}
}

// expectErrorMsg reads the next message and asserts it's an ErrorMsg with
// the given code.
func expectErrorMsg(t *testing.T, ctx context.Context, conn *websocket.Conn, wantCode string) {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read error msg: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("error frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypeError {
		t.Fatalf("post-bad-input message type = %q, want %q\nraw: %s", got, wireproto.TypeError, data)
	}
	var msg wireproto.ErrorMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if msg.Code != wantCode {
		t.Errorf("ErrorMsg.Code = %q, want %q (full: %+v)", msg.Code, wantCode, msg)
	}
}

// completeHandshake runs a normal challenge/identify/welcome exchange against
// the test relay AND drains the peer-list the relay pushes immediately after
// welcome (AGENTS.md "Discovery"), returning the live conn + identity. It's
// a small wrapper so tests that exercise post-handshake behavior don't have
// to repeat the full setup boilerplate from TestHandshakeSuccess and don't
// see the discovery-layer peer-list as a stray message in their assertions.
func completeHandshake(t *testing.T, wsURL string) (context.Context, *websocket.Conn, *cryptoid.Identity) {
	t.Helper()
	ctx, conn := dialRelay(t, wsURL)
	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	challenge := readChallenge(t, ctx, conn)
	sendIdentify(t, ctx, conn, buildIdentify(id, challenge.Nonce))
	readWelcome(t, ctx, conn)
	drainPeerList(t, ctx, conn)
	return ctx, conn, id
}

// completeHandshakeWithIdentity is like completeHandshake but uses a caller-
// provided identity, so tests exercising the displaced-peer path can dial
// twice with the same identity.
func completeHandshakeWithIdentity(t *testing.T, wsURL string, id *cryptoid.Identity) (context.Context, *websocket.Conn) {
	t.Helper()
	ctx, conn := dialRelay(t, wsURL)
	challenge := readChallenge(t, ctx, conn)
	sendIdentify(t, ctx, conn, buildIdentify(id, challenge.Nonce))
	readWelcome(t, ctx, conn)
	drainPeerList(t, ctx, conn)
	return ctx, conn
}

// readWelcome reads the relay's response and asserts it's a WelcomeMsg.
func readWelcome(t *testing.T, ctx context.Context, conn *websocket.Conn) wireproto.WelcomeMsg {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("welcome frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypeWelcome {
		t.Fatalf("post-identify type = %q, want %q\nraw: %s", got, wireproto.TypeWelcome, data)
	}
	var msg wireproto.WelcomeMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal welcome: %v", err)
	}
	return msg
}

// drainPeerList reads the peer-list the relay pushes immediately after
// WelcomeMsg and returns its contents. Tests use it to keep the conn's
// queue empty before exercising post-handshake behavior.
func drainPeerList(t *testing.T, ctx context.Context, conn *websocket.Conn) wireproto.PeerListMsg {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read peer-list: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("peer-list frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypePeerList {
		t.Fatalf("post-welcome type = %q, want %q\nraw: %s", got, wireproto.TypePeerList, data)
	}
	var msg wireproto.PeerListMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal peer-list: %v", err)
	}
	return msg
}

// expectPeerJoined reads the next message from conn and asserts it's a
// PeerJoinedMsg, returning the parsed message.
func expectPeerJoined(t *testing.T, ctx context.Context, conn *websocket.Conn) wireproto.PeerJoinedMsg {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read peer-joined: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("peer-joined frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypePeerJoined {
		t.Fatalf("expected peer-joined, got %q\nraw: %s", got, data)
	}
	var msg wireproto.PeerJoinedMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal peer-joined: %v", err)
	}
	return msg
}

// expectPeerLeft reads the next message from conn and asserts it's a
// PeerLeftMsg, returning the parsed message.
func expectPeerLeft(t *testing.T, ctx context.Context, conn *websocket.Conn) wireproto.PeerLeftMsg {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read peer-left: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("peer-left frame type = %v, want MessageText", typ)
	}
	if got, _ := wireproto.PeekType(data); got != wireproto.TypePeerLeft {
		t.Fatalf("expected peer-left, got %q\nraw: %s", got, data)
	}
	var msg wireproto.PeerLeftMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal peer-left: %v", err)
	}
	return msg
}

// TestPeerListExcludesSelf asserts a newly-connected peer's peer-list does
// NOT contain its own record. The receiver shouldn't have to filter itself
// out of a list it just received.
func TestPeerListExcludesSelf(t *testing.T) {
	wsURL, _ := startTestRelay(t)
	ctx, conn := dialRelay(t, wsURL)
	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	challenge := readChallenge(t, ctx, conn)
	sendIdentify(t, ctx, conn, buildIdentify(id, challenge.Nonce))
	readWelcome(t, ctx, conn)
	pl := drainPeerList(t, ctx, conn)
	if len(pl.Peers) != 0 {
		t.Errorf("peer-list for sole peer has %d entries, want 0 (got %+v)", len(pl.Peers), pl.Peers)
	}
}

// TestPeerListContainsExistingPeers asserts a new peer's peer-list contains
// every previously-connected peer.
func TestPeerListContainsExistingPeers(t *testing.T) {
	wsURL, hub := startTestRelay(t)

	// A connects first.
	_, _, idA := completeHandshake(t, wsURL)

	// Wait for A to be registered before B dials, so B's peer-list snapshot
	// is guaranteed to include A.
	deadline := time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// B connects and reads its peer-list.
	ctx, conn := dialRelay(t, wsURL)
	idB, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	challenge := readChallenge(t, ctx, conn)
	sendIdentify(t, ctx, conn, buildIdentify(idB, challenge.Nonce))
	readWelcome(t, ctx, conn)
	pl := drainPeerList(t, ctx, conn)

	if len(pl.Peers) != 1 {
		t.Fatalf("B's peer-list has %d entries, want 1 (got %+v)", len(pl.Peers), pl.Peers)
	}
	if !bytes.Equal(pl.Peers[0].Ed25519Pub, idA.Ed25519Pub) {
		t.Errorf("B's peer-list[0].Ed25519Pub mismatches A's identity")
	}
	if pl.Peers[0].IP == "" || pl.Peers[0].Port == 0 {
		t.Errorf("B's peer-list[0] missing IP/Port: %+v", pl.Peers[0])
	}
}

// TestPeerJoinedBroadcast asserts an existing peer receives a peer-joined
// when a new peer completes its handshake.
func TestPeerJoinedBroadcast(t *testing.T) {
	wsURL, _ := startTestRelay(t)

	ctxA, connA, _ := completeHandshake(t, wsURL)
	_, _, idB := completeHandshake(t, wsURL)

	// A should receive a peer-joined describing B (B's broadcast targets
	// every peer except B itself).
	msg := expectPeerJoined(t, ctxA, connA)
	if !bytes.Equal(msg.Peer.Ed25519Pub, idB.Ed25519Pub) {
		t.Errorf("peer-joined.Peer.Ed25519Pub mismatches B's identity")
	}
	if msg.Peer.IP == "" || msg.Peer.Port == 0 {
		t.Errorf("peer-joined.Peer missing IP/Port: %+v", msg.Peer)
	}
}

// TestPeerLeftBroadcast asserts remaining peers receive peer-left when a
// peer disconnects cleanly. Also asserts the ordering invariant: B is told
// A exists (via peer-list at handshake time) BEFORE B is told A left —
// otherwise B's wholesale setPeers(parsePeerList(...)) on the TS side could
// re-introduce A after a peer-left arrives out of order. The hub.broadcastMu
// held across the join sequence in HandleWebSocket is what guarantees this.
func TestPeerLeftBroadcast(t *testing.T) {
	wsURL, hub := startTestRelay(t)

	ctxA, connA, idA := completeHandshake(t, wsURL)

	// Wait for A to be registered before B dials, so B's peer-list is
	// guaranteed to include A. This makes the ordering assertion below
	// load-bearing rather than trivially-satisfied-on-empty.
	deadline := time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// B dials; capture its peer-list inline so we can assert it contained A
	// (i.e. B knew about A before B is told A left).
	ctxB, connB := dialRelay(t, wsURL)
	idB, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	_ = idB
	challenge := readChallenge(t, ctxB, connB)
	sendIdentify(t, ctxB, connB, buildIdentify(idB, challenge.Nonce))
	readWelcome(t, ctxB, connB)
	bPeerList := drainPeerList(t, ctxB, connB)

	// Ordering invariant: B's peer-list (received during handshake) must
	// contain A. Without hub.broadcastMu serializing the join sequence,
	// a peer-left for A could race ahead of B's peer-list and a wholesale
	// TS-side setPeers would re-introduce A.
	foundA := false
	for _, p := range bPeerList.Peers {
		if bytes.Equal(p.Ed25519Pub, idA.Ed25519Pub) {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Fatalf("B's peer-list did not contain A — ordering invariant broken (peers=%+v)", bPeerList.Peers)
	}

	// A receives peer-joined for B; drain it so A's queue is clean before
	// disconnect (not strictly needed for this test but keeps the model
	// tight).
	expectPeerJoined(t, ctxA, connA)

	// A disconnects cleanly.
	connA.Close(websocket.StatusNormalClosure, "")

	// B should receive peer-left for A within a bounded window.
	readCtx, cancel := context.WithTimeout(ctxB, 5*time.Second)
	defer cancel()
	msg := expectPeerLeft(t, readCtx, connB)
	if !bytes.Equal(msg.Ed25519Pub, idA.Ed25519Pub) {
		t.Errorf("peer-left.Ed25519Pub mismatches A's identity")
	}
}

// TestPeerListContainsAllExistingPeers asserts a third peer's peer-list
// contains exactly the two existing peers — no duplicates, no self, both
// ed25519 pubs present. Complements TestPeerListContainsExistingPeers (which
// only covers the 1 → 2 case).
func TestPeerListContainsAllExistingPeers(t *testing.T) {
	wsURL, hub := startTestRelay(t)

	// A connects.
	_, _, idA := completeHandshake(t, wsURL)
	deadline := time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// B connects.
	_, _, idB := completeHandshake(t, wsURL)
	deadline = time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// C connects and reads its peer-list.
	ctx, conn := dialRelay(t, wsURL)
	idC, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	challenge := readChallenge(t, ctx, conn)
	sendIdentify(t, ctx, conn, buildIdentify(idC, challenge.Nonce))
	readWelcome(t, ctx, conn)
	pl := drainPeerList(t, ctx, conn)

	if len(pl.Peers) != 2 {
		t.Fatalf("C's peer-list has %d entries, want 2 (got %+v)", len(pl.Peers), pl.Peers)
	}

	// Build a set of the keys C saw and check membership + no duplicates +
	// no self.
	seen := make(map[string]int, 2)
	for _, p := range pl.Peers {
		seen[string(p.Ed25519Pub)]++
		if bytes.Equal(p.Ed25519Pub, idC.Ed25519Pub) {
			t.Errorf("C's peer-list contained C's own identity")
		}
	}
	if seen[string(idA.Ed25519Pub)] != 1 {
		t.Errorf("A appears %d times in C's peer-list, want exactly 1", seen[string(idA.Ed25519Pub)])
	}
	if seen[string(idB.Ed25519Pub)] != 1 {
		t.Errorf("B appears %d times in C's peer-list, want exactly 1", seen[string(idB.Ed25519Pub)])
	}
}

// TestPeerLeftNotBroadcastOnDisplacement asserts that a displaced peer
// (same identity reconnects on a new connection) does NOT cause a
// peer-left broadcast — the identity is still live via the new connection,
// and other peers should not be told it left.
func TestPeerLeftNotBroadcastOnDisplacement(t *testing.T) {
	wsURL, _ := startTestRelay(t)

	// A connects, then B connects.
	ctxA, connA, idA := completeHandshake(t, wsURL)
	_, connB, _ := completeHandshake(t, wsURL)

	// A receives peer-joined for B; drain it so A's queue is clean before
	// the displacement happens. B never receives peer-joined for itself.
	expectPeerJoined(t, ctxA, connA)

	// A reconnects with the same identity, displacing the original A.
	_, connA2 := completeHandshakeWithIdentity(t, wsURL, idA)
	_ = connA2

	// B receives peer-joined for the new A (same identity bytes, fresh
	// broadcast from the new connection's HandleWebSocket).
	readCtx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	msgJoined := expectPeerJoined(t, readCtx1, connB)
	if !bytes.Equal(msgJoined.Peer.Ed25519Pub, idA.Ed25519Pub) {
		t.Errorf("peer-joined after displacement: ed25519 mismatch")
	}

	// Crucially, B must NOT receive a peer-left for A's identity — the
	// displaced goroutine's hub.remove() returns false (the new connection
	// owns the entry), so the peer-left broadcast is skipped. Set a short
	// deadline; expect the read to time out.
	readCtx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	if _, data, err := connB.Read(readCtx2); err == nil {
		t.Errorf("B unexpectedly received a message after displacement (peer-left would be wrong here): %s", data)
	}
}

// TestPostHandshakeReadLimit asserts the SetReadLimit applied at connection
// accept also enforces during the post-handshake park loop — not just during
// the handshake itself. A peer that sends a frame strictly larger than
// wireproto.ReadLimit after welcoming must be dropped, and the hub must drain.
func TestPostHandshakeReadLimit(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctx, conn, _ := completeHandshake(t, wsURL)

	// Wait for the relay to register the peer before slamming it with
	// the oversize frame; otherwise we may close before hub.add runs.
	deadline := time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 1 {
		t.Fatalf("PeerCount before oversize write = %d, want 1", got)
	}

	// Strictly more than ReadLimit (AGENTS.md: tests must send more than the
	// limit). Use printable ASCII so a stray log line stays readable.
	oversize := bytes.Repeat([]byte{'a'}, wireproto.ReadLimit+1)
	if err := conn.Write(ctx, websocket.MessageText, oversize); err != nil {
		// Some platforms may surface the relay-side close before the
		// write returns. Either ordering is acceptable as long as the
		// next Read fails and the hub drains.
		t.Logf("write oversize returned error (acceptable): %v", err)
	}

	// The relay should close the connection within ~1s.
	readCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, _, err := conn.Read(readCtx)
	if err == nil {
		t.Fatalf("expected error from conn.Read after oversize frame, got nil")
	}
	// Distinguish the relay-enforced cap from a context-deadline path:
	// either the websocket layer reports StatusMessageTooBig as the close
	// status, or the error message carries the read-limit signal
	// coder/websocket emits ("read limited" / "too big").
	status := websocket.CloseStatus(err)
	errStr := err.Error()
	if status != websocket.StatusMessageTooBig &&
		!strings.Contains(errStr, "too big") &&
		!strings.Contains(errStr, "read limited") {
		t.Errorf("expected relay-enforced read-limit signal, got status=%v err=%v", status, err)
	}

	// And the peer must drop from the hub.
	deadline = time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after oversize drop = %d, want 0", got)
	}
}

func TestWelcomeAdvertisesMaxChunk(t *testing.T) {
	wsURL, _ := startTestRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })

	challenge := readChallenge(t, ctx, conn)
	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	sendIdentify(t, ctx, conn, buildIdentify(id, challenge.Nonce))
	welcome := readWelcome(t, ctx, conn)
	if welcome.Limits == nil || welcome.Limits.MaxChunkBytes != wireproto.MaxChunkBytes {
		t.Fatalf("welcome.limits = %+v, want max_chunk_bytes=%d", welcome.Limits, wireproto.MaxChunkBytes)
	}
}

// TestIdentityReconnectDisplacesOldConn asserts that a second handshake
// using the same identity replaces the first peer entry rather than adding
// a duplicate, that the displaced conn is closed with StatusPolicyViolation
// (the round-1 fix), and that closing the surviving conn drops the hub to
// zero — i.e. the displaced goroutine's deferred remove() did not clobber
// the new entry (the pointer-equality check in (*Hub).remove).
func TestIdentityReconnectDisplacesOldConn(t *testing.T) {
	wsURL, hub := startTestRelay(t)

	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	_, conn1 := completeHandshakeWithIdentity(t, wsURL, id)

	deadline := time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 1 {
		t.Fatalf("PeerCount after first handshake = %d, want 1", got)
	}

	_, conn2 := completeHandshakeWithIdentity(t, wsURL, id)

	// Hub size must stay at 1 — the second connection replaces the first
	// rather than registering as a separate peer.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.PeerCount() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 1 {
		t.Fatalf("PeerCount after reconnect = %d, want 1", got)
	}

	// conn1's next Read must return: the relay should have closed it with
	// StatusPolicyViolation (per the round-1 fix).
	readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err = conn1.Read(readCtx)
	if err == nil {
		t.Fatalf("expected conn1 to be closed after displacement, got nil error")
	}
	if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
		t.Errorf("conn1 close status = %v, want StatusPolicyViolation", status)
	}

	// Closing the surviving conn must drop the hub to zero — i.e. the
	// displaced conn1's deferred remove() did NOT clobber the conn2 entry.
	conn2.Close(websocket.StatusNormalClosure, "")
	deadline = time.Now().Add(2 * time.Second)
	for hub.PeerCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after closing surviving conn = %d, want 0", got)
	}
}
