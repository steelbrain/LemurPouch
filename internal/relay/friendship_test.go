package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/cryptoid"
	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// setupMesh connects n peers, drains every peer-joined notification on
// every prior peer, and returns matched ctxs/conns/identities. The pattern
// is sequential so peer-joined arrival order is deterministic regardless
// of whether broadcastExcept is synchronous (this branch) or fan-out
// (what main is moving toward).
func setupMesh(t *testing.T, wsURL string, n int) ([]context.Context, []*websocket.Conn, []*cryptoid.Identity) {
	t.Helper()
	ctxs := make([]context.Context, n)
	conns := make([]*websocket.Conn, n)
	ids := make([]*cryptoid.Identity, n)
	for i := 0; i < n; i++ {
		ctxs[i], conns[i], ids[i] = completeHandshake(t, wsURL)
		// Each previously-connected peer receives peer-joined for the
		// new arrival.
		for j := 0; j < i; j++ {
			expectPeerJoined(t, ctxs[j], conns[j])
		}
	}
	return ctxs, conns, ids
}

// sendDirective marshals one of the c2s friendship directives
// (invite/accept/reject) and writes it. label appears in error messages.
func sendDirective(t *testing.T, ctx context.Context, conn *websocket.Conn, marshal func([]byte) ([]byte, error), to []byte, label string) {
	t.Helper()
	data, err := marshal(to)
	if err != nil {
		t.Fatalf("marshal %s: %v", label, err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write %s: %v", label, err)
	}
}

func sendInvite(t *testing.T, ctx context.Context, conn *websocket.Conn, to []byte) {
	t.Helper()
	sendDirective(t, ctx, conn, wireproto.MarshalInvite, to, "invite")
}

func sendAccept(t *testing.T, ctx context.Context, conn *websocket.Conn, to []byte) {
	t.Helper()
	sendDirective(t, ctx, conn, wireproto.MarshalAccept, to, "accept")
}

func sendReject(t *testing.T, ctx context.Context, conn *websocket.Conn, to []byte) {
	t.Helper()
	sendDirective(t, ctx, conn, wireproto.MarshalReject, to, "reject")
}

// expectFriendshipNotification reads the next message and asserts it's the
// expected s2c friendship notification, returning the parsed `from` bytes.
func expectFriendshipNotification(t *testing.T, ctx context.Context, conn *websocket.Conn, wantType string) wireproto.FriendshipNotification {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read %s: %v", wantType, err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("%s frame type = %v, want MessageText", wantType, typ)
	}
	if got, _ := wireproto.PeekType(data); got != wantType {
		t.Fatalf("expected %s, got %q\nraw: %s", wantType, got, data)
	}
	var msg wireproto.FriendshipNotification
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal %s: %v", wantType, err)
	}
	return msg
}

// expectNoMessage asserts that conn does not yield a message within d.
// Used to verify silent-drop semantics (queued invites, no-op re-invites,
// disconnect cleanup not surfacing anything to the survivor).
func expectNoMessage(t *testing.T, conn *websocket.Conn, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err == nil {
		t.Fatalf("expected no message within %v, got: %s", d, data)
	}
}

// pairCounts reads the FriendshipManager's pair state for assertion. Same-
// package access into private fields is intentional — the alternative
// (timing-based assumptions about when the relay has finished processing a
// directive) is flaky.
func pairCounts(fm *FriendshipManager, senderIP string, recipientEd25519 []byte) (active int, queued int, rejected bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	state := fm.pairs[pairInvitesKey{
		senderIP:     senderIP,
		recipientHex: hex.EncodeToString(recipientEd25519),
	}]
	if state == nil {
		return 0, 0, false
	}
	if state.active != nil {
		active = 1
	}
	return active, len(state.queued), state.rejected
}

// waitForPairCounts polls until pairCounts matches the expected values, or
// fails the test. Used to bridge the gap between "the test wrote a frame"
// and "the relay's per-conn read goroutine processed the frame and updated
// FriendshipManager state".
func waitForPairCounts(t *testing.T, fm *FriendshipManager, senderIP string, recipientEd25519 []byte, wantActive, wantQueued int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a, q, _ := pairCounts(fm, senderIP, recipientEd25519)
		if a == wantActive && q == wantQueued {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	a, q, r := pairCounts(fm, senderIP, recipientEd25519)
	t.Fatalf("pairCounts after wait = (active=%d, queued=%d, rejected=%v), want (active=%d, queued=%d)",
		a, q, r, wantActive, wantQueued)
}

// peerIP looks up the relay-observed IP of an identity. Loopback dial
// usually surfaces "127.0.0.1" but on IPv6-only hosts it could be "::1";
// reading it from the hub avoids hardcoding either.
func peerIP(t *testing.T, hub *Hub, ed25519Pub []byte) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if peer := hub.lookup(ed25519Pub); peer != nil {
			return peer.Record.IP
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peerIP: identity %x never registered", ed25519Pub)
	return ""
}

func TestFriendshipInviteAccept(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)

	sendInvite(t, ctxs[0], conns[0], ids[1].Ed25519Pub)

	// B receives invite-from carrying A's identity.
	gotInvite := expectFriendshipNotification(t, ctxs[1], conns[1], wireproto.TypeInviteFrom)
	if !bytes.Equal(gotInvite.From, ids[0].Ed25519Pub) {
		t.Errorf("invite-from.From mismatches A's identity")
	}

	sendAccept(t, ctxs[1], conns[1], ids[0].Ed25519Pub)

	// A receives accept-from carrying B's identity.
	gotAccept := expectFriendshipNotification(t, ctxs[0], conns[0], wireproto.TypeAcceptFrom)
	if !bytes.Equal(gotAccept.From, ids[1].Ed25519Pub) {
		t.Errorf("accept-from.From mismatches B's identity")
	}

	// Mutual friendship is established. Symmetric: AreFriends(A,B) == AreFriends(B,A).
	if !hub.fm.AreFriends(ids[0].Ed25519Pub, ids[1].Ed25519Pub) {
		t.Error("AreFriends(A,B) after accept = false, want true")
	}
	if !hub.fm.AreFriends(ids[1].Ed25519Pub, ids[0].Ed25519Pub) {
		t.Error("AreFriends(B,A) after accept = false, want true")
	}
}

func TestFriendshipInviteReject(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)

	sendInvite(t, ctxs[0], conns[0], ids[1].Ed25519Pub)
	expectFriendshipNotification(t, ctxs[1], conns[1], wireproto.TypeInviteFrom)

	sendReject(t, ctxs[1], conns[1], ids[0].Ed25519Pub)

	gotReject := expectFriendshipNotification(t, ctxs[0], conns[0], wireproto.TypeRejectFrom)
	if !bytes.Equal(gotReject.From, ids[1].Ed25519Pub) {
		t.Errorf("reject-from.From mismatches B's identity")
	}

	if hub.fm.AreFriends(ids[0].Ed25519Pub, ids[1].Ed25519Pub) {
		t.Error("AreFriends after reject = true, want false")
	}

	// Pair state should now be marked rejected so subsequent invites from
	// A's IP to B auto-reject. Wait for relay-side state to settle before
	// asserting (HandleReject's writes are async, but the rejected flag
	// is set under fm.mu before writes fire — so this should be ~instant).
	waitForPairCounts(t, hub.fm, peerIP(t, hub, ids[0].Ed25519Pub), ids[1].Ed25519Pub, 0, 0)
	_, _, rejected := pairCounts(hub.fm, peerIP(t, hub, ids[0].Ed25519Pub), ids[1].Ed25519Pub)
	if !rejected {
		t.Error("pair state rejected = false after reject, want true")
	}
}

func TestFriendshipQueueAdvancesOnAccept(t *testing.T) {
	// Three peers on the same loopback IP: X and Y both invite R. R sees
	// X's invite first, accepts. R then sees Y's invite (advanced from
	// queue); Y sees invite-deferred.
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 3)
	idX, idY, idR := ids[0], ids[1], ids[2]
	ctxX, ctxY, ctxR := ctxs[0], ctxs[1], ctxs[2]
	connX, connY, connR := conns[0], conns[1], conns[2]
	senderIP := peerIP(t, hub, idX.Ed25519Pub)

	sendInvite(t, ctxX, connX, idR.Ed25519Pub)
	got := expectFriendshipNotification(t, ctxR, connR, wireproto.TypeInviteFrom)
	if !bytes.Equal(got.From, idX.Ed25519Pub) {
		t.Errorf("first invite-from.From mismatches X's identity")
	}

	sendInvite(t, ctxY, connY, idR.Ed25519Pub)
	// Wait for Y's invite to land in the queue before R sends accept,
	// otherwise R's accept can race ahead and Y becomes the new active
	// directly (no invite-deferred).
	waitForPairCounts(t, hub.fm, senderIP, idR.Ed25519Pub, 1, 1)

	sendAccept(t, ctxR, connR, idX.Ed25519Pub)

	gotAccept := expectFriendshipNotification(t, ctxX, connX, wireproto.TypeAcceptFrom)
	if !bytes.Equal(gotAccept.From, idR.Ed25519Pub) {
		t.Errorf("accept-from.From mismatches R's identity")
	}

	// R now sees Y's invite as the new active.
	gotNextInvite := expectFriendshipNotification(t, ctxR, connR, wireproto.TypeInviteFrom)
	if !bytes.Equal(gotNextInvite.From, idY.Ed25519Pub) {
		t.Errorf("queued invite-from.From mismatches Y's identity")
	}

	// Y receives invite-deferred carrying R's identity (the recipient who
	// just became available again).
	gotDeferred := expectFriendshipNotification(t, ctxY, connY, wireproto.TypeInviteDeferred)
	if !bytes.Equal(gotDeferred.From, idR.Ed25519Pub) {
		t.Errorf("invite-deferred.From mismatches R's identity")
	}

	// State: X-R is friends; Y is now the active invite for R.
	if !hub.fm.AreFriends(idX.Ed25519Pub, idR.Ed25519Pub) {
		t.Error("AreFriends(X,R) after queue advance = false, want true")
	}
}

func TestFriendshipQueueAutoRejectOnReject(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 3)
	// idY is intentionally unused — Y's identity isn't checked in this
	// test (the assertion is on the auto-reject notification's `from`
	// field, which carries R's identity, not Y's).
	idX, idR := ids[0], ids[2]
	ctxX, ctxY, ctxR := ctxs[0], ctxs[1], ctxs[2]
	connX, connY, connR := conns[0], conns[1], conns[2]
	senderIP := peerIP(t, hub, idX.Ed25519Pub)

	sendInvite(t, ctxX, connX, idR.Ed25519Pub)
	expectFriendshipNotification(t, ctxR, connR, wireproto.TypeInviteFrom)

	sendInvite(t, ctxY, connY, idR.Ed25519Pub)
	waitForPairCounts(t, hub.fm, senderIP, idR.Ed25519Pub, 1, 1)

	sendReject(t, ctxR, connR, idX.Ed25519Pub)

	// X gets the direct reject. Y gets invite-auto-rejected (queued
	// invites are dropped on reject; sender is told their invite never
	// reached the recipient).
	gotReject := expectFriendshipNotification(t, ctxX, connX, wireproto.TypeRejectFrom)
	if !bytes.Equal(gotReject.From, idR.Ed25519Pub) {
		t.Errorf("reject-from.From mismatches R's identity")
	}
	gotAuto := expectFriendshipNotification(t, ctxY, connY, wireproto.TypeInviteAutoRejected)
	if !bytes.Equal(gotAuto.From, idR.Ed25519Pub) {
		t.Errorf("invite-auto-rejected.From mismatches R's identity")
	}

	// Pair state stays around with rejected=true; no active, no queue.
	a, q, rejected := pairCounts(hub.fm, senderIP, idR.Ed25519Pub)
	if a != 0 || q != 0 || !rejected {
		t.Errorf("post-reject pair state = (active=%d, queued=%d, rejected=%v), want (0, 0, true)", a, q, rejected)
	}
}

func TestFriendshipAutoRejectAfterRejectionLogged(t *testing.T) {
	// Peers X and Z share an IP (loopback). X invites R; R rejects. Z's
	// subsequent invite to R must auto-reject without bothering R.
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 3)
	idX, idZ, idR := ids[0], ids[1], ids[2]
	ctxX, ctxZ, ctxR := ctxs[0], ctxs[1], ctxs[2]
	connX, connZ, connR := conns[0], conns[1], conns[2]

	sendInvite(t, ctxX, connX, idR.Ed25519Pub)
	expectFriendshipNotification(t, ctxR, connR, wireproto.TypeInviteFrom)

	sendReject(t, ctxR, connR, idX.Ed25519Pub)
	expectFriendshipNotification(t, ctxX, connX, wireproto.TypeRejectFrom)

	// Z invites R. Z hears invite-auto-rejected; R must hear nothing.
	sendInvite(t, ctxZ, connZ, idR.Ed25519Pub)
	gotAuto := expectFriendshipNotification(t, ctxZ, connZ, wireproto.TypeInviteAutoRejected)
	if !bytes.Equal(gotAuto.From, idR.Ed25519Pub) {
		t.Errorf("invite-auto-rejected.From mismatches R's identity")
	}
	expectNoMessage(t, connR, 300*time.Millisecond)

	// And no friendship was created.
	if hub.fm.AreFriends(idZ.Ed25519Pub, idR.Ed25519Pub) {
		t.Error("AreFriends(Z,R) after auto-reject = true, want false")
	}
}

func TestFriendshipNoOpWhenAlreadyFriends(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)

	// Establish friendship first.
	sendInvite(t, ctxs[0], conns[0], ids[1].Ed25519Pub)
	expectFriendshipNotification(t, ctxs[1], conns[1], wireproto.TypeInviteFrom)
	sendAccept(t, ctxs[1], conns[1], ids[0].Ed25519Pub)
	expectFriendshipNotification(t, ctxs[0], conns[0], wireproto.TypeAcceptFrom)

	if !hub.fm.AreFriends(ids[0].Ed25519Pub, ids[1].Ed25519Pub) {
		t.Fatal("preconditions: AreFriends after accept = false")
	}
	senderIP := peerIP(t, hub, ids[0].Ed25519Pub)
	activeBefore, queuedBefore, rejectedBefore := pairCounts(hub.fm, senderIP, ids[1].Ed25519Pub)

	// Re-invite. The friendship-set check in HandleInvite should make
	// this a no-op: no message to either peer, no pair state changes.
	sendInvite(t, ctxs[0], conns[0], ids[1].Ed25519Pub)

	// Two-pronged verification:
	//
	// 1. State-based: the relay-side FriendshipManager state is unchanged
	//    after a small settle window. State assertions are reliable here
	//    because they don't perturb connection lifetimes, unlike a
	//    deadlined Read which coder/websocket terminates the conn on.
	//
	// 2. Wire-based: the recipient's conn yields no message within a
	//    short window. Done LAST so the conn close that
	//    coder/websocket performs on ctx cancellation can't broadcast a
	//    spurious peer-left to a peer we'd later try to read.
	time.Sleep(100 * time.Millisecond)
	a, q, r := pairCounts(hub.fm, senderIP, ids[1].Ed25519Pub)
	if a != activeBefore || q != queuedBefore || r != rejectedBefore {
		t.Errorf("pair state after re-invite = (a=%d, q=%d, r=%v), want (a=%d, q=%d, r=%v)",
			a, q, r, activeBefore, queuedBefore, rejectedBefore)
	}
	if !hub.fm.AreFriends(ids[0].Ed25519Pub, ids[1].Ed25519Pub) {
		t.Error("AreFriends after re-invite = false, want true")
	}
	expectNoMessage(t, conns[1], 300*time.Millisecond)
}

func TestFriendshipSelfInviteDropped(t *testing.T) {
	wsURL, _ := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 1)

	// Self-invite. HandleInvite's first guard drops it before any state
	// or message would be created.
	sendInvite(t, ctxs[0], conns[0], ids[0].Ed25519Pub)
	expectNoMessage(t, conns[0], 300*time.Millisecond)
}

func TestFriendshipInviteToMissingRecipientDropped(t *testing.T) {
	wsURL, _ := startTestRelay(t)
	ctxs, conns, _ := setupMesh(t, wsURL, 1)

	// Invite a 32-byte identity that nobody is connected as. Silent drop.
	bogus := bytes.Repeat([]byte{0xAB}, 32)
	sendInvite(t, ctxs[0], conns[0], bogus)
	expectNoMessage(t, conns[0], 300*time.Millisecond)
}

func TestFriendshipDisconnectClearsFriendship(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxA, connA, idA := completeHandshake(t, wsURL)
	ctxB, connB, idB := completeHandshake(t, wsURL)
	expectPeerJoined(t, ctxA, connA) // A's peer-joined for B

	// Establish A-B friendship.
	sendInvite(t, ctxA, connA, idB.Ed25519Pub)
	expectFriendshipNotification(t, ctxB, connB, wireproto.TypeInviteFrom)
	sendAccept(t, ctxB, connB, idA.Ed25519Pub)
	expectFriendshipNotification(t, ctxA, connA, wireproto.TypeAcceptFrom)
	if !hub.fm.AreFriends(idA.Ed25519Pub, idB.Ed25519Pub) {
		t.Fatal("preconditions: AreFriends after accept = false")
	}

	// B disconnects. The relay's defer chain calls
	// hub.fm.OnPeerDisconnect(idB), which should drop the friendship.
	connB.Close(websocket.StatusNormalClosure, "")

	// Wait for the friendship to clear (disconnect cleanup runs in a
	// separate goroutine via the deferred remove path).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !hub.fm.AreFriends(idA.Ed25519Pub, idB.Ed25519Pub) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("AreFriends after B disconnect = true, want false")
}

func TestFriendshipDisconnectClearsActiveInvite(t *testing.T) {
	// A invites B and then disconnects without B ever responding. The
	// pair state should be garbage-collected so a fresh invite from a
	// peer at A's IP can take the slot. We verify by having C (same IP)
	// invite B after A's disconnect — C's invite should become active
	// (B receives invite-from from C), not queued.
	wsURL, hub := startTestRelay(t)
	ctxA, connA, idA := completeHandshake(t, wsURL)
	ctxB, connB, idB := completeHandshake(t, wsURL)
	expectPeerJoined(t, ctxA, connA)
	ctxC, connC, idC := completeHandshake(t, wsURL)
	expectPeerJoined(t, ctxA, connA) // A: peer-joined for C
	expectPeerJoined(t, ctxB, connB) // B: peer-joined for C

	senderIP := peerIP(t, hub, idA.Ed25519Pub)

	sendInvite(t, ctxA, connA, idB.Ed25519Pub)
	expectFriendshipNotification(t, ctxB, connB, wireproto.TypeInviteFrom)

	// A walks away.
	connA.Close(websocket.StatusNormalClosure, "")

	// Drain the peer-left broadcast that A's disconnect generates on
	// each surviving peer's queue. Without this, B's next read would
	// see peer-left rather than the C-invite we're about to send.
	// Draining peer-left also doubles as a sync barrier: the relay's
	// defer chain runs OnPeerDisconnect *before* broadcastExcept, so a
	// successful peer-left read implies the (senderIP, B) pair state
	// has already been cleaned.
	expectPeerLeft(t, ctxB, connB)
	expectPeerLeft(t, ctxC, connC)

	if a, q, _ := pairCounts(hub.fm, senderIP, idB.Ed25519Pub); a != 0 || q != 0 {
		t.Fatalf("pair state after A disconnect = (active=%d, queued=%d), want (0, 0)", a, q)
	}

	// C invites B from the same IP. With the prior state cleared, C's
	// invite must become active (not queued, not auto-rejected).
	sendInvite(t, ctxC, connC, idB.Ed25519Pub)
	gotInvite := expectFriendshipNotification(t, ctxB, connB, wireproto.TypeInviteFrom)
	if !bytes.Equal(gotInvite.From, idC.Ed25519Pub) {
		t.Errorf("post-disconnect invite-from.From mismatches C's identity")
	}
}

// TestFriendshipAcceptWithoutInviteIsNoOp verifies that an accept directive
// from B to A without any pending invite from A is a silent no-op: A hears
// nothing, no friendship is created, no pair state is leaked.
func TestFriendshipAcceptWithoutInviteIsNoOp(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)

	// B sends accept(A) out of the blue — no prior invite from A.
	sendAccept(t, ctxs[1], conns[1], ids[0].Ed25519Pub)

	// Settle window, then assert nothing happened on either side.
	time.Sleep(100 * time.Millisecond)
	if hub.fm.AreFriends(ids[0].Ed25519Pub, ids[1].Ed25519Pub) {
		t.Error("AreFriends after spurious accept = true, want false")
	}
	senderIP := peerIP(t, hub, ids[0].Ed25519Pub)
	a, q, r := pairCounts(hub.fm, senderIP, ids[1].Ed25519Pub)
	if a != 0 || q != 0 || r {
		t.Errorf("pair state after spurious accept = (a=%d, q=%d, r=%v), want (0, 0, false)", a, q, r)
	}
	expectNoMessage(t, conns[0], 300*time.Millisecond)
}

// TestFriendshipRejectWithoutInviteIsNoOp verifies that a reject directive
// without a matching pending invite is a silent no-op — no reject-from
// reaches the originator, and no rejected flag is set on the pair state
// (otherwise an attacker could pre-poison rejection state for an arbitrary
// (IP, recipient) pair without an actual invite ever happening).
func TestFriendshipRejectWithoutInviteIsNoOp(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)

	sendReject(t, ctxs[1], conns[1], ids[0].Ed25519Pub)

	time.Sleep(100 * time.Millisecond)
	senderIP := peerIP(t, hub, ids[0].Ed25519Pub)
	a, q, r := pairCounts(hub.fm, senderIP, ids[1].Ed25519Pub)
	if a != 0 || q != 0 || r {
		t.Errorf("pair state after spurious reject = (a=%d, q=%d, r=%v), want (0, 0, false)", a, q, r)
	}
	expectNoMessage(t, conns[0], 300*time.Millisecond)
}

// TestFriendshipSelfAcceptAndRejectDropped verifies that a peer cannot
// short-circuit the consent model by sending accept(self) or reject(self):
// both must be no-ops with no friendship created and no message echoed back.
// The current guard rests on (a) HandleInvite blocking self-invites so the
// (selfIP, self) pair state never exists and (b) handleResponse early-
// returning when the active sender doesn't match — this test pins the
// behavior so a future refactor doesn't open a self-friendship loophole.
func TestFriendshipSelfAcceptAndRejectDropped(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 1)

	sendAccept(t, ctxs[0], conns[0], ids[0].Ed25519Pub)
	sendReject(t, ctxs[0], conns[0], ids[0].Ed25519Pub)

	time.Sleep(100 * time.Millisecond)
	if hub.fm.AreFriends(ids[0].Ed25519Pub, ids[0].Ed25519Pub) {
		t.Error("AreFriends(self, self) after self-accept = true, want false")
	}
	senderIP := peerIP(t, hub, ids[0].Ed25519Pub)
	a, q, r := pairCounts(hub.fm, senderIP, ids[0].Ed25519Pub)
	if a != 0 || q != 0 || r {
		t.Errorf("self-pair state = (a=%d, q=%d, r=%v), want (0, 0, false)", a, q, r)
	}
	expectNoMessage(t, conns[0], 300*time.Millisecond)
}

// TestFriendshipDoubleAcceptIsNoOp verifies that a second accept after the
// friendship is already established does NOT re-fire accept-from. The pair
// state survives accept (so HandleInvite can dedupe via the friends set),
// but state.active is nil — handleResponse must early-return on the second
// accept rather than spuriously notifying the originator again.
func TestFriendshipDoubleAcceptIsNoOp(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)

	sendInvite(t, ctxs[0], conns[0], ids[1].Ed25519Pub)
	expectFriendshipNotification(t, ctxs[1], conns[1], wireproto.TypeInviteFrom)
	sendAccept(t, ctxs[1], conns[1], ids[0].Ed25519Pub)
	expectFriendshipNotification(t, ctxs[0], conns[0], wireproto.TypeAcceptFrom)

	if !hub.fm.AreFriends(ids[0].Ed25519Pub, ids[1].Ed25519Pub) {
		t.Fatal("preconditions: AreFriends after first accept = false")
	}

	// Second accept — should be silent.
	sendAccept(t, ctxs[1], conns[1], ids[0].Ed25519Pub)
	expectNoMessage(t, conns[0], 300*time.Millisecond)
}

// TestFriendshipQueuedSenderDisplacementGetsDeferred pins the round-2 fix:
// when a queued invite's sender is displaced by a same-identity reconnect
// (its old conn is closed by add(), and OnPeerDisconnect is intentionally
// suppressed for the old peer), the queue still holds a *Peer pointing at
// the dead conn. When the queue advances on accept, handleResponse must
// re-resolve the live conn for the queued sender's identity via
// hub.lookup so the invite-deferred notification reaches the new
// connection. Without the fix, the write goes to the closed old conn and
// the new connection silently never learns its invite became active.
func TestFriendshipQueuedSenderDisplacementGetsDeferred(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 3)
	idX, idY, idR := ids[0], ids[1], ids[2]
	ctxX, ctxY, ctxR := ctxs[0], ctxs[1], ctxs[2]
	connX, connY, connR := conns[0], conns[1], conns[2]
	senderIP := peerIP(t, hub, idX.Ed25519Pub)

	// X invites R first → becomes active.
	sendInvite(t, ctxX, connX, idR.Ed25519Pub)
	expectFriendshipNotification(t, ctxR, connR, wireproto.TypeInviteFrom)

	// Y invites R → queued behind X.
	sendInvite(t, ctxY, connY, idR.Ed25519Pub)
	waitForPairCounts(t, hub.fm, senderIP, idR.Ed25519Pub, 1, 1)

	// Y reconnects with the same identity, displacing the original Y.
	// The displaced goroutine's defer skips OnPeerDisconnect (so the
	// queued *Peer still pins the old conn), but its conn was closed
	// by hub.add() — exactly the staleness case the fix addresses.
	ctxY2, connY2 := completeHandshakeWithIdentity(t, wsURL, idY)

	// Drain the new-Y peer-joined that surviving peers receive.
	expectPeerJoined(t, ctxX, connX) // X sees Y2's peer-joined
	expectPeerJoined(t, ctxR, connR) // R sees Y2's peer-joined

	// R accepts X. Queue advances → Y's invite is now active.
	sendAccept(t, ctxR, connR, idX.Ed25519Pub)
	expectFriendshipNotification(t, ctxX, connX, wireproto.TypeAcceptFrom)
	// R receives the queued invite-from carrying Y's identity.
	gotInvite := expectFriendshipNotification(t, ctxR, connR, wireproto.TypeInviteFrom)
	if !bytes.Equal(gotInvite.From, idY.Ed25519Pub) {
		t.Errorf("queued invite-from.From mismatches Y's identity")
	}

	// The new Y conn (connY2) — not the old, closed connY — must
	// receive invite-deferred. This is the load-bearing assertion: a
	// stale-pointer write would land on the closed connY and connY2
	// would time out below.
	gotDeferred := expectFriendshipNotification(t, ctxY2, connY2, wireproto.TypeInviteDeferred)
	if !bytes.Equal(gotDeferred.From, idR.Ed25519Pub) {
		t.Errorf("invite-deferred.From mismatches R's identity")
	}
}
