package relay

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// makeTestEnvelope synthesizes a dummy binary envelope frame addressed
// to dest. The relay never decrypts, so we don't need real crypto here —
// the sealed payload is just a fixed pattern with the right minimum
// length (16 bytes for the Poly1305 tag). innerType identifies the
// payload kind to the (would-be) recipient; for routing tests we use
// InnerTypeJSONControl by default.
func makeTestEnvelope(t *testing.T, dest []byte, innerType byte, sealedLen int) []byte {
	t.Helper()
	if sealedLen < wireproto.EnvelopeMinSealedLen {
		t.Fatalf("makeTestEnvelope: sealedLen %d below minimum", sealedLen)
	}
	nonce := bytes.Repeat([]byte{0xCC}, wireproto.EnvelopeNonceLen)
	sealed := bytes.Repeat([]byte{0xDD}, sealedLen)
	frame, err := wireproto.MarshalEnvelope(innerType, dest, nonce, sealed)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	return frame
}

// readBinary reads the next frame from conn and asserts it's binary,
// returning the payload bytes. Used to assert envelope-forward delivery.
func readBinary(t *testing.T, ctx context.Context, conn *websocket.Conn) []byte {
	t.Helper()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("frame type = %v, want MessageBinary", typ)
	}
	return data
}

// expectNoBinary asserts no binary frame arrives within d. Used to
// verify the silent-drop semantics on non-friend, missing-dest, and
// malformed-envelope paths.
func expectNoBinary(t *testing.T, conn *websocket.Conn, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	typ, data, err := conn.Read(ctx)
	if err == nil {
		t.Fatalf("expected no frame within %v, got type=%v data=%d bytes", d, typ, len(data))
	}
}

// becomeFriends runs the invite/accept handshake between two
// already-connected peers (sender first), drains the resulting
// notifications on both conns, and asserts the relay-side
// FriendshipManager registered the friendship.
func becomeFriends(
	t *testing.T,
	hub *Hub,
	ctxA, ctxB context.Context,
	connA, connB *websocket.Conn,
	idA, idB []byte,
) {
	t.Helper()
	sendInvite(t, ctxA, connA, idB)
	if got := expectFriendshipNotification(t, ctxB, connB, wireproto.TypeInviteFrom); !bytes.Equal(got.From, idA) {
		t.Fatalf("invite-from.From mismatches A's identity")
	}
	sendAccept(t, ctxB, connB, idA)
	if got := expectFriendshipNotification(t, ctxA, connA, wireproto.TypeAcceptFrom); !bytes.Equal(got.From, idB) {
		t.Fatalf("accept-from.From mismatches B's identity")
	}
	if !hub.fm.AreFriends(idA, idB) {
		t.Fatal("AreFriends after accept = false")
	}
}

func TestEnvelopeForwardBetweenFriends(t *testing.T) {
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)
	idA, idB := ids[0].Ed25519Pub, ids[1].Ed25519Pub

	becomeFriends(t, hub, ctxs[0], ctxs[1], conns[0], conns[1], idA, idB)

	// A constructs an envelope addressed to B, with a known sealed
	// pattern so the equality assertion is precise.
	sealedPattern := bytes.Repeat([]byte{0xDD}, 64)
	nonce := bytes.Repeat([]byte{0xCC}, wireproto.EnvelopeNonceLen)
	frameOut, err := wireproto.MarshalEnvelope(wireproto.InnerTypeJSONControl, idB, nonce, sealedPattern)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}

	if err := conns[0].Write(ctxs[0], websocket.MessageBinary, frameOut); err != nil {
		t.Fatalf("write envelope: %v", err)
	}

	// B reads the forwarded frame.
	frameIn := readBinary(t, ctxs[1], conns[1])

	// Same length, same inner-type byte, same nonce, same sealed payload —
	// only the 32-byte peer field changes from B's identity to A's.
	if len(frameIn) != len(frameOut) {
		t.Fatalf("forwarded frame length = %d, sent %d", len(frameIn), len(frameOut))
	}
	hdr, sealed, err := wireproto.ParseEnvelopeHeader(frameIn)
	if err != nil {
		t.Fatalf("ParseEnvelopeHeader on received frame: %v", err)
	}
	if hdr.InnerType != wireproto.InnerTypeJSONControl {
		t.Errorf("inner-type changed in forward: got 0x%02x, want 0x%02x", hdr.InnerType, wireproto.InnerTypeJSONControl)
	}
	if !bytes.Equal(hdr.PeerKey, idA) {
		t.Errorf("peer field not rewritten to source: got %x..., want %x...", hdr.PeerKey[:4], idA[:4])
	}
	if !bytes.Equal(hdr.Nonce, nonce) {
		t.Errorf("nonce mutated in forward")
	}
	if !bytes.Equal(sealed, sealedPattern) {
		t.Errorf("sealed payload mutated in forward")
	}
}

func TestEnvelopeDroppedWhenNotFriends(t *testing.T) {
	// A and B are connected but never establish friendship. A's envelope
	// to B must be silently dropped — B sees nothing.
	wsURL, _ := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)
	idB := ids[1].Ed25519Pub

	frame := makeTestEnvelope(t, idB, wireproto.InnerTypeJSONControl, 32)
	if err := conns[0].Write(ctxs[0], websocket.MessageBinary, frame); err != nil {
		t.Fatalf("write envelope: %v", err)
	}

	// expectNoBinary closes B's conn via ctx-deadline cancellation, so
	// run it last (no other reads on conns[1] follow).
	expectNoBinary(t, conns[1], 300*time.Millisecond)
}

func TestEnvelopeDroppedWhenDestNotConnected(t *testing.T) {
	// A is the only connected peer. An envelope addressed to a
	// non-existent identity is silently dropped — A doesn't get an
	// error reply (the relay never replies inline to envelope frames),
	// and the connection stays alive.
	wsURL, hub := startTestRelay(t)
	ctxs, conns, _ := setupMesh(t, wsURL, 1)

	bogusDest := bytes.Repeat([]byte{0xEE}, wireproto.EnvelopePeerKeyLen)
	frame := makeTestEnvelope(t, bogusDest, wireproto.InnerTypeJSONControl, 32)
	if err := conns[0].Write(ctxs[0], websocket.MessageBinary, frame); err != nil {
		t.Fatalf("write envelope: %v", err)
	}

	// Give the relay a moment to process. A's conn must remain alive
	// (PeerCount unchanged) — drop is silent, not a connection-killing
	// protocol violation.
	time.Sleep(100 * time.Millisecond)
	if got := hub.PeerCount(); got != 1 {
		t.Errorf("PeerCount after envelope-to-nowhere = %d, want 1", got)
	}
}

func TestEnvelopeMalformedFrameDropped(t *testing.T) {
	// A sends a binary frame too short to be a valid envelope. The
	// relay must drop it silently — no inline error reply, A's conn
	// stays alive (silent-drop policy keeps a buggy or malicious peer
	// from being able to learn about routing state via timing).
	wsURL, hub := startTestRelay(t)
	ctxs, conns, _ := setupMesh(t, wsURL, 1)

	short := bytes.Repeat([]byte{0xFF}, wireproto.EnvelopeMinFrameLen-1)
	if err := conns[0].Write(ctxs[0], websocket.MessageBinary, short); err != nil {
		t.Fatalf("write short binary: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if got := hub.PeerCount(); got != 1 {
		t.Errorf("PeerCount after malformed envelope = %d, want 1", got)
	}
}

func TestEnvelopeForwardPreservesUnknownInnerType(t *testing.T) {
	// Forward-compat: the relay does not validate the inner-type byte;
	// a future inner-type extension (e.g. 0x03 reserved for a v1.x
	// add-on) must round-trip end-to-end without change.
	wsURL, hub := startTestRelay(t)
	ctxs, conns, ids := setupMesh(t, wsURL, 2)
	idA, idB := ids[0].Ed25519Pub, ids[1].Ed25519Pub
	becomeFriends(t, hub, ctxs[0], ctxs[1], conns[0], conns[1], idA, idB)

	frame := makeTestEnvelope(t, idB, 0x7E, 32)
	if err := conns[0].Write(ctxs[0], websocket.MessageBinary, frame); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	frameIn := readBinary(t, ctxs[1], conns[1])
	if frameIn[0] != 0x7E {
		t.Errorf("unknown inner-type 0x7E mutated in forward: got 0x%02x", frameIn[0])
	}
}
