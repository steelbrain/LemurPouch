package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/steelbrain/lemur-pouch/internal/cryptoid"
	"github.com/steelbrain/lemur-pouch/internal/relay"
)

// startRelay spins up an in-process relay server and returns its base URL.
func startRelay(t *testing.T) string {
	t.Helper()
	hub := relay.NewHub()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", relay.HandleWebSocket(hub))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func connect(t *testing.T, url, dir string) *Client {
	t.Helper()
	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, url, id, dir)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// waitFor reads events from c until match returns true or the deadline hits.
func waitFor(t *testing.T, c *Client, match func(Event) bool) Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-c.Events():
			if _, ok := e.(Disconnected); ok && !match(e) {
				t.Fatalf("unexpected disconnect: %+v", e)
			}
			if ce, ok := e.(ClientError); ok && !match(e) {
				t.Logf("client error (non-fatal): %v", ce.Err)
			}
			if match(e) {
				return e
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event")
		}
	}
}

func matchType[T Event]() func(Event) bool {
	return func(e Event) bool {
		_, ok := e.(T)
		return ok
	}
}

// befriend connects two clients, establishes a friendship, and returns them
// (a invites, b accepts). Both clients' download dirs are temp dirs.
func befriend(t *testing.T, url string) (a, b *Client) {
	t.Helper()
	a = connect(t, url, t.TempDir())
	// Ensure a is registered before b connects so discovery ordering is
	// deterministic: b's peer-list will contain a.
	b = connect(t, url, t.TempDir())

	waitFor(t, b, func(e Event) bool {
		pl, ok := e.(PeerListEvent)
		return ok && len(pl.Peers) == 1
	})
	waitFor(t, a, matchType[PeerJoined]())

	if err := a.Invite(b.Self().Ed25519Pub); err != nil {
		t.Fatalf("invite: %v", err)
	}
	waitFor(t, b, matchType[InviteReceived]())
	if err := b.Accept(a.Self().Ed25519Pub); err != nil {
		t.Fatalf("accept: %v", err)
	}
	waitFor(t, b, matchType[FriendshipEstablished]())
	waitFor(t, a, matchType[FriendshipEstablished]())
	return a, b
}

func TestEndToEndTransfer(t *testing.T) {
	url := startRelay(t)
	a, b := befriend(t, url)

	// Source file: a few hundred KB so it spans multiple 64 KiB chunks.
	payload := make([]byte, 300*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := a.SendFile(b.Self().Ed25519Pub, src); err != nil {
		t.Fatalf("send file: %v", err)
	}
	off := waitFor(t, b, matchType[TransferOfferReceived]()).(TransferOfferReceived)
	if off.Filename != "source.bin" || off.Size != int64(len(payload)) {
		t.Fatalf("offer mismatch: %+v", off)
	}
	if err := b.AcceptTransfer(off.TransferID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}

	done := waitFor(t, b, matchType[TransferComplete]()).(TransferComplete)
	waitFor(t, a, matchType[TransferComplete]())

	got, err := os.ReadFile(done.Path)
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received bytes differ from source (got %d, want %d)", len(got), len(payload))
	}
}

func TestEmptyFileTransfer(t *testing.T) {
	url := startRelay(t)
	a, b := befriend(t, url)

	src := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(src, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SendFile(b.Self().Ed25519Pub, src); err != nil {
		t.Fatalf("send: %v", err)
	}
	off := waitFor(t, b, matchType[TransferOfferReceived]()).(TransferOfferReceived)
	if err := b.AcceptTransfer(off.TransferID); err != nil {
		t.Fatal(err)
	}
	done := waitFor(t, b, matchType[TransferComplete]()).(TransferComplete)
	got, err := os.ReadFile(done.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(got))
	}
}

func TestTransferReject(t *testing.T) {
	url := startRelay(t)
	a, b := befriend(t, url)

	src := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SendFile(b.Self().Ed25519Pub, src); err != nil {
		t.Fatal(err)
	}
	off := waitFor(t, b, matchType[TransferOfferReceived]()).(TransferOfferReceived)
	if err := b.RejectTransfer(off.TransferID, "no thanks"); err != nil {
		t.Fatal(err)
	}
	fail := waitFor(t, a, matchType[TransferFailed]()).(TransferFailed)
	if fail.Direction != Outbound || fail.Reason != "no thanks" {
		t.Fatalf("unexpected failure: %+v", fail)
	}
}

func TestFriendshipRejection(t *testing.T) {
	url := startRelay(t)
	a := connect(t, url, t.TempDir())
	b := connect(t, url, t.TempDir())
	waitFor(t, b, matchType[PeerListEvent]())
	waitFor(t, a, matchType[PeerJoined]())

	if err := a.Invite(b.Self().Ed25519Pub); err != nil {
		t.Fatal(err)
	}
	waitFor(t, b, matchType[InviteReceived]())
	if err := b.Reject(a.Self().Ed25519Pub); err != nil {
		t.Fatal(err)
	}
	waitFor(t, a, matchType[InviteRejected]())
}

func TestPeerLeftAbortsTransfer(t *testing.T) {
	url := startRelay(t)
	a, b := befriend(t, url)

	payload := make([]byte, 5*1024*1024) // large enough to still be streaming
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SendFile(b.Self().Ed25519Pub, src); err != nil {
		t.Fatal(err)
	}
	off := waitFor(t, b, matchType[TransferOfferReceived]()).(TransferOfferReceived)
	if err := b.AcceptTransfer(off.TransferID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, b, matchType[TransferStarted]())
	// b vanishes mid-stream; a must observe peer-left and abort the transfer.
	b.Close()
	waitFor(t, a, func(e Event) bool {
		_, left := e.(PeerLeft)
		_, failed := e.(TransferFailed)
		return left || failed
	})
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"http://1.2.3.4:8080/": "ws://1.2.3.4:8080/ws",
		"http://1.2.3.4:8080":  "ws://1.2.3.4:8080/ws",
		"https://host/":        "wss://host/ws",
		"ws://host:9/ws":       "ws://host:9/ws",
		"1.2.3.4:8080":         "ws://1.2.3.4:8080/ws",
		"wss://host/custom":    "wss://host/custom",
	}
	for in, want := range cases {
		got, err := normalizeURL(in)
		if err != nil {
			t.Errorf("normalizeURL(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := normalizeURL(""); err == nil {
		t.Error("expected error for empty URL")
	}
	if _, err := normalizeURL("ftp://host"); err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestUniquePath(t *testing.T) {
	dir := t.TempDir()
	p1, err := uniquePath(dir, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p1) != "a.txt" {
		t.Fatalf("got %q", p1)
	}
	os.WriteFile(p1, nil, 0o644)
	p2, err := uniquePath(dir, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p2) != "a (1).txt" {
		t.Fatalf("collision resolution: got %q", p2)
	}
	// Path traversal is stripped to the base name.
	p3, _ := uniquePath(dir, "../../etc/passwd")
	if filepath.Dir(p3) != dir {
		t.Fatalf("traversal not contained: %q", p3)
	}
}

func TestChunkCount(t *testing.T) {
	cases := map[int64]uint64{0: 1, 1: 1, 65536: 1, 65537: 2, 131072: 2}
	for size, want := range cases {
		if got := chunkCount(size); got != want {
			t.Errorf("chunkCount(%d) = %d, want %d", size, got, want)
		}
	}
}

func TestEventTypesDistinct(t *testing.T) {
	// Sanity: the event interface is implemented by the expected set.
	var evs = []Event{
		PeerListEvent{}, PeerJoined{}, PeerLeft{}, InviteReceived{},
		FriendshipEstablished{}, InviteRejected{}, InviteDeferred{},
		InviteAutoRejected{}, TransferOfferReceived{}, TransferStarted{},
		TransferProgress{}, TransferComplete{}, TransferFailed{},
		ClientError{}, Disconnected{},
	}
	seen := map[reflect.Type]bool{}
	for _, e := range evs {
		ty := reflect.TypeOf(e)
		if seen[ty] {
			t.Errorf("duplicate event type %v", ty)
		}
		seen[ty] = true
	}
}
