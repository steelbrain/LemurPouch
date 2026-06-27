package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"

	"github.com/steelbrain/lemur-pouch/internal/client"
)

// newTestModel builds a model without a live client. handleEvent only
// dereferences m.client inside the (unexecuted) returned command, so folding
// and rendering work with a nil client.
func newTestModel() model {
	return model{
		self:        client.PeerInfo{Fingerprint: "abandon-ladder-quantum-tribe-yellow-velvet"},
		relayURL:    "ws://127.0.0.1:8080/ws",
		downloadDir: "/tmp/dl",
		states:      make(map[string]peerState),
		xferByID:    make(map[string]*xfer),
		input:       textinput.New(),
	}
}

func ed(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func tidBytes(b byte) []byte {
	k := make([]byte, 16)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestPeerListAndJoinLeave(t *testing.T) {
	m := newTestModel()
	p := client.PeerInfo{Ed25519Pub: ed(1), Fingerprint: "a-b-c-d-e-f", IP: "10.0.0.2", Port: 5}

	mi, _ := m.handleEvent(client.PeerListEvent{Peers: []client.PeerInfo{p}})
	m = mi.(model)
	if len(m.peers) != 1 {
		t.Fatalf("peer-list: got %d peers", len(m.peers))
	}

	q := client.PeerInfo{Ed25519Pub: ed(2), Fingerprint: "g-h-i-j-k-l"}
	mi, _ = m.handleEvent(client.PeerJoined{Peer: q})
	m = mi.(model)
	if len(m.peers) != 2 {
		t.Fatalf("peer-joined: got %d peers", len(m.peers))
	}

	mi, _ = m.handleEvent(client.PeerLeft{Ed25519Pub: ed(1)})
	m = mi.(model)
	if len(m.peers) != 1 || hexOf(m.peers[0].Ed25519Pub) != hexOf(ed(2)) {
		t.Fatalf("peer-left: unexpected peers %+v", m.peers)
	}
}

func TestFriendshipStateTransitions(t *testing.T) {
	m := newTestModel()
	peer := client.PeerInfo{Ed25519Pub: ed(7), Fingerprint: "a-b-c-d-e-f"}

	mi, _ := m.handleEvent(client.InviteReceived{From: peer})
	m = mi.(model)
	if m.stateOf(ed(7)) != peerIncoming {
		t.Fatalf("expected peerIncoming, got %v", m.stateOf(ed(7)))
	}
	if !m.hasPeer(ed(7)) {
		t.Fatal("invite should surface the peer in the list")
	}

	mi, _ = m.handleEvent(client.FriendshipEstablished{Peer: peer})
	m = mi.(model)
	if m.stateOf(ed(7)) != peerFriend {
		t.Fatalf("expected peerFriend, got %v", m.stateOf(ed(7)))
	}
}

func TestTransferOfferLifecycle(t *testing.T) {
	m := newTestModel()
	id := tidBytes(9)
	from := client.PeerInfo{Ed25519Pub: ed(3), Fingerprint: "a-b-c-d-e-f"}

	mi, _ := m.handleEvent(client.TransferOfferReceived{TransferID: id, From: from, Filename: "doc.pdf", Size: 2048})
	m = mi.(model)
	if len(m.offers) != 1 || len(m.xfers) != 1 {
		t.Fatalf("offer not registered: offers=%d xfers=%d", len(m.offers), len(m.xfers))
	}

	mi, _ = m.handleEvent(client.TransferStarted{TransferID: id, Direction: client.Inbound, Size: 2048})
	m = mi.(model)
	mi, _ = m.handleEvent(client.TransferProgress{TransferID: id, Direction: client.Inbound, BytesDone: 1024, Total: 2048})
	m = mi.(model)
	if x := m.xferByID[hexOf(id)]; x == nil || x.status != xferActive || x.done != 1024 {
		t.Fatalf("progress not applied: %+v", m.xferByID[hexOf(id)])
	}

	mi, _ = m.handleEvent(client.TransferComplete{TransferID: id, Direction: client.Inbound, Filename: "doc.pdf", Path: "/tmp/dl/doc.pdf"})
	m = mi.(model)
	if x := m.xferByID[hexOf(id)]; x.status != xferDone || x.detail != "/tmp/dl/doc.pdf" {
		t.Fatalf("complete not applied: %+v", m.xferByID[hexOf(id)])
	}
}

func TestTransferFailedDropsOffer(t *testing.T) {
	m := newTestModel()
	id := tidBytes(4)
	mi, _ := m.handleEvent(client.TransferOfferReceived{TransferID: id, From: client.PeerInfo{Ed25519Pub: ed(1)}, Filename: "x", Size: 1})
	m = mi.(model)
	mi, _ = m.handleEvent(client.TransferFailed{TransferID: id, Direction: client.Inbound, Filename: "x", Reason: "boom"})
	m = mi.(model)
	if len(m.offers) != 0 {
		t.Fatalf("failed transfer should drop the pending offer, have %d", len(m.offers))
	}
	if x := m.xferByID[hexOf(id)]; x.status != xferFailed {
		t.Fatalf("expected failed, got %v", x.status)
	}
}

func TestDisconnectedStopsListening(t *testing.T) {
	m := newTestModel()
	mi, cmd := m.handleEvent(client.Disconnected{Err: nil})
	m = mi.(model)
	if !m.disconnected {
		t.Fatal("expected disconnected flag")
	}
	if cmd != nil {
		t.Fatal("should not re-arm the event listener after disconnect")
	}
}

func TestViewRendersKeyState(t *testing.T) {
	m := newTestModel()
	m.peers = []client.PeerInfo{{Ed25519Pub: ed(1), Fingerprint: "a-b-c-d-e-f", IP: "10.0.0.9", Port: 7}}
	m.states[hexOf(ed(1))] = peerFriend
	m.addXfer(&xfer{id: "z", dir: client.Outbound, filename: "f.bin", status: xferActive, done: 50, total: 100})
	out := m.View()
	for _, want := range []string{"LemurPouch", "PEERS", "TRANSFERS", "10.0.0.9:7", "f.bin", "connected"} {
		if !strings.Contains(stripANSI(out), want) {
			t.Errorf("view missing %q\n---\n%s", want, stripANSI(out))
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 512: "512 B", 1024: "1.0 KB", 1536: "1.5 KB", 1048576: "1.0 MB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"  /tmp/a.txt  ":           "/tmp/a.txt",
		`/tmp/Screenshot\ 01.png`:  "/tmp/Screenshot 01.png",
		`/a/b\ c\ d.png`:           "/a/b c d.png",
		`"/tmp/with space.txt"`:    "/tmp/with space.txt",
		"'/tmp/single quoted.txt'": "/tmp/single quoted.txt",
		`/no/escapes/here.bin`:     "/no/escapes/here.bin",
		`/paren\(s\).png`:          "/paren(s).png",
	}
	for in, want := range cases {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	if got := expandHome("~"); got != home {
		t.Errorf("expandHome(~) = %q, want %q", got, home)
	}
	if got := expandHome("~/Downloads/x"); got != filepath.Join(home, "Downloads/x") {
		t.Errorf("expandHome(~/Downloads/x) = %q", got)
	}
	if got := expandHome("/abs/path"); got != "/abs/path" {
		t.Errorf("expandHome left absolute path alone: %q", got)
	}
}

func TestShortFP(t *testing.T) {
	if got := shortFP("a-b-c-d-e-f"); got != "a-b-c-…" {
		t.Errorf("shortFP long = %q", got)
	}
	if got := shortFP("a-b"); got != "a-b" {
		t.Errorf("shortFP short = %q", got)
	}
}

// stripANSI removes lipgloss color escapes so substring assertions are stable
// regardless of the test terminal's color profile.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
