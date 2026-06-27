// Package client implements a Go relay client: the browser-side half of the
// LemurPouch protocol (connection handshake, discovery, friendship, encrypted
// envelopes, and file transfers) reimplemented for a native CLI/TUI. It
// mirrors the TypeScript client in web/src so the two interop bit-for-bit.
//
// A Client runs a read loop and a write loop over one outbound WebSocket to a
// relay. State (peers, friendships, in-flight transfers) is owned by the
// Client; callers observe changes through the Events channel and drive
// actions through the command methods (Invite/Accept/Reject, SendFile,
// AcceptTransfer/RejectTransfer). All state is session-scoped, matching the
// relay — AGENTS.md "Session Lifetime".
package client

import "github.com/steelbrain/lemur-pouch/internal/cryptoid"

// PeerInfo is the client-facing view of a discovered peer. Fingerprint is the
// six-word BIP-39 rendering of Ed25519Pub (AGENTS.md "Fingerprint"), the only
// human-readable name for a peer.
type PeerInfo struct {
	Ed25519Pub  []byte
	X25519Pub   []byte
	Fingerprint string
	IP          string
	Port        int
}

func peerInfoFrom(ed, x []byte, ip string, port int) PeerInfo {
	return PeerInfo{
		Ed25519Pub:  ed,
		X25519Pub:   x,
		Fingerprint: cryptoid.Fingerprint(ed),
		IP:          ip,
		Port:        port,
	}
}

// Direction labels a transfer from the local client's perspective.
type Direction int

const (
	Outbound Direction = iota // we are sending
	Inbound                   // we are receiving
)

// Event is the sum type emitted on Client.Events. Consumers type-switch over
// the concrete variants below.
type Event interface{ isClientEvent() }

// PeerListEvent is the discovery snapshot delivered right after connect, and
// is NOT re-sent on later changes (PeerJoined/PeerLeft carry those).
type PeerListEvent struct{ Peers []PeerInfo }

// PeerJoined / PeerLeft track the live discovery set after the initial list.
type PeerJoined struct{ Peer PeerInfo }
type PeerLeft struct{ Ed25519Pub []byte }

// InviteReceived signals an incoming friendship invite awaiting the user's
// Accept or Reject.
type InviteReceived struct{ From PeerInfo }

// FriendshipEstablished fires once per-pair session keys are derived — either
// because a peer accepted our invite, or because we accepted theirs.
type FriendshipEstablished struct{ Peer PeerInfo }

// InviteRejected / InviteDeferred / InviteAutoRejected are the relay's
// queue/log signals back to an inviter (AGENTS.md "Anti-Abuse").
type InviteRejected struct{ Ed25519Pub []byte }
type InviteDeferred struct{ Ed25519Pub []byte }
type InviteAutoRejected struct{ Ed25519Pub []byte }

// TransferOfferReceived signals an incoming file offer awaiting AcceptTransfer
// or RejectTransfer.
type TransferOfferReceived struct {
	TransferID []byte
	From       PeerInfo
	Filename   string
	Size       int64
}

// TransferStarted fires when bytes begin flowing (we got accepted, or we
// accepted an offer).
type TransferStarted struct {
	TransferID []byte
	Direction  Direction
	Filename   string
	Size       int64
}

// TransferProgress reports cumulative bytes moved. Emitted best-effort (may be
// coalesced/dropped under load); never relied on for correctness.
type TransferProgress struct {
	TransferID []byte
	Direction  Direction
	BytesDone  int64
	Total      int64
}

// TransferComplete fires on success. For inbound transfers Path is where the
// file was written.
type TransferComplete struct {
	TransferID []byte
	Direction  Direction
	Filename   string
	Path       string
}

// TransferFailed fires on rejection, integrity failure, or abort.
type TransferFailed struct {
	TransferID []byte
	Direction  Direction
	Filename   string
	Reason     string
}

// ClientError surfaces a non-fatal error (a malformed frame dropped, a failed
// local action). Fatal teardown is reported by Disconnected.
type ClientError struct{ Err error }

// Disconnected is the terminal event: the connection is gone and no further
// events will follow.
type Disconnected struct{ Err error }

func (PeerListEvent) isClientEvent()         {}
func (PeerJoined) isClientEvent()            {}
func (PeerLeft) isClientEvent()              {}
func (InviteReceived) isClientEvent()        {}
func (FriendshipEstablished) isClientEvent() {}
func (InviteRejected) isClientEvent()        {}
func (InviteDeferred) isClientEvent()        {}
func (InviteAutoRejected) isClientEvent()    {}
func (TransferOfferReceived) isClientEvent() {}
func (TransferStarted) isClientEvent()       {}
func (TransferProgress) isClientEvent()      {}
func (TransferComplete) isClientEvent()      {}
func (TransferFailed) isClientEvent()        {}
func (ClientError) isClientEvent()           {}
func (Disconnected) isClientEvent()          {}
