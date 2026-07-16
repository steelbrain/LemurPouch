package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/steelbrain/LemurPouch/internal/client"
)

// handleEvent folds a client event into the model and re-arms the event
// listener (unless the connection has terminated).
func (m model) handleEvent(ev client.Event) (tea.Model, tea.Cmd) {
	switch e := ev.(type) {
	case client.PeerListEvent:
		m.peers = e.Peers
		m.clampCursor()
	case client.PeerJoined:
		if !m.hasPeer(e.Peer.Ed25519Pub) {
			m.peers = append(m.peers, e.Peer)
		}
	case client.PeerLeft:
		m.removePeer(e.Ed25519Pub)
		delete(m.states, hexOf(e.Ed25519Pub))
		m.clampCursor()
	case client.InviteReceived:
		if !m.hasPeer(e.From.Ed25519Pub) {
			m.peers = append(m.peers, e.From)
		}
		m.states[hexOf(e.From.Ed25519Pub)] = peerIncoming
		m.status = shortFP(e.From.Fingerprint) + " wants to connect — [c] accept, [x] reject."
	case client.FriendshipEstablished:
		m.states[hexOf(e.Peer.Ed25519Pub)] = peerFriend
		m.status = "Connected to " + shortFP(e.Peer.Fingerprint) + "."
	case client.InviteRejected:
		m.states[hexOf(e.Ed25519Pub)] = peerNone
		m.status = "Your invite was rejected."
	case client.InviteDeferred:
		m.status = "Invite queued (an earlier invite from your network is pending)."
	case client.InviteAutoRejected:
		m.states[hexOf(e.Ed25519Pub)] = peerNone
		m.status = "Invite auto-rejected (peer previously declined your network)."
	case client.TransferOfferReceived:
		m.offers = append(m.offers, e)
		m.addXfer(&xfer{id: hexOf(e.TransferID), dir: client.Inbound, filename: e.Filename, status: xferOffered, total: e.Size})
		m.status = "Incoming file " + e.Filename + " from " + shortFP(e.From.Fingerprint) + " — [a] accept, [r] reject."
	case client.TransferStarted:
		if x := m.xferByID[hexOf(e.TransferID)]; x != nil {
			x.status = xferActive
			x.total = e.Size
		}
	case client.TransferProgress:
		if x := m.xferByID[hexOf(e.TransferID)]; x != nil {
			x.status = xferActive
			now := time.Now().UnixNano()
			if x.lastProgAt > 0 && e.BytesDone >= x.lastDone {
				dt := float64(now-x.lastProgAt) / 1e9
				if dt > 0 {
					instant := float64(e.BytesDone-x.lastDone) / dt
					// EMA τ ≈ 3 s: alpha = dt / (τ + dt)
					if x.rateBps <= 0 {
						x.rateBps = instant
					} else {
						alpha := dt / (3.0 + dt)
						x.rateBps += alpha * (instant - x.rateBps)
					}
				}
			}
			x.lastProgAt = now
			x.lastDone = e.BytesDone
			x.done = e.BytesDone
			x.total = e.Total
		}
	case client.TransferComplete:
		if x := m.xferByID[hexOf(e.TransferID)]; x != nil {
			x.status = xferDone
			x.done = x.total
			x.detail = e.Path
		}
		if e.Direction == client.Inbound {
			m.status = "Received " + e.Filename + " → " + e.Path
		} else {
			m.status = "Sent " + e.Filename + "."
		}
	case client.TransferFailed:
		if x := m.xferByID[hexOf(e.TransferID)]; x != nil {
			x.status = xferFailed
			x.detail = e.Reason
		}
		m.dropOffer(e.TransferID)
		m.status = "Transfer of " + e.Filename + " failed: " + e.Reason
	case client.ClientError:
		// Non-fatal; surface quietly without clobbering an action result.
		m.status = "note: " + e.Err.Error()
	case client.Disconnected:
		m.disconnected = true
		m.disconnectErr = e.Err
		if e.Err != nil {
			m.status = "Disconnected: " + e.Err.Error() + " — press q to quit."
		} else {
			m.status = "Disconnected from relay — press q to quit."
		}
		return m, nil
	}
	return m, waitForEvent(m.client)
}

func (m *model) hasPeer(ed []byte) bool {
	key := hexOf(ed)
	for _, p := range m.peers {
		if hexOf(p.Ed25519Pub) == key {
			return true
		}
	}
	return false
}

func (m *model) removePeer(ed []byte) {
	key := hexOf(ed)
	out := m.peers[:0]
	for _, p := range m.peers {
		if hexOf(p.Ed25519Pub) != key {
			out = append(out, p)
		}
	}
	m.peers = out
}

func (m *model) dropOffer(transferID []byte) {
	key := hexOf(transferID)
	out := m.offers[:0]
	for _, o := range m.offers {
		if hexOf(o.TransferID) != key {
			out = append(out, o)
		}
	}
	m.offers = out
}

func (m *model) clampCursor() {
	if m.cursor >= len(m.peers) {
		m.cursor = len(m.peers) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}
