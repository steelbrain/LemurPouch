package relay

import (
	"context"
	"log"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// envelopeWriteTimeout caps how long a single binary-envelope forward to
// the destination peer can take before being abandoned. Mirrors
// broadcastWriteTimeout in spirit — a slow recipient must not park the
// sender's read loop indefinitely. Reusing the same constant keeps the
// "max time the relay tolerates a slow peer" invariant uniform across
// the discovery, friendship, and envelope-routing paths.
const envelopeWriteTimeout = broadcastWriteTimeout

// forwardEnvelope parses a binary envelope frame from sender, looks up
// the destination identity, verifies the (sender, recipient) friendship
// is established, rewrites the peer field destination -> source, and
// forwards the frame to the destination peer. All failure modes
// (malformed frame, missing destination, no friendship, write error)
// drop the frame silently — the relay never replies inline to envelope
// frames per AGENTS.md "What the Relay Enforces".
//
// The frame buffer comes from coder/websocket's Read and is valid only
// until the caller's next Read on the same conn — this function
// completes the synchronous forward (including the Write to the
// destination) before returning, so the caller can immediately Read the
// next frame without copying.
//
// Synchronous-write trade-off: a slow recipient's Write blocks the
// sender's read loop for up to envelopeWriteTimeout. That's acceptable
// for v0 because the bound is tight and the alternative (per-forward
// goroutine + frame copy) is more code with no real-world win on a LAN.
// If we ever multiplex many concurrent transfers per pair, revisit.
func (h *Hub) forwardEnvelope(sender *Peer, frame []byte) {
	hdr, _, err := wireproto.ParseEnvelopeHeader(frame)
	if err != nil {
		log.Printf(
			"envelope from %s: %v",
			hexKey(sender.Record.Ed25519Pub)[:16], err,
		)
		return
	}

	// hdr.PeerKey aliases the frame buffer and is overwritten in place
	// by RewriteDestinationToSource below — copy it now so the post-
	// rewrite hub.lookup still sees the destination identity rather
	// than the source identity that replaces it.
	destKey := append([]byte(nil), hdr.PeerKey...)

	// Friendship gate — AGENTS.md "What the Relay Enforces": "Drops
	// envelopes for which the (sender, recipient) pair has no active
	// friendship." Drop silently to avoid logging noise from flapping
	// or pre-friendship peers; recipients that care will retry at the
	// application layer.
	if !h.fm.AreFriends(sender.Record.Ed25519Pub, destKey) {
		return
	}

	// Rewrite the peer field from destination to the sender's
	// authenticated identity, so the recipient can attribute the
	// envelope. The mutation is in place on the same buffer
	// coder/websocket's Read returned to us, which is safe because
	// (1) we don't pass the buffer to a goroutine that might outlive
	// the caller's next Read, and (2) the buffer is owned by the
	// sender's read loop, not by any other code path.
	if err := wireproto.RewriteDestinationToSource(frame, sender.Record.Ed25519Pub); err != nil {
		// Unreachable in practice — ParseEnvelopeHeader already
		// validated the length, and sender.Record.Ed25519Pub is
		// always 32 bytes. Logged at warning level rather than
		// dropped silently because reaching here implies a code-side
		// invariant violation worth investigating.
		log.Printf("envelope rewrite (unexpected): %v", err)
		return
	}

	// Resolve the destination immediately before the write so a
	// same-identity reconnect can't displace the recipient between
	// lookup and write — see writeAsyncToIdentity in friendship.go for
	// the equivalent pattern. If the destination isn't connected at
	// this instant, drop silently.
	dest := h.lookup(destKey)
	if dest == nil {
		return
	}

	// Bound the per-forward write so a slow recipient can't park the
	// sender's read loop. Rooted in context.Background, not the
	// caller's request context, because the relay's view of "is the
	// write taking too long" is independent of the request lifecycle.
	writeCtx, cancel := context.WithTimeout(context.Background(), envelopeWriteTimeout)
	defer cancel()
	if err := dest.conn.Write(writeCtx, websocket.MessageBinary, frame); err != nil {
		log.Printf(
			"envelope forward to %s: %v",
			hexKey(dest.Record.Ed25519Pub)[:16], err,
		)
	}
}
