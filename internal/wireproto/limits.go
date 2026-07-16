package wireproto

// Transfer size / flow-control defaults. Negotiated per transfer via
// welcome.limits and transfer-accept; absence degrades to ChunkDataSize
// (legacy 64 KiB) with unwindowed streaming. See AGENTS.md "Flow Control
// & Negotiated Limits".

const (
	// PreferredChunkSize is the sender's preferred raw chunk payload size
	// when the peer and relay both advertise enough capacity.
	PreferredChunkSize = 1 << 20 // 1 MiB

	// MaxChunkBytes is the largest raw chunk-data size the relay advertises
	// on welcome (and therefore the largest it will forward).
	MaxChunkBytes = 1 << 20 // 1 MiB

	// ReadLimit is the per-connection WebSocket frame cap on the relay and
	// Go client. Sized for MaxChunkBytes of raw chunk data plus envelope
	// header (57) + Poly1305 tag (16) + chunk header (21) with headroom.
	// Trade-off: per-conn transient buffer exposure is ReadLimit × N
	// connections; acceptable for a LAN relay.
	ReadLimit = 4 << 20 // 4 MiB

	// DefaultWindowBytes is the receiver-advertised flow-control window
	// when both peers support windowing.
	DefaultWindowBytes = 8 << 20 // 8 MiB

	// StallTimeoutSec is how long:
	//   - a windowed sender waits for ack progress before "flow-control stall"
	//   - a receiver waits for peer byte/control progress before "receive stall"
	StallTimeoutSec = 30
)

// FloorChunkSize clamps an advertised chunk size to the 64 KiB floor
// (ChunkDataSize). Values below the floor break deployed receivers' seq
// bounds, which assume ceil(total / 64 KiB).
func FloorChunkSize(n int) int {
	if n < ChunkDataSize {
		return ChunkDataSize
	}
	return n
}

// NegotiateChunkSize picks the effective raw chunk size for a transfer.
// Absent peer/relay advertisements (0) are treated as the legacy floor.
// The result is never below ChunkDataSize.
func NegotiateChunkSize(preference, relayMax, acceptMax int) int {
	eff := preference
	if eff <= 0 {
		eff = PreferredChunkSize
	}
	relay := relayMax
	if relay <= 0 {
		relay = ChunkDataSize
	}
	accept := acceptMax
	if accept <= 0 {
		accept = ChunkDataSize
	}
	if relay < eff {
		eff = relay
	}
	if accept < eff {
		eff = accept
	}
	return FloorChunkSize(eff)
}

// EffectiveWindow returns the sender's in-flight byte cap. When windowBytes
// is 0 the transfer is unwindowed (legacy). Otherwise the window is at
// least 2× chunk so one outstanding chunk can never deadlock the window.
func EffectiveWindow(windowBytes, chunkSize int) int {
	if windowBytes <= 0 {
		return 0
	}
	minWin := 2 * chunkSize
	if windowBytes < minWin {
		return minWin
	}
	return windowBytes
}

// AckThreshold is how many newly received bytes trigger a transfer-ack
// (window/4). Zero window means no acks are required.
func AckThreshold(windowBytes int) int {
	if windowBytes <= 0 {
		return 0
	}
	return windowBytes / 4
}

// InFlight reports how many bytes are outstanding (sent but not yet acked).
func InFlight(sent, lastAck int64) int64 {
	if sent < lastAck {
		return 0
	}
	return sent - lastAck
}

// WindowFull reports whether the sender must block for an ack.
func WindowFull(sent, lastAck int64, windowBytes int) bool {
	if windowBytes <= 0 {
		return false
	}
	return InFlight(sent, lastAck) >= int64(windowBytes)
}

// ShouldAck reports whether the receiver should emit a cumulative ack.
func ShouldAck(received, lastAcked int64, windowBytes int) bool {
	th := AckThreshold(windowBytes)
	if th <= 0 {
		return false
	}
	return received-lastAcked >= int64(th)
}
