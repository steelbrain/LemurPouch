package wireproto

import (
	"encoding/json"
	"fmt"
)

// Transfer-control messages — the inner-type 0x01 (JSON control) payloads
// that ride encrypted inside binary envelopes once a friendship exists. See
// AGENTS.md "Encrypted Envelopes > Inner type 0x01 — JSON control". The
// relay never sees these; they are the TS `portal/src/transfer/control.ts`
// shapes mirrored Go-side so a Go client and the browser interop.
//
// Field names are snake_case on the wire (matching the TS encoder and Go's
// json struct tags). Byte fields (TransferID, SHA256) are RFC 4648 base64 of
// the raw bytes — Go's encoding/json does this automatically for []byte.

// Type discriminators for transfer-control messages.
const (
	TypeTransferOffer  = "transfer-offer"
	TypeTransferAccept = "transfer-accept"
	TypeTransferReject = "transfer-reject"
	TypeTransferEnd    = "transfer-end"
	TypeTransferAck    = "transfer-ack"
)

// Fixed byte lengths for transfer-control fields.
const (
	// TransferIDLen is the random per-transfer identifier length. Lets the
	// recipient distinguish concurrent transfers between the same pair.
	TransferIDLen = 16
	// SHA256Len is the digest length carried on transfer-end.
	SHA256Len = 32
)

// TransferOffer announces a file the sender wishes to send. SHA256 rides on
// transfer-end (not here): both peers hash incrementally as bytes stream, so
// the digest only exists once the last chunk is sent.
type TransferOffer struct {
	Type       string `json:"type"`
	TransferID []byte `json:"transfer_id"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
}

// TransferAccept is the recipient's consent to receive the offered file.
// MaxChunkBytes and WindowBytes are optional receiver-capacity ads: absent
// (or 0 after parse) means legacy 64 KiB chunks with unwindowed streaming.
// Pointers so omitempty drops them for old-style accepts and so a missing
// JSON field is distinguishable from an explicit zero.
type TransferAccept struct {
	Type          string `json:"type"`
	TransferID    []byte `json:"transfer_id"`
	MaxChunkBytes *int   `json:"max_chunk_bytes,omitempty"`
	WindowBytes   *int   `json:"window_bytes,omitempty"`
}

// TransferAck is a cumulative receiver→sender progress signal used for
// windowed flow control. ReceivedBytes is monotonic and idempotent.
type TransferAck struct {
	Type          string `json:"type"`
	TransferID    []byte `json:"transfer_id"`
	ReceivedBytes int64  `json:"received_bytes"`
}

// TransferReject declines the offer. Reason is optional human-readable
// detail; it is omitted from the wire when empty.
type TransferReject struct {
	Type       string `json:"type"`
	TransferID []byte `json:"transfer_id"`
	Reason     string `json:"reason,omitempty"`
}

// TransferEnd terminates a transfer after the last chunk, carrying the
// sender's finalized SHA-256 of the payload for end-to-end integrity.
type TransferEnd struct {
	Type       string `json:"type"`
	TransferID []byte `json:"transfer_id"`
	SHA256     []byte `json:"sha256"`
}

func MarshalTransferOffer(transferID []byte, filename string, size int64) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	if size < 0 {
		return nil, fmt.Errorf("wireproto: size must be non-negative, got %d", size)
	}
	return json.Marshal(TransferOffer{Type: TypeTransferOffer, TransferID: transferID, Filename: filename, Size: size})
}

// MarshalTransferAccept builds a transfer-accept. Pass nil for maxChunk/window
// to emit a legacy accept (no capacity fields). Non-nil values are floored
// at ChunkDataSize for maxChunk; window is left as-is (0 is meaningful only
// when the field is present — callers that want windowing pass a positive).
func MarshalTransferAccept(transferID []byte, maxChunkBytes, windowBytes *int) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	m := TransferAccept{Type: TypeTransferAccept, TransferID: transferID}
	if maxChunkBytes != nil {
		v := FloorChunkSize(*maxChunkBytes)
		m.MaxChunkBytes = &v
	}
	if windowBytes != nil {
		v := *windowBytes
		m.WindowBytes = &v
	}
	return json.Marshal(m)
}

func MarshalTransferAck(transferID []byte, receivedBytes int64) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	if receivedBytes < 0 {
		return nil, fmt.Errorf("wireproto: received_bytes must be non-negative, got %d", receivedBytes)
	}
	return json.Marshal(TransferAck{Type: TypeTransferAck, TransferID: transferID, ReceivedBytes: receivedBytes})
}

func MarshalTransferReject(transferID []byte, reason string) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	return json.Marshal(TransferReject{Type: TypeTransferReject, TransferID: transferID, Reason: reason})
}

func MarshalTransferEnd(transferID, sha256 []byte) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	if len(sha256) != SHA256Len {
		return nil, fmt.Errorf("wireproto: sha256 must be %d bytes, got %d", SHA256Len, len(sha256))
	}
	return json.Marshal(TransferEnd{Type: TypeTransferEnd, TransferID: transferID, SHA256: sha256})
}

// ParseTransferOffer validates and decodes a transfer-offer payload. Like the
// TS parsers it rejects wrong-length / nil byte fields (a nil TransferID from
// a JSON null marshals to length 0) and negative sizes at the boundary.
func ParseTransferOffer(data []byte) (TransferOffer, error) {
	var m TransferOffer
	if err := json.Unmarshal(data, &m); err != nil {
		return TransferOffer{}, fmt.Errorf("wireproto: parse transfer-offer: %w", err)
	}
	if m.Type != TypeTransferOffer {
		return TransferOffer{}, fmt.Errorf("wireproto: expected %q, got %q", TypeTransferOffer, m.Type)
	}
	if len(m.TransferID) != TransferIDLen {
		return TransferOffer{}, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(m.TransferID))
	}
	if m.Size < 0 {
		return TransferOffer{}, fmt.Errorf("wireproto: size must be non-negative, got %d", m.Size)
	}
	return m, nil
}

func ParseTransferAccept(data []byte) (TransferAccept, error) {
	var m TransferAccept
	if err := json.Unmarshal(data, &m); err != nil {
		return TransferAccept{}, fmt.Errorf("wireproto: parse transfer-accept: %w", err)
	}
	if m.Type != TypeTransferAccept {
		return TransferAccept{}, fmt.Errorf("wireproto: expected %q, got %q", TypeTransferAccept, m.Type)
	}
	if len(m.TransferID) != TransferIDLen {
		return TransferAccept{}, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(m.TransferID))
	}
	if m.MaxChunkBytes != nil {
		v := FloorChunkSize(*m.MaxChunkBytes)
		m.MaxChunkBytes = &v
	}
	if m.WindowBytes != nil && *m.WindowBytes < 0 {
		return TransferAccept{}, fmt.Errorf("wireproto: window_bytes must be non-negative, got %d", *m.WindowBytes)
	}
	return m, nil
}

func ParseTransferAck(data []byte) (TransferAck, error) {
	var m TransferAck
	if err := json.Unmarshal(data, &m); err != nil {
		return TransferAck{}, fmt.Errorf("wireproto: parse transfer-ack: %w", err)
	}
	if m.Type != TypeTransferAck {
		return TransferAck{}, fmt.Errorf("wireproto: expected %q, got %q", TypeTransferAck, m.Type)
	}
	if len(m.TransferID) != TransferIDLen {
		return TransferAck{}, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(m.TransferID))
	}
	if m.ReceivedBytes < 0 {
		return TransferAck{}, fmt.Errorf("wireproto: received_bytes must be non-negative, got %d", m.ReceivedBytes)
	}
	return m, nil
}

func ParseTransferReject(data []byte) (TransferReject, error) {
	var m TransferReject
	if err := json.Unmarshal(data, &m); err != nil {
		return TransferReject{}, fmt.Errorf("wireproto: parse transfer-reject: %w", err)
	}
	if m.Type != TypeTransferReject {
		return TransferReject{}, fmt.Errorf("wireproto: expected %q, got %q", TypeTransferReject, m.Type)
	}
	if len(m.TransferID) != TransferIDLen {
		return TransferReject{}, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(m.TransferID))
	}
	return m, nil
}

func ParseTransferEnd(data []byte) (TransferEnd, error) {
	var m TransferEnd
	if err := json.Unmarshal(data, &m); err != nil {
		return TransferEnd{}, fmt.Errorf("wireproto: parse transfer-end: %w", err)
	}
	if m.Type != TypeTransferEnd {
		return TransferEnd{}, fmt.Errorf("wireproto: expected %q, got %q", TypeTransferEnd, m.Type)
	}
	if len(m.TransferID) != TransferIDLen {
		return TransferEnd{}, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(m.TransferID))
	}
	if len(m.SHA256) != SHA256Len {
		return TransferEnd{}, fmt.Errorf("wireproto: sha256 must be %d bytes, got %d", SHA256Len, len(m.SHA256))
	}
	return m, nil
}
