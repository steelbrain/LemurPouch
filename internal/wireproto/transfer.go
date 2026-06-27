package wireproto

import (
	"encoding/json"
	"fmt"
)

// Transfer-control messages — the inner-type 0x01 (JSON control) payloads
// that ride encrypted inside binary envelopes once a friendship exists. See
// AGENTS.md "Encrypted Envelopes > Inner type 0x01 — JSON control". The
// relay never sees these; they are the TS `web/src/transfer/control.ts`
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
type TransferAccept struct {
	Type       string `json:"type"`
	TransferID []byte `json:"transfer_id"`
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

func MarshalTransferAccept(transferID []byte) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	return json.Marshal(TransferAccept{Type: TypeTransferAccept, TransferID: transferID})
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
