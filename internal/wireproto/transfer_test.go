package wireproto

import (
	"bytes"
	"encoding/json"
	"testing"
)

func tid() []byte {
	b := make([]byte, TransferIDLen)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func sha() []byte {
	b := make([]byte, SHA256Len)
	for i := range b {
		b[i] = byte(255 - i)
	}
	return b
}

func TestTransferOfferRoundTrip(t *testing.T) {
	raw, err := MarshalTransferOffer(tid(), "report.pdf", 1048576)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, err := ParseTransferOffer(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(m.TransferID, tid()) || m.Filename != "report.pdf" || m.Size != 1048576 {
		t.Fatalf("round-trip mismatch: %+v", m)
	}
}

func TestTransferAcceptRoundTrip(t *testing.T) {
	raw, err := MarshalTransferAccept(tid(), nil, nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, err := ParseTransferAccept(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(m.TransferID, tid()) {
		t.Fatalf("round-trip mismatch: %+v", m)
	}
	if m.MaxChunkBytes != nil || m.WindowBytes != nil {
		t.Fatalf("legacy accept should omit capacity fields: %+v", m)
	}
}

func TestTransferAcceptWithLimitsRoundTrip(t *testing.T) {
	maxC, win := PreferredChunkSize, DefaultWindowBytes
	raw, err := MarshalTransferAccept(tid(), &maxC, &win)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Pin field names for Go-TS interop.
	for _, want := range []string{`"max_chunk_bytes"`, `"window_bytes"`, `"transfer_id"`, `"type"`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("missing field %s in %s", want, raw)
		}
	}
	m, err := ParseTransferAccept(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.MaxChunkBytes == nil || *m.MaxChunkBytes != PreferredChunkSize {
		t.Fatalf("max_chunk_bytes = %v", m.MaxChunkBytes)
	}
	if m.WindowBytes == nil || *m.WindowBytes != DefaultWindowBytes {
		t.Fatalf("window_bytes = %v", m.WindowBytes)
	}
}

func TestTransferAcceptFloorsSubFloorChunk(t *testing.T) {
	tiny := 1000
	raw, err := MarshalTransferAccept(tid(), &tiny, nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, err := ParseTransferAccept(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.MaxChunkBytes == nil || *m.MaxChunkBytes != ChunkDataSize {
		t.Fatalf("expected floor %d, got %v", ChunkDataSize, m.MaxChunkBytes)
	}
}

func TestTransferAckRoundTrip(t *testing.T) {
	raw, err := MarshalTransferAck(tid(), 123456789)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"type"`, `"transfer_id"`, `"received_bytes"`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("missing field %s in %s", want, raw)
		}
	}
	m, err := ParseTransferAck(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(m.TransferID, tid()) || m.ReceivedBytes != 123456789 {
		t.Fatalf("round-trip mismatch: %+v", m)
	}
}

func TestParseTransferAckIgnoresUnknownFields(t *testing.T) {
	// Additive: unknown JSON fields must not break parsers.
	raw := []byte(`{"type":"transfer-ack","transfer_id":"AAAAAAAAAAAAAAAAAAAAAA==","received_bytes":1,"future":true}`)
	m, err := ParseTransferAck(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.ReceivedBytes != 1 {
		t.Fatalf("got %+v", m)
	}
}

func TestParseUnknownTransferControlTypeDropped(t *testing.T) {
	// Mirrors TS parseTransferControl returning null for unknown types.
	raw := []byte(`{"type":"transfer-future","transfer_id":"AAAAAAAAAAAAAAAAAAAAAA=="}`)
	if _, err := ParseTransferOffer(raw); err == nil {
		t.Fatal("expected type mismatch")
	}
	if _, err := ParseTransferAck(raw); err == nil {
		t.Fatal("expected type mismatch for ack parser")
	}
}

func TestTransferRejectRoundTrip(t *testing.T) {
	raw, err := MarshalTransferReject(tid(), "out of disk")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, err := ParseTransferReject(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(m.TransferID, tid()) || m.Reason != "out of disk" {
		t.Fatalf("round-trip mismatch: %+v", m)
	}
}

func TestTransferRejectOmitsEmptyReason(t *testing.T) {
	raw, err := MarshalTransferReject(tid(), "")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := generic["reason"]; ok {
		t.Fatalf("empty reason should be omitted, got %s", raw)
	}
}

func TestTransferEndRoundTrip(t *testing.T) {
	raw, err := MarshalTransferEnd(tid(), sha())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m, err := ParseTransferEnd(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(m.TransferID, tid()) || !bytes.Equal(m.SHA256, sha()) {
		t.Fatalf("round-trip mismatch: %+v", m)
	}
}

func TestTransferControlFieldNames(t *testing.T) {
	raw, _ := MarshalTransferOffer(tid(), "f", 1)
	for _, want := range []string{`"type"`, `"transfer_id"`, `"filename"`, `"size"`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("transfer-offer missing field %s: %s", want, raw)
		}
	}
	raw, _ = MarshalTransferEnd(tid(), sha())
	if !bytes.Contains(raw, []byte(`"sha256"`)) {
		t.Errorf("transfer-end missing sha256: %s", raw)
	}
}

func TestTransferControlTypeStrings(t *testing.T) {
	cases := map[string]string{
		TypeTransferOffer:  "transfer-offer",
		TypeTransferAccept: "transfer-accept",
		TypeTransferReject: "transfer-reject",
		TypeTransferEnd:    "transfer-end",
		TypeTransferAck:    "transfer-ack",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("type string drift: %q != %q", got, want)
		}
	}
}

func TestTransferOfferRejectsBadInputs(t *testing.T) {
	if _, err := MarshalTransferOffer(make([]byte, 15), "f", 1); err == nil {
		t.Error("expected error for short transfer_id")
	}
	if _, err := MarshalTransferOffer(tid(), "f", -1); err == nil {
		t.Error("expected error for negative size")
	}
	// Parser rejects a JSON null transfer_id (decodes to nil → len 0).
	if _, err := ParseTransferOffer([]byte(`{"type":"transfer-offer","transfer_id":null,"filename":"f","size":1}`)); err == nil {
		t.Error("expected error for null transfer_id")
	}
	// Parser rejects negative size.
	bad := []byte(`{"type":"transfer-offer","transfer_id":"AAAAAAAAAAAAAAAAAAAAAA==","filename":"f","size":-5}`)
	if _, err := ParseTransferOffer(bad); err == nil {
		t.Error("expected error for negative size on parse")
	}
}

func TestTransferEndRejectsBadInputs(t *testing.T) {
	if _, err := MarshalTransferEnd(tid(), make([]byte, 31)); err == nil {
		t.Error("expected error for short sha256")
	}
	if _, err := ParseTransferEnd([]byte(`{"type":"transfer-end","transfer_id":"AAAAAAAAAAAAAAAAAAAAAA==","sha256":null}`)); err == nil {
		t.Error("expected error for null sha256")
	}
}

func TestTransferParsersRejectWrongType(t *testing.T) {
	raw, _ := MarshalTransferAccept(tid(), nil, nil)
	if _, err := ParseTransferOffer(raw); err == nil {
		t.Error("expected type mismatch error")
	}
}

func TestWelcomeLimitsJSONFieldNames(t *testing.T) {
	data, err := MarshalWelcome(WelcomeMsg{
		You: PeerRecord{
			Ed25519Pub: make([]byte, 32),
			X25519Pub:  make([]byte, 32),
			SigBinding: make([]byte, 64),
			IP:         "10.0.0.1",
			Port:       1,
		},
		Limits: &WelcomeLimits{MaxChunkBytes: MaxChunkBytes},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"limits"`, `"max_chunk_bytes"`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("welcome missing %s: %s", want, data)
		}
	}
	// Absent limits must omit the field (old-relay shape).
	data2, err := MarshalWelcome(WelcomeMsg{
		You: PeerRecord{
			Ed25519Pub: make([]byte, 32),
			X25519Pub:  make([]byte, 32),
			SigBinding: make([]byte, 64),
			IP:         "10.0.0.1",
			Port:       1,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(data2, []byte(`"limits"`)) {
		t.Fatalf("absent limits should be omitted: %s", data2)
	}
}
