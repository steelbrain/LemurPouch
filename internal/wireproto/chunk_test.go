package wireproto

import (
	"bytes"
	"testing"
)

func TestChunkRoundTrip(t *testing.T) {
	data := []byte("hello chunk payload")
	frame, err := MarshalChunk(tid(), 7, ChunkFlagLast, data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, err := ParseChunk(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(c.TransferID, tid()) {
		t.Errorf("transfer_id mismatch")
	}
	if c.Seq != 7 {
		t.Errorf("seq = %d, want 7", c.Seq)
	}
	if !c.IsLast() {
		t.Errorf("expected last-chunk flag")
	}
	if !bytes.Equal(c.Data, data) {
		t.Errorf("data mismatch: %q", c.Data)
	}
}

func TestChunkNonLast(t *testing.T) {
	frame, err := MarshalChunk(tid(), 0, 0, []byte("x"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, err := ParseChunk(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.IsLast() {
		t.Errorf("did not expect last-chunk flag")
	}
}

func TestChunkEmptyData(t *testing.T) {
	frame, err := MarshalChunk(tid(), 0, ChunkFlagLast, nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(frame) != ChunkHeaderLen {
		t.Fatalf("empty chunk frame len = %d, want %d", len(frame), ChunkHeaderLen)
	}
	c, err := ParseChunk(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.Data) != 0 || !c.IsLast() {
		t.Errorf("empty last chunk parsed wrong: %+v", c)
	}
}

func TestMarshalChunkRejectsBadTransferID(t *testing.T) {
	if _, err := MarshalChunk(make([]byte, 15), 0, 0, nil); err == nil {
		t.Error("expected error for short transfer_id")
	}
}

func TestParseChunkRejectsShortFrame(t *testing.T) {
	if _, err := ParseChunk(make([]byte, ChunkHeaderLen-1)); err == nil {
		t.Error("expected error for short frame")
	}
}

func TestChunkBigEndianSeq(t *testing.T) {
	frame, _ := MarshalChunk(tid(), 0x01020304, 0, nil)
	got := frame[TransferIDLen : TransferIDLen+4]
	want := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(got, want) {
		t.Errorf("seq bytes = %v, want big-endian %v", got, want)
	}
}
