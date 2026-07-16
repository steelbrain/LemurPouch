package wireproto

import (
	"encoding/binary"
	"fmt"
)

// File-chunk binary format — the inner-type 0x02 payload that rides
// encrypted inside binary envelopes during a transfer's streaming phase. See
// AGENTS.md "Encrypted Envelopes > Inner type 0x02 — file chunk". Mirrors the
// TS `portal/src/transfer/chunk.ts` layout so a Go client and the browser interop.
//
//	[ 16 bytes] transfer_id
//	[ 4 bytes ] seq (uint32 big-endian)
//	[ 1 byte  ] flags  (bit 0 = last chunk)
//	[ N bytes ] raw file data       (negotiated size, floor 64 KiB)
const (
	ChunkHeaderLen = TransferIDLen + 4 + 1 // 21
	// ChunkDataSize is the legacy / floor raw bytes per chunk. Negotiated
	// transfers may use larger sizes (up to MaxChunkBytes); receivers bound
	// seq by ceil(total / ChunkDataSize) so larger chunks still validate.
	// See AGENTS.md "Flow Control & Negotiated Limits".
	ChunkDataSize = 64 * 1024
	// ChunkFlagLast marks the final chunk of a transfer.
	ChunkFlagLast byte = 0x01
)

// Chunk is a parsed file-chunk frame. Data aliases the source buffer; clone
// if a stable copy is needed past the buffer's lifetime.
type Chunk struct {
	TransferID []byte // length 16
	Seq        uint32
	Flags      byte
	Data       []byte
}

// IsLast reports whether this chunk is the last of its transfer.
func (c Chunk) IsLast() bool { return c.Flags&ChunkFlagLast != 0 }

// MarshalChunk builds a chunk frame. transferID must be exactly TransferIDLen
// bytes; data may be empty (a 0-byte file streams as a single empty last
// chunk).
func MarshalChunk(transferID []byte, seq uint32, flags byte, data []byte) ([]byte, error) {
	if len(transferID) != TransferIDLen {
		return nil, fmt.Errorf("wireproto: chunk transfer_id must be %d bytes, got %d", TransferIDLen, len(transferID))
	}
	out := make([]byte, ChunkHeaderLen+len(data))
	copy(out[:TransferIDLen], transferID)
	binary.BigEndian.PutUint32(out[TransferIDLen:TransferIDLen+4], seq)
	out[TransferIDLen+4] = flags
	copy(out[ChunkHeaderLen:], data)
	return out, nil
}

// ParseChunk extracts the fixed header and aliases the data tail. Returns an
// error if frame is shorter than ChunkHeaderLen.
func ParseChunk(frame []byte) (Chunk, error) {
	if len(frame) < ChunkHeaderLen {
		return Chunk{}, fmt.Errorf("wireproto: chunk frame too short: %d bytes (min %d)", len(frame), ChunkHeaderLen)
	}
	return Chunk{
		TransferID: frame[:TransferIDLen],
		Seq:        binary.BigEndian.Uint32(frame[TransferIDLen : TransferIDLen+4]),
		Flags:      frame[TransferIDLen+4],
		Data:       frame[ChunkHeaderLen:],
	}, nil
}
