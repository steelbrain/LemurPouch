package wireproto

import "testing"

func TestFloorChunkSize(t *testing.T) {
	if got := FloorChunkSize(0); got != ChunkDataSize {
		t.Fatalf("FloorChunkSize(0) = %d, want %d", got, ChunkDataSize)
	}
	if got := FloorChunkSize(1000); got != ChunkDataSize {
		t.Fatalf("FloorChunkSize(1000) = %d, want %d", got, ChunkDataSize)
	}
	if got := FloorChunkSize(ChunkDataSize); got != ChunkDataSize {
		t.Fatalf("FloorChunkSize(floor) = %d", got)
	}
	if got := FloorChunkSize(PreferredChunkSize); got != PreferredChunkSize {
		t.Fatalf("FloorChunkSize(1MiB) = %d", got)
	}
}

func TestNegotiateChunkSize(t *testing.T) {
	// New↔new: preference + full ads → preferred.
	got := NegotiateChunkSize(PreferredChunkSize, MaxChunkBytes, MaxChunkBytes)
	if got != PreferredChunkSize {
		t.Fatalf("new↔new = %d, want %d", got, PreferredChunkSize)
	}
	// Absent relay + accept → legacy 64 KiB.
	got = NegotiateChunkSize(PreferredChunkSize, 0, 0)
	if got != ChunkDataSize {
		t.Fatalf("absent ads = %d, want %d", got, ChunkDataSize)
	}
	// Advertised below floor → floor.
	got = NegotiateChunkSize(PreferredChunkSize, 1000, PreferredChunkSize)
	if got != ChunkDataSize {
		t.Fatalf("sub-floor ad = %d, want %d", got, ChunkDataSize)
	}
	// Min of the three wins.
	got = NegotiateChunkSize(PreferredChunkSize, 256*1024, PreferredChunkSize)
	if got != 256*1024 {
		t.Fatalf("min of three = %d, want 256Ki", got)
	}
}

func TestEffectiveWindow(t *testing.T) {
	if got := EffectiveWindow(0, PreferredChunkSize); got != 0 {
		t.Fatalf("unwindowed = %d", got)
	}
	// Window smaller than 2×chunk is raised.
	got := EffectiveWindow(PreferredChunkSize, PreferredChunkSize)
	if got != 2*PreferredChunkSize {
		t.Fatalf("raised window = %d, want %d", got, 2*PreferredChunkSize)
	}
	got = EffectiveWindow(DefaultWindowBytes, PreferredChunkSize)
	if got != DefaultWindowBytes {
		t.Fatalf("default window = %d", got)
	}
}

func TestWindowFullAndAck(t *testing.T) {
	win := DefaultWindowBytes
	if WindowFull(0, 0, 0) {
		t.Fatal("unwindowed should never block")
	}
	if !WindowFull(int64(win), 0, win) {
		t.Fatal("exactly window should block")
	}
	if WindowFull(int64(win)-1, 0, win) {
		t.Fatal("under window should not block")
	}
	if !ShouldAck(int64(win/4), 0, win) {
		t.Fatal("at threshold should ack")
	}
	if ShouldAck(int64(win/4)-1, 0, win) {
		t.Fatal("under threshold should not ack")
	}
	if ShouldAck(100, 0, 0) {
		t.Fatal("unwindowed should not ack")
	}
}
