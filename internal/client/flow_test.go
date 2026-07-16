package client

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

func TestWindowedSenderBlocksThenUnblocksOnAck(t *testing.T) {
	win := wireproto.DefaultWindowBytes
	chunk := wireproto.PreferredChunkSize
	eff := wireproto.EffectiveWindow(win, chunk)
	if eff != win {
		t.Fatalf("effective window = %d", eff)
	}
	if !wireproto.WindowFull(int64(eff), 0, eff) {
		t.Fatal("expected full")
	}
	if wireproto.WindowFull(int64(eff), int64(eff/2), eff) {
		t.Fatal("after half ack should have room")
	}
}

func TestOldAcceptNoWindowNeverBlocks(t *testing.T) {
	if wireproto.EffectiveWindow(0, wireproto.PreferredChunkSize) != 0 {
		t.Fatal("legacy accept must be unwindowed")
	}
	if wireproto.WindowFull(1<<40, 0, 0) {
		t.Fatal("unwindowed must never block")
	}
}

func TestNegotiateLegacyMix(t *testing.T) {
	got := wireproto.NegotiateChunkSize(wireproto.PreferredChunkSize, 0, 0)
	if got != wireproto.ChunkDataSize {
		t.Fatalf("legacy mix = %d", got)
	}
	got = wireproto.NegotiateChunkSize(
		wireproto.PreferredChunkSize,
		wireproto.MaxChunkBytes,
		wireproto.MaxChunkBytes,
	)
	if got != wireproto.PreferredChunkSize {
		t.Fatalf("new↔new = %d", got)
	}
}

// TestWaitForWindowFlowControlStall drives the real Client.waitForWindow
// against a window-full outboundTransfer whose lastAck never advances, and
// asserts the production error string "flow-control stall".
func TestWaitForWindowFlowControlStall(t *testing.T) {
	orig := stallTimeout
	stallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { stallTimeout = orig })

	c := &Client{}
	ot := &outboundTransfer{
		sent:    int64(wireproto.DefaultWindowBytes),
		lastAck: 0,
		window:  wireproto.DefaultWindowBytes,
		status:  statusStreaming,
	}
	ot.ackCond = sync.NewCond(&ot.mu)

	// Need to send one more byte while already window-full.
	err := c.waitForWindow(ot, 1)
	if err == nil {
		t.Fatal("expected flow-control stall, got nil")
	}
	if err.Error() != "flow-control stall" {
		t.Fatalf("error = %q, want %q", err.Error(), "flow-control stall")
	}
}

// TestWaitForWindowUnblocksOnAck advances lastAck while waitForWindow is
// blocked and asserts the production path returns nil (not stall).
func TestWaitForWindowUnblocksOnAck(t *testing.T) {
	orig := stallTimeout
	stallTimeout = 5 * time.Second
	t.Cleanup(func() { stallTimeout = orig })

	c := &Client{}
	ot := &outboundTransfer{
		sent:    int64(wireproto.DefaultWindowBytes),
		lastAck: 0,
		window:  wireproto.DefaultWindowBytes,
		status:  statusStreaming,
	}
	ot.ackCond = sync.NewCond(&ot.mu)

	done := make(chan error, 1)
	go func() {
		done <- c.waitForWindow(ot, 1)
	}()

	// Let the waiter block, then simulate a transfer-ack.
	time.Sleep(20 * time.Millisecond)
	ot.mu.Lock()
	ot.lastAck = int64(wireproto.DefaultWindowBytes) // full window acked
	ot.ackCond.Broadcast()
	ot.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil after ack, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForWindow did not return after ack")
	}
}

// TestWaitForWindowAbortOnTransferFailed asserts aborted/failed transfers
// exit waitForWindow without waiting for the stall timeout.
func TestWaitForWindowAbortOnTransferFailed(t *testing.T) {
	orig := stallTimeout
	stallTimeout = 5 * time.Second
	t.Cleanup(func() { stallTimeout = orig })

	c := &Client{}
	ot := &outboundTransfer{
		sent:    int64(wireproto.DefaultWindowBytes),
		lastAck: 0,
		window:  wireproto.DefaultWindowBytes,
		status:  statusStreaming,
	}
	ot.ackCond = sync.NewCond(&ot.mu)

	done := make(chan error, 1)
	go func() {
		done <- c.waitForWindow(ot, 1)
	}()
	time.Sleep(20 * time.Millisecond)
	ot.mu.Lock()
	ot.aborted = true
	ot.status = statusFailed
	ot.ackCond.Broadcast()
	ot.mu.Unlock()

	select {
	case err := <-done:
		if err == nil || err.Error() != "transfer aborted" {
			t.Fatalf("got %v, want transfer aborted", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForWindow did not return after abort")
	}
}

// TestReceiveStallAbortsInbound asserts that an inbound transfer with no
// peer progress for stallTimeout is torn down with reason "receive stall".
func TestReceiveStallAbortsInbound(t *testing.T) {
	orig := stallTimeout
	stallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { stallTimeout = orig })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &Client{
		ctx:     ctx,
		cancel:  cancel,
		events:  make(chan Event, eventBuffer),
		inbound: make(map[string]*inboundTransfer),
	}
	var id [wireproto.TransferIDLen]byte
	id[0] = 0xab
	it := &inboundTransfer{
		id:       id,
		filename: "stall.bin",
		size:     1024,
		status:   statusStreaming,
		pending:  map[uint32][]byte{},
	}
	idHex := hex.EncodeToString(id[:])
	c.mu.Lock()
	c.inbound[idHex] = it
	c.mu.Unlock()

	it.mu.Lock()
	c.armInboundIdle(it)
	it.mu.Unlock()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-c.Events():
			fail, ok := ev.(TransferFailed)
			if !ok {
				continue
			}
			if fail.Reason != "receive stall" {
				t.Fatalf("reason = %q, want receive stall", fail.Reason)
			}
			if fail.Filename != "stall.bin" {
				t.Fatalf("filename = %q", fail.Filename)
			}
			c.mu.Lock()
			_, still := c.inbound[idHex]
			c.mu.Unlock()
			if still {
				t.Fatal("inbound entry should be removed after receive stall")
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for receive stall")
		}
	}
}
