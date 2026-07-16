package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

type transferStatus int

const (
	statusOffered  transferStatus = iota // inbound: awaiting our accept/reject
	statusAwaiting                       // outbound: awaiting peer's accept/reject
	statusStreaming
	statusDone
	statusFailed
)

type outboundTransfer struct {
	mu       sync.Mutex
	id       [wireproto.TransferIDLen]byte
	peer     PeerInfo
	path     string
	filename string
	size     int64
	sent     int64
	status   transferStatus
	aborted  bool
	// Windowed flow control (0 window = legacy unwindowed).
	chunkSize int
	window    int
	lastAck   int64
	ackCond   *sync.Cond // signaled when lastAck advances or abort
}

type inboundTransfer struct {
	mu          sync.Mutex
	id          [wireproto.TransferIDLen]byte
	peer        PeerInfo
	filename    string
	size        int64
	status      transferStatus
	file        *os.File
	tmpPath     string
	finalPath   string
	hasher      hash.Hash
	writeOffset int64
	nextSeq     uint32
	pending     map[uint32][]byte
	received    int64
	lastSeqSet  bool
	lastSeq     uint32
	expectedSha []byte
	digest      []byte
	// Receiver-side flow control bookkeeping.
	window     int
	lastAcked  int64
	chunkFloor int // for seq bound; always ChunkDataSize for interoperability
	// idleTimer aborts the receive if the peer stops making progress
	// (no accepted chunk / transfer-end) for stallTimeout. Prevents a
	// half-finished transfer from sitting in the UI forever when the
	// sender deadlocks or disconnects without a clean peer-left.
	idleTimer *time.Timer
}

// SendFile offers the file at path to the friend peerEd25519 and, once
// accepted, streams it. Returns the minted 16-byte transfer ID. The peer must
// already be a friend.
func (c *Client) SendFile(peerEd25519 []byte, path string) ([]byte, error) {
	peerKey := hex.EncodeToString(peerEd25519)
	c.mu.Lock()
	peer, friends := c.friends[peerKey]
	c.mu.Unlock()
	if !friends {
		return nil, fmt.Errorf("not friends with %s", peerKey)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}

	var id [wireproto.TransferIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("mint transfer id: %w", err)
	}
	ot := &outboundTransfer{
		id:       id,
		peer:     peer.peer,
		path:     path,
		filename: filepath.Base(path),
		size:     info.Size(),
		status:   statusAwaiting,
	}
	c.mu.Lock()
	c.outbound[hex.EncodeToString(id[:])] = ot
	c.mu.Unlock()

	offer, err := wireproto.MarshalTransferOffer(id[:], ot.filename, ot.size)
	if err != nil {
		return nil, fmt.Errorf("marshal offer: %w", err)
	}
	if err := c.sealAndSend(peerEd25519, wireproto.InnerTypeJSONControl, offer); err != nil {
		return nil, err
	}
	return id[:], nil
}

// handleTransferControl dispatches a decrypted inner-type 0x01 payload.
func (c *Client) handleTransferControl(from PeerInfo, plaintext []byte) {
	typ, err := wireproto.PeekType(plaintext)
	if err != nil {
		c.emit(ClientError{Err: fmt.Errorf("peek transfer-control type: %w", err)})
		return
	}
	switch typ {
	case wireproto.TypeTransferOffer:
		m, err := wireproto.ParseTransferOffer(plaintext)
		if err != nil {
			c.emit(ClientError{Err: err})
			return
		}
		c.handleOffer(from, m)
	case wireproto.TypeTransferAccept:
		m, err := wireproto.ParseTransferAccept(plaintext)
		if err != nil {
			c.emit(ClientError{Err: err})
			return
		}
		c.handleTransferAccept(from, m)
	case wireproto.TypeTransferReject:
		m, err := wireproto.ParseTransferReject(plaintext)
		if err != nil {
			c.emit(ClientError{Err: err})
			return
		}
		c.handleTransferReject(from, m.TransferID, m.Reason)
	case wireproto.TypeTransferEnd:
		m, err := wireproto.ParseTransferEnd(plaintext)
		if err != nil {
			c.emit(ClientError{Err: err})
			return
		}
		c.handleTransferEnd(m.TransferID, m.SHA256)
	case wireproto.TypeTransferAck:
		m, err := wireproto.ParseTransferAck(plaintext)
		if err != nil {
			c.emit(ClientError{Err: err})
			return
		}
		c.handleTransferAck(from, m)
		// Unknown types fall through silently — additive interop with older
		// peers that may one day send new control messages.
	}
}

func (c *Client) handleOffer(from PeerInfo, m wireproto.TransferOffer) {
	idHex := hex.EncodeToString(m.TransferID)
	c.mu.Lock()
	if _, dup := c.inbound[idHex]; dup {
		c.mu.Unlock()
		return // duplicate transfer id — drop
	}
	it := &inboundTransfer{
		peer:       from,
		filename:   m.Filename,
		size:       m.Size,
		status:     statusOffered,
		pending:    make(map[uint32][]byte),
		chunkFloor: wireproto.ChunkDataSize,
	}
	copy(it.id[:], m.TransferID)
	c.inbound[idHex] = it
	c.mu.Unlock()
	c.emit(TransferOfferReceived{TransferID: m.TransferID, From: from, Filename: m.Filename, Size: m.Size})
}

// AcceptTransfer consents to an offered inbound transfer, opens the
// destination file, and sends transfer-accept so the sender begins streaming.
func (c *Client) AcceptTransfer(transferID []byte) error {
	idHex := hex.EncodeToString(transferID)
	c.mu.Lock()
	it, ok := c.inbound[idHex]
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown inbound transfer %s", idHex)
	}

	it.mu.Lock()
	if it.status != statusOffered {
		it.mu.Unlock()
		return fmt.Errorf("transfer %s is not awaiting a decision", idHex)
	}
	finalPath, err := uniquePath(c.downloadDir, it.filename)
	if err != nil {
		it.mu.Unlock()
		return err
	}
	f, err := os.CreateTemp(c.downloadDir, ".lemur-*.part")
	if err != nil {
		it.mu.Unlock()
		return fmt.Errorf("create temp file: %w", err)
	}
	it.file = f
	it.tmpPath = f.Name()
	it.finalPath = finalPath
	it.hasher = sha256.New()
	it.status = statusStreaming
	// Advertise our capacity so a new sender can use big chunks + windowing.
	// Old senders ignore unknown fields and drop unknown 0x01 types (acks).
	maxChunk := wireproto.MaxChunkBytes
	if c.maxChunkBytes > 0 && c.maxChunkBytes < maxChunk {
		maxChunk = c.maxChunkBytes
	}
	window := wireproto.DefaultWindowBytes
	it.window = wireproto.EffectiveWindow(window, wireproto.NegotiateChunkSize(
		wireproto.PreferredChunkSize, c.maxChunkBytes, maxChunk,
	))
	c.armInboundIdle(it)
	peer := it.peer
	size := it.size
	it.mu.Unlock()

	accept, err := wireproto.MarshalTransferAccept(transferID, &maxChunk, &window)
	if err != nil {
		return fmt.Errorf("marshal accept: %w", err)
	}
	if err := c.sealAndSend(peer.Ed25519Pub, wireproto.InnerTypeJSONControl, accept); err != nil {
		return err
	}
	c.emit(TransferStarted{TransferID: transferID, Direction: Inbound, Filename: it.filename, Size: size})
	return nil
}

// RejectTransfer declines an offered inbound transfer.
func (c *Client) RejectTransfer(transferID []byte, reason string) error {
	idHex := hex.EncodeToString(transferID)
	c.mu.Lock()
	it, ok := c.inbound[idHex]
	if ok {
		delete(c.inbound, idHex)
	}
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown inbound transfer %s", idHex)
	}
	reject, err := wireproto.MarshalTransferReject(transferID, reason)
	if err != nil {
		return fmt.Errorf("marshal reject: %w", err)
	}
	if err := c.sealAndSend(it.peer.Ed25519Pub, wireproto.InnerTypeJSONControl, reject); err != nil {
		return err
	}
	c.emit(TransferFailed{TransferID: transferID, Direction: Inbound, Filename: it.filename, Reason: "rejected by you"})
	return nil
}

func (c *Client) handleTransferAccept(from PeerInfo, m wireproto.TransferAccept) {
	idHex := hex.EncodeToString(m.TransferID)
	c.mu.Lock()
	ot, ok := c.outbound[idHex]
	c.mu.Unlock()
	if !ok {
		return
	}
	ot.mu.Lock()
	mismatch := !bytesEqual(ot.peer.Ed25519Pub, from.Ed25519Pub) || ot.status != statusAwaiting
	if mismatch {
		ot.mu.Unlock()
		return
	}
	acceptMax := 0
	if m.MaxChunkBytes != nil {
		acceptMax = *m.MaxChunkBytes
	}
	windowAd := 0
	if m.WindowBytes != nil {
		windowAd = *m.WindowBytes
	}
	ot.chunkSize = wireproto.NegotiateChunkSize(wireproto.PreferredChunkSize, c.maxChunkBytes, acceptMax)
	ot.window = wireproto.EffectiveWindow(windowAd, ot.chunkSize)
	ot.lastAck = 0
	ot.ackCond = sync.NewCond(&ot.mu)
	ot.status = statusStreaming
	ot.mu.Unlock()
	c.emit(TransferStarted{TransferID: m.TransferID, Direction: Outbound, Filename: ot.filename, Size: ot.size})
	go c.streamFile(ot)
}

func (c *Client) handleTransferAck(from PeerInfo, m wireproto.TransferAck) {
	idHex := hex.EncodeToString(m.TransferID)
	c.mu.Lock()
	ot, ok := c.outbound[idHex]
	c.mu.Unlock()
	if !ok {
		return
	}
	ot.mu.Lock()
	defer ot.mu.Unlock()
	if !bytesEqual(ot.peer.Ed25519Pub, from.Ed25519Pub) {
		return
	}
	if ot.window <= 0 {
		return // unwindowed: ignore acks
	}
	if m.ReceivedBytes < ot.lastAck {
		return // non-monotonic — ignore
	}
	ot.lastAck = m.ReceivedBytes
	if ot.ackCond != nil {
		ot.ackCond.Broadcast()
	}
}

func (c *Client) handleTransferReject(from PeerInfo, transferID []byte, reason string) {
	idHex := hex.EncodeToString(transferID)
	c.mu.Lock()
	ot, ok := c.outbound[idHex]
	if ok {
		delete(c.outbound, idHex)
	}
	c.mu.Unlock()
	if !ok {
		return
	}
	ot.mu.Lock()
	// Verify the rejecter is the peer we offered to before mutating state, so
	// a reject forged by a different friend can't corrupt this transfer.
	if !bytesEqual(ot.peer.Ed25519Pub, from.Ed25519Pub) {
		ot.mu.Unlock()
		return
	}
	ot.status = statusFailed
	filename := ot.filename
	ot.mu.Unlock()
	if reason == "" {
		reason = "rejected by peer"
	}
	c.emit(TransferFailed{TransferID: transferID, Direction: Outbound, Filename: filename, Reason: reason})
}

// streamFile reads the source file in negotiated-size chunks, encrypts and
// sends each, folds the bytes into a running SHA-256, then sends transfer-end
// with the finalized digest. When the accept carried a window, blocks while
// in-flight ≥ window and aborts after StallTimeoutSec without ack progress.
func (c *Client) streamFile(ot *outboundTransfer) {
	fail := func(reason string) {
		ot.mu.Lock()
		// If a peer-left (or anything else) already aborted/failed this
		// transfer, don't emit a second TransferFailed.
		if ot.aborted || ot.status == statusFailed {
			ot.mu.Unlock()
			return
		}
		ot.status = statusFailed
		ot.aborted = true
		if ot.ackCond != nil {
			ot.ackCond.Broadcast()
		}
		ot.mu.Unlock()
		c.emit(TransferFailed{TransferID: ot.id[:], Direction: Outbound, Filename: ot.filename, Reason: reason})
	}

	f, err := os.Open(ot.path)
	if err != nil {
		fail(fmt.Sprintf("open: %v", err))
		return
	}
	defer f.Close()

	ot.mu.Lock()
	chunkSize := ot.chunkSize
	if chunkSize <= 0 {
		chunkSize = wireproto.ChunkDataSize
	}
	window := ot.window
	ot.mu.Unlock()

	hasher := sha256.New()
	buf := make([]byte, chunkSize)
	var seq uint32
	var sent int64
	for {
		n, readErr := io.ReadFull(f, buf)
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			// Final (possibly empty/short) chunk.
		} else if readErr != nil {
			fail(fmt.Sprintf("read: %v", readErr))
			return
		}
		data := buf[:n]
		// EOF forces last-chunk even if the stat size disagrees (e.g. the
		// file was truncated mid-send) — otherwise a 0-byte read at a size
		// boundary would loop forever.
		atEOF := readErr == io.EOF || readErr == io.ErrUnexpectedEOF
		isLast := atEOF || sent+int64(n) >= ot.size
		var flags byte
		if isLast {
			flags = wireproto.ChunkFlagLast
		}

		// Windowed: wait until in-flight leaves room for this chunk (or
		// abort on stall / peer disconnect).
		if window > 0 {
			if err := c.waitForWindow(ot, int64(n)); err != nil {
				fail(err.Error())
				return
			}
		}

		ot.mu.Lock()
		aborted := ot.aborted
		ot.mu.Unlock()
		if aborted {
			return // failure already reported by the aborting path
		}

		chunk, err := wireproto.MarshalChunk(ot.id[:], seq, flags, data)
		if err != nil {
			fail(fmt.Sprintf("marshal chunk: %v", err))
			return
		}
		if err := c.sealAndSend(ot.peer.Ed25519Pub, wireproto.InnerTypeFileChunk, chunk); err != nil {
			fail(fmt.Sprintf("send chunk: %v", err))
			return
		}
		hasher.Write(data)
		sent += int64(n)
		seq++

		ot.mu.Lock()
		ot.sent = sent
		ot.mu.Unlock()
		c.emitProgress(TransferProgress{TransferID: ot.id[:], Direction: Outbound, BytesDone: sent, Total: ot.size})

		if isLast {
			break
		}
	}

	end, err := wireproto.MarshalTransferEnd(ot.id[:], hasher.Sum(nil))
	if err != nil {
		fail(fmt.Sprintf("marshal end: %v", err))
		return
	}
	if err := c.sealAndSend(ot.peer.Ed25519Pub, wireproto.InnerTypeJSONControl, end); err != nil {
		fail(fmt.Sprintf("send end: %v", err))
		return
	}
	ot.mu.Lock()
	ot.status = statusDone
	ot.mu.Unlock()
	c.emit(TransferComplete{TransferID: ot.id[:], Direction: Outbound, Filename: ot.filename})
}

// stallTimeout is how long waitForWindow waits for ack progress before
// returning "flow-control stall". Overridable in tests (defaults to
// wireproto.StallTimeoutSec).
var stallTimeout = time.Duration(wireproto.StallTimeoutSec) * time.Second

// waitForWindow blocks until sending n more bytes would fit under the
// window, or returns an error on abort / stallTimeout without ack progress.
// Caller must not hold ot.mu.
func (c *Client) waitForWindow(ot *outboundTransfer, n int64) error {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	if ot.ackCond == nil {
		return nil
	}
	deadline := time.Now().Add(stallTimeout)
	lastSeenAck := ot.lastAck
	for {
		if ot.aborted || ot.status == statusFailed {
			return errors.New("transfer aborted")
		}
		// Room for this chunk?
		if !wireproto.WindowFull(ot.sent+n, ot.lastAck, ot.window) {
			return nil
		}
		// Ack advanced since we started waiting — reset the stall clock.
		if ot.lastAck > lastSeenAck {
			lastSeenAck = ot.lastAck
			deadline = time.Now().Add(stallTimeout)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("flow-control stall")
		}
		// Timed wait via a one-shot timer that broadcasts the cond.
		timer := time.AfterFunc(remaining, func() {
			ot.mu.Lock()
			if ot.ackCond != nil {
				ot.ackCond.Broadcast()
			}
			ot.mu.Unlock()
		})
		ot.ackCond.Wait()
		timer.Stop()
	}
}

// handleChunk folds an inbound file chunk into its transfer's assembler,
// writing in-order bytes to disk and verifying length/order invariants.
func (c *Client) handleChunk(plaintext []byte) {
	chunk, err := wireproto.ParseChunk(plaintext)
	if err != nil {
		c.emit(ClientError{Err: err})
		return
	}
	idHex := hex.EncodeToString(chunk.TransferID)
	c.mu.Lock()
	it, ok := c.inbound[idHex]
	c.mu.Unlock()
	if !ok {
		return
	}

	it.mu.Lock()
	if it.status != statusStreaming {
		it.mu.Unlock()
		return
	}
	// Seq bound uses the 64 KiB floor so larger negotiated chunks still pass
	// (fewer seqs) and old senders remain valid.
	expectedChunks := chunkCount(it.size, it.chunkFloor)
	if uint64(chunk.Seq) >= expectedChunks {
		c.abortInbound(it, "chunk sequence out of range")
		it.mu.Unlock()
		return
	}
	if chunk.Seq < it.nextSeq {
		it.mu.Unlock()
		return // already consumed — duplicate
	}
	if _, dup := it.pending[chunk.Seq]; dup {
		it.mu.Unlock()
		return
	}
	if len(chunk.Data) == 0 && !chunk.IsLast() {
		c.abortInbound(it, "empty non-final chunk")
		it.mu.Unlock()
		return
	}
	if it.received+int64(len(chunk.Data)) > it.size {
		c.abortInbound(it, "stream overshoots offered size")
		it.mu.Unlock()
		return
	}
	if chunk.IsLast() {
		it.lastSeqSet = true
		it.lastSeq = chunk.Seq
	}
	it.received += int64(len(chunk.Data))

	if chunk.Seq == it.nextSeq {
		if err := writeInOrder(it, chunk.Data); err != nil {
			c.abortInbound(it, err.Error())
			it.mu.Unlock()
			return
		}
		// Drain any buffered successors.
		for {
			next, ok := it.pending[it.nextSeq]
			if !ok {
				break
			}
			delete(it.pending, it.nextSeq)
			if err := writeInOrder(it, next); err != nil {
				c.abortInbound(it, err.Error())
				it.mu.Unlock()
				return
			}
		}
	} else {
		cp := make([]byte, len(chunk.Data))
		copy(cp, chunk.Data)
		it.pending[chunk.Seq] = cp
	}

	complete := it.lastSeqSet && it.nextSeq == it.lastSeq+1
	if complete {
		if it.writeOffset != it.size {
			c.abortInbound(it, "stream shorter than offered size")
			it.mu.Unlock()
			return
		}
		it.digest = it.hasher.Sum(nil)
	}
	received := it.received
	total := it.size
	needAck := wireproto.ShouldAck(it.received, it.lastAcked, it.window)
	if needAck {
		it.lastAcked = it.received
	}
	peer := it.peer
	ackBytes := it.lastAcked
	c.tryFinalize(it)
	// Peer made progress (this chunk). Reset the receive-stall clock unless
	// tryFinalize already terminalized the transfer.
	if it.status == statusStreaming {
		c.armInboundIdle(it)
	}
	it.mu.Unlock()
	c.emitProgress(TransferProgress{TransferID: chunk.TransferID, Direction: Inbound, BytesDone: received, Total: total})
	if needAck {
		ack, err := wireproto.MarshalTransferAck(chunk.TransferID, ackBytes)
		if err == nil {
			_ = c.sealAndSend(peer.Ed25519Pub, wireproto.InnerTypeJSONControl, ack)
		}
	}
}

func (c *Client) handleTransferEnd(transferID, sha []byte) {
	idHex := hex.EncodeToString(transferID)
	c.mu.Lock()
	it, ok := c.inbound[idHex]
	c.mu.Unlock()
	if !ok {
		return
	}
	it.mu.Lock()
	if it.status != statusStreaming {
		it.mu.Unlock()
		return
	}
	it.expectedSha = sha
	c.tryFinalize(it)
	// transfer-end is peer progress even when we still lack the last chunk.
	if it.status == statusStreaming {
		c.armInboundIdle(it)
	}
	it.mu.Unlock()
}

// stopInboundIdle cancels the receive-stall timer. Caller holds it.mu.
func stopInboundIdle(it *inboundTransfer) {
	if it.idleTimer != nil {
		it.idleTimer.Stop()
		it.idleTimer = nil
	}
}

// armInboundIdle (re)starts the receive-stall timer. After stallTimeout with
// no accepted chunk or transfer-end, aborts the inbound transfer. Caller
// holds it.mu.
func (c *Client) armInboundIdle(it *inboundTransfer) {
	stopInboundIdle(it)
	id := it.id
	it.idleTimer = time.AfterFunc(stallTimeout, func() {
		c.mu.Lock()
		cur, ok := c.inbound[hex.EncodeToString(id[:])]
		c.mu.Unlock()
		if !ok || cur != it {
			return
		}
		it.mu.Lock()
		defer it.mu.Unlock()
		if it.status != statusStreaming {
			return
		}
		c.abortInbound(it, "receive stall")
	})
}

// tryFinalize commits or fails an inbound transfer once both the locally
// computed digest and the sender's transfer-end digest are available. Caller
// must hold it.mu.
func (c *Client) tryFinalize(it *inboundTransfer) {
	if it.digest == nil || it.expectedSha == nil || it.status != statusStreaming {
		return
	}
	if !bytesEqual(it.digest, it.expectedSha) {
		c.abortInbound(it, "integrity check failed (sha256 mismatch)")
		return
	}
	if err := it.file.Close(); err != nil {
		c.abortInbound(it, fmt.Sprintf("close: %v", err))
		return
	}
	if err := os.Rename(it.tmpPath, it.finalPath); err != nil {
		c.abortInbound(it, fmt.Sprintf("rename: %v", err))
		return
	}
	stopInboundIdle(it)
	it.status = statusDone
	c.mu.Lock()
	delete(c.inbound, hex.EncodeToString(it.id[:]))
	c.mu.Unlock()
	c.emit(TransferComplete{TransferID: it.id[:], Direction: Inbound, Filename: it.filename, Path: it.finalPath})
}

// abortInbound tears down a failed inbound transfer: closes and removes the
// temp file and reports the failure. Caller must hold it.mu.
func (c *Client) abortInbound(it *inboundTransfer, reason string) {
	if it.status == statusFailed || it.status == statusDone {
		return
	}
	stopInboundIdle(it)
	it.status = statusFailed
	if it.file != nil {
		it.file.Close()
		os.Remove(it.tmpPath)
	}
	c.mu.Lock()
	delete(c.inbound, hex.EncodeToString(it.id[:]))
	c.mu.Unlock()
	c.emit(TransferFailed{TransferID: it.id[:], Direction: Inbound, Filename: it.filename, Reason: reason})
}

// failTransfersForPeer aborts every in-flight transfer with the given peer,
// used when the peer disconnects.
func (c *Client) failTransfersForPeer(peerHex string, reason string) {
	c.mu.Lock()
	var outs []*outboundTransfer
	var ins []*inboundTransfer
	for _, ot := range c.outbound {
		if hex.EncodeToString(ot.peer.Ed25519Pub) == peerHex {
			outs = append(outs, ot)
		}
	}
	for _, it := range c.inbound {
		if hex.EncodeToString(it.peer.Ed25519Pub) == peerHex {
			ins = append(ins, it)
		}
	}
	c.mu.Unlock()

	for _, ot := range outs {
		ot.mu.Lock()
		active := ot.status == statusAwaiting || ot.status == statusStreaming
		ot.aborted = true
		if active {
			ot.status = statusFailed
		}
		if ot.ackCond != nil {
			ot.ackCond.Broadcast()
		}
		ot.mu.Unlock()
		c.mu.Lock()
		delete(c.outbound, hex.EncodeToString(ot.id[:]))
		c.mu.Unlock()
		if active {
			c.emit(TransferFailed{TransferID: ot.id[:], Direction: Outbound, Filename: ot.filename, Reason: reason})
		}
	}
	for _, it := range ins {
		it.mu.Lock()
		c.abortInbound(it, reason)
		it.mu.Unlock()
	}
}

// writeInOrder appends a contiguous chunk to the destination file and hashes
// it, advancing the write offset and next-expected sequence. Caller holds it.mu.
func writeInOrder(it *inboundTransfer, data []byte) error {
	if _, err := it.file.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	it.hasher.Write(data)
	it.writeOffset += int64(len(data))
	it.nextSeq++
	return nil
}

// chunkCount returns the number of chunks a file of the given size streams as
// when chunked at chunkSize (defaults to ChunkDataSize). A zero-byte file is
// a single empty last chunk. Receivers always pass the 64 KiB floor so larger
// sender chunks stay within the bound.
func chunkCount(size int64, chunkSize int) uint64 {
	if chunkSize <= 0 {
		chunkSize = wireproto.ChunkDataSize
	}
	if size <= 0 {
		return 1
	}
	return uint64((size + int64(chunkSize) - 1) / int64(chunkSize))
}

// uniquePath returns a non-colliding path in dir for the given (untrusted)
// filename. The name is reduced to its base component to prevent path
// traversal, and a numeric suffix is appended on collision.
func uniquePath(dir, filename string) (string, error) {
	base := filepath.Base(filepath.FromSlash(filename))
	if base == "." || base == ".." || base == string(filepath.Separator) || base == "" {
		base = "received-file"
	}
	candidate := filepath.Join(dir, base)
	if !exists(candidate) {
		return candidate, nil
	}
	ext := filepath.Ext(base)
	stem := base[:len(base)-len(ext)]
	for i := 1; i < 10000; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if !exists(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("could not find a free filename")
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
