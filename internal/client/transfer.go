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

	"github.com/steelbrain/lemur-pouch/internal/wireproto"
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
		c.handleTransferAccept(from, m.TransferID)
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
		peer:     from,
		filename: m.Filename,
		size:     m.Size,
		status:   statusOffered,
		pending:  make(map[uint32][]byte),
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
	peer := it.peer
	size := it.size
	it.mu.Unlock()

	accept, err := wireproto.MarshalTransferAccept(transferID)
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

func (c *Client) handleTransferAccept(from PeerInfo, transferID []byte) {
	idHex := hex.EncodeToString(transferID)
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
	ot.status = statusStreaming
	ot.mu.Unlock()
	c.emit(TransferStarted{TransferID: transferID, Direction: Outbound, Filename: ot.filename, Size: ot.size})
	go c.streamFile(ot)
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

// streamFile reads the source file in 64 KiB chunks, encrypts and sends each,
// folds the bytes into a running SHA-256, then sends transfer-end with the
// finalized digest.
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
		ot.mu.Unlock()
		c.emit(TransferFailed{TransferID: ot.id[:], Direction: Outbound, Filename: ot.filename, Reason: reason})
	}

	f, err := os.Open(ot.path)
	if err != nil {
		fail(fmt.Sprintf("open: %v", err))
		return
	}
	defer f.Close()

	hasher := sha256.New()
	buf := make([]byte, wireproto.ChunkDataSize)
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
	expectedChunks := chunkCount(it.size)
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
	c.tryFinalize(it)
	it.mu.Unlock()
	c.emitProgress(TransferProgress{TransferID: chunk.TransferID, Direction: Inbound, BytesDone: received, Total: total})
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
	it.mu.Unlock()
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

// chunkCount returns the number of chunks a file of the given size streams as.
// A zero-byte file is a single empty last chunk.
func chunkCount(size int64) uint64 {
	if size <= 0 {
		return 1
	}
	return uint64((size + wireproto.ChunkDataSize - 1) / wireproto.ChunkDataSize)
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
