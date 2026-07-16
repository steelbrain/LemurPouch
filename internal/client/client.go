package client

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/cryptoid"
	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// writeTimeout bounds a single frame write so a wedged relay can't block the
// writer goroutine forever.
const writeTimeout = 30 * time.Second

// eventBuffer sizes the events channel. Generous so bursty discovery/progress
// events don't block the read loop; emits past capacity drop on ctx cancel.
const eventBuffer = 128

type friendship struct {
	peer    PeerInfo
	sendKey [32]byte
	recvKey [32]byte
}

type outFrame struct {
	typ  websocket.MessageType
	data []byte
}

// Client is a connected relay client. Construct with Connect; observe Events;
// drive with the command methods. Safe for concurrent use by multiple
// goroutines.
type Client struct {
	id          *cryptoid.Identity
	conn        *websocket.Conn
	self        PeerInfo
	downloadDir string
	// maxChunkBytes is the relay's advertised max raw chunk size (0 ⇒ legacy
	// 64 KiB floor). Captured from welcome.limits.
	maxChunkBytes int

	events  chan Event
	writeCh chan outFrame

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	peers    map[string]PeerInfo
	friends  map[string]*friendship
	inbound  map[string]*inboundTransfer
	outbound map[string]*outboundTransfer

	closeOnce sync.Once
	closeErr  error
}

// Connect dials the relay at rawURL, performs the connection handshake, and
// returns a running Client. rawURL may be an http(s):// relay URL (as printed
// by `--serve`) or a ws(s):// URL; either way it is normalized to the relay's
// /ws endpoint. downloadDir is where received files are written.
//
// The returned Client owns a background read loop and write loop; call Close
// to tear them down. The handshake itself is bounded by ctx.
func Connect(ctx context.Context, rawURL string, id *cryptoid.Identity, downloadDir string) (*Client, error) {
	wsURL, err := normalizeURL(rawURL)
	if err != nil {
		return nil, err
	}

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial relay: %w", err)
	}
	// Match the relay's frame cap so we can receive a full negotiated chunk
	// envelope. writeCh occupancy per transfer is bounded by window/chunk
	// (~8 frames at default 8 MiB / 1 MiB), so the 64-frame buffer is fine.
	conn.SetReadLimit(int64(wireproto.ReadLimit))

	self, maxChunk, err := doHandshake(ctx, conn, id)
	if err != nil {
		conn.Close(websocket.StatusInternalError, "handshake failed")
		return nil, err
	}

	bg, cancel := context.WithCancel(context.Background())
	c := &Client{
		id:            id,
		conn:          conn,
		self:          self,
		downloadDir:   downloadDir,
		maxChunkBytes: maxChunk,
		events:        make(chan Event, eventBuffer),
		writeCh:       make(chan outFrame, 64),
		ctx:           bg,
		cancel:        cancel,
		peers:         make(map[string]PeerInfo),
		friends:       make(map[string]*friendship),
		inbound:       make(map[string]*inboundTransfer),
		outbound:      make(map[string]*outboundTransfer),
	}

	go c.writeLoop()
	go c.readLoop()
	return c, nil
}

// Events returns the channel of asynchronous events. The channel is never
// closed; a Disconnected event marks the terminal state.
func (c *Client) Events() <-chan Event { return c.events }

// Self returns the relay's view of this client's own identity.
func (c *Client) Self() PeerInfo { return c.self }

// DownloadDir returns the directory received files are written to.
func (c *Client) DownloadDir() string { return c.downloadDir }

// Close tears down the connection and background loops. Idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.closeErr = c.conn.Close(websocket.StatusNormalClosure, "client closing")
	})
	return c.closeErr
}

func (c *Client) emit(e Event) {
	select {
	case c.events <- e:
	case <-c.ctx.Done():
	}
}

// emitProgress is best-effort: it never blocks. Progress is advisory, so a
// full channel drops the update rather than stalling the read/stream loop.
func (c *Client) emitProgress(e TransferProgress) {
	select {
	case c.events <- e:
	default:
	}
}

func (c *Client) write(typ websocket.MessageType, data []byte) {
	select {
	case c.writeCh <- outFrame{typ: typ, data: data}:
	case <-c.ctx.Done():
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case f := <-c.writeCh:
			wctx, cancel := context.WithTimeout(c.ctx, writeTimeout)
			err := c.conn.Write(wctx, f.typ, f.data)
			cancel()
			if err != nil {
				c.shutdown(fmt.Errorf("write: %w", err))
				return
			}
		}
	}
}

func (c *Client) readLoop() {
	for {
		typ, data, err := c.conn.Read(c.ctx)
		if err != nil {
			c.shutdown(err)
			return
		}
		switch typ {
		case websocket.MessageText:
			c.handleControl(data)
		case websocket.MessageBinary:
			c.handleEnvelope(data)
		}
	}
}

// shutdown reports the terminal Disconnected event exactly once and cancels
// the context, unblocking the loops and dropping further emits.
func (c *Client) shutdown(err error) {
	c.closeOnce.Do(func() {
		// Normalize an expected close into a nil error for the UI.
		if errors.Is(err, context.Canceled) || websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			err = nil
		}
		c.closeErr = c.conn.Close(websocket.StatusNormalClosure, "")
		// Emit before cancel so the terminal event isn't dropped by emit's
		// ctx-cancel escape hatch.
		select {
		case c.events <- Disconnected{Err: err}:
		default:
		}
		c.cancel()
	})
}

// handleControl dispatches a cleartext JSON frame from the relay.
func (c *Client) handleControl(data []byte) {
	typ, err := wireproto.PeekType(data)
	if err != nil {
		c.emit(ClientError{Err: fmt.Errorf("peek control type: %w", err)})
		return
	}
	switch typ {
	case wireproto.TypePeerList:
		var m wireproto.PeerListMsg
		if err := json.Unmarshal(data, &m); err != nil {
			c.emit(ClientError{Err: fmt.Errorf("peer-list: %w", err)})
			return
		}
		c.handlePeerList(m.Peers)
	case wireproto.TypePeerJoined:
		var m wireproto.PeerJoinedMsg
		if err := json.Unmarshal(data, &m); err != nil {
			c.emit(ClientError{Err: fmt.Errorf("peer-joined: %w", err)})
			return
		}
		c.handlePeerJoined(m.Peer)
	case wireproto.TypePeerLeft:
		var m wireproto.PeerLeftMsg
		if err := json.Unmarshal(data, &m); err != nil {
			c.emit(ClientError{Err: fmt.Errorf("peer-left: %w", err)})
			return
		}
		c.handlePeerLeft(m.Ed25519Pub)
	case wireproto.TypeInviteFrom, wireproto.TypeAcceptFrom, wireproto.TypeRejectFrom,
		wireproto.TypeInviteDeferred, wireproto.TypeInviteAutoRejected:
		var m wireproto.FriendshipNotification
		if err := json.Unmarshal(data, &m); err != nil {
			c.emit(ClientError{Err: fmt.Errorf("friendship notification: %w", err)})
			return
		}
		c.handleFriendshipNotification(typ, m.From)
	case wireproto.TypeError:
		var m wireproto.ErrorMsg
		if err := json.Unmarshal(data, &m); err == nil {
			c.emit(ClientError{Err: fmt.Errorf("relay error [%s]: %s", m.Code, m.Message)})
		}
	}
}

func (c *Client) handlePeerList(peers []wireproto.PeerRecord) {
	var infos []PeerInfo
	c.mu.Lock()
	c.peers = make(map[string]PeerInfo)
	for _, p := range peers {
		if !cryptoid.VerifyBinding(p.Ed25519Pub, p.X25519Pub, p.SigBinding) {
			continue
		}
		info := peerInfoFrom(p.Ed25519Pub, p.X25519Pub, p.IP, p.Port)
		c.peers[hex.EncodeToString(p.Ed25519Pub)] = info
		infos = append(infos, info)
	}
	c.mu.Unlock()
	c.emit(PeerListEvent{Peers: infos})
}

func (c *Client) handlePeerJoined(p wireproto.PeerRecord) {
	if !cryptoid.VerifyBinding(p.Ed25519Pub, p.X25519Pub, p.SigBinding) {
		c.emit(ClientError{Err: errors.New("peer-joined: sig_binding verification failed")})
		return
	}
	info := peerInfoFrom(p.Ed25519Pub, p.X25519Pub, p.IP, p.Port)
	c.mu.Lock()
	c.peers[hex.EncodeToString(p.Ed25519Pub)] = info
	c.mu.Unlock()
	c.emit(PeerJoined{Peer: info})
}

func (c *Client) handlePeerLeft(ed []byte) {
	key := hex.EncodeToString(ed)
	c.mu.Lock()
	delete(c.peers, key)
	delete(c.friends, key)
	c.mu.Unlock()
	c.failTransfersForPeer(key, "peer disconnected")
	c.emit(PeerLeft{Ed25519Pub: ed})
}

// normalizeURL accepts an http(s)/ws(s) URL and returns a ws(s) URL pointing
// at the relay's /ws endpoint.
func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty relay URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "ws://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse relay URL: %w", err)
	}
	switch u.Scheme {
	case "http", "ws":
		u.Scheme = "ws"
	case "https", "wss":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}
	return u.String(), nil
}

// pubToECDH converts a 32-byte X25519 public key to *ecdh.PublicKey.
func pubToECDH(x []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(x)
}
