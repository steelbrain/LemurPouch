package client

import (
	"encoding/hex"
	"fmt"

	"github.com/coder/websocket"

	"github.com/steelbrain/lemur-pouch/internal/cryptoid"
	"github.com/steelbrain/lemur-pouch/internal/wireproto"
)

// sealAndSend encrypts plaintext under the friendship send key and writes a
// binary envelope addressed to destPub. innerType is bound into the AEAD as
// AAD. The friendship must already exist.
func (c *Client) sealAndSend(destPub []byte, innerType byte, plaintext []byte) error {
	c.mu.Lock()
	f, ok := c.friends[hex.EncodeToString(destPub)]
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("no friendship with %s", cryptoid.Fingerprint(destPub))
	}
	nonce, ciphertext, err := cryptoid.EncryptEnvelope(f.sendKey, plaintext, innerType)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	frame, err := wireproto.MarshalEnvelope(innerType, destPub, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	c.write(websocket.MessageBinary, frame)
	return nil
}

// handleEnvelope decrypts an inbound binary frame and dispatches the plaintext
// by inner type. Malformed or unauthenticated frames are dropped silently
// (mirroring the relay's no-inline-error policy) save for a non-fatal
// ClientError so the UI can surface diagnostics.
func (c *Client) handleEnvelope(frame []byte) {
	header, sealed, err := wireproto.ParseEnvelopeHeader(frame)
	if err != nil {
		c.emit(ClientError{Err: fmt.Errorf("parse envelope: %w", err)})
		return
	}
	// PeerKey was rewritten by the relay to the source identity.
	srcKey := hex.EncodeToString(header.PeerKey)
	c.mu.Lock()
	f, ok := c.friends[srcKey]
	c.mu.Unlock()
	if !ok {
		// No friendship with the supposed sender — drop.
		return
	}
	plaintext, err := cryptoid.DecryptEnvelope(f.recvKey, header.Nonce, sealed, header.InnerType)
	if err != nil {
		c.emit(ClientError{Err: fmt.Errorf("decrypt envelope from %s: %w", f.peer.Fingerprint, err)})
		return
	}
	switch header.InnerType {
	case wireproto.InnerTypeJSONControl:
		c.handleTransferControl(f.peer, plaintext)
	case wireproto.InnerTypeFileChunk:
		c.handleChunk(plaintext)
	default:
		// Unknown inner type — forward-compat drop.
	}
}
