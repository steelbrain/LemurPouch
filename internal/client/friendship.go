package client

import (
	"encoding/hex"
	"fmt"

	"github.com/coder/websocket"

	"github.com/steelbrain/LemurPouch/internal/wireproto"
)

// Invite sends a friendship invite to the peer identified by its Ed25519
// public key (consent only, no payload — AGENTS.md "Tier 1: Friendship").
func (c *Client) Invite(peerEd25519 []byte) error {
	frame, err := wireproto.MarshalInvite(peerEd25519)
	if err != nil {
		return fmt.Errorf("marshal invite: %w", err)
	}
	c.write(websocket.MessageText, frame)
	return nil
}

// Accept accepts an incoming invite from peerEd25519 and derives the
// per-friendship session keys. After this returns nil, transfers may flow.
func (c *Client) Accept(peerEd25519 []byte) error {
	if err := c.deriveFriendship(peerEd25519); err != nil {
		return err
	}
	frame, err := wireproto.MarshalAccept(peerEd25519)
	if err != nil {
		return fmt.Errorf("marshal accept: %w", err)
	}
	c.write(websocket.MessageText, frame)
	c.mu.Lock()
	f := c.friends[hex.EncodeToString(peerEd25519)]
	c.mu.Unlock()
	if f != nil {
		c.emit(FriendshipEstablished{Peer: f.peer})
	}
	return nil
}

// Reject declines an incoming invite from peerEd25519.
func (c *Client) Reject(peerEd25519 []byte) error {
	frame, err := wireproto.MarshalReject(peerEd25519)
	if err != nil {
		return fmt.Errorf("marshal reject: %w", err)
	}
	c.write(websocket.MessageText, frame)
	return nil
}

// deriveFriendship computes and stores the directional session keys for the
// friendship with peerEd25519, looked up from the discovery peer set.
func (c *Client) deriveFriendship(peerEd25519 []byte) error {
	key := hex.EncodeToString(peerEd25519)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.friends[key]; ok {
		return nil // already friends; idempotent
	}
	peer, ok := c.peers[key]
	if !ok {
		return fmt.Errorf("unknown peer %s", key)
	}
	peerX, err := pubToECDH(peer.X25519Pub)
	if err != nil {
		return fmt.Errorf("peer x25519 pub: %w", err)
	}
	sendKey, recvKey, err := c.id.FriendshipKeys(peerEd25519, peerX)
	if err != nil {
		return fmt.Errorf("derive friendship keys: %w", err)
	}
	c.friends[key] = &friendship{peer: peer, sendKey: sendKey, recvKey: recvKey}
	return nil
}

// handleFriendshipNotification processes an s2c friendship signal.
func (c *Client) handleFriendshipNotification(typ string, from []byte) {
	switch typ {
	case wireproto.TypeInviteFrom:
		key := hex.EncodeToString(from)
		c.mu.Lock()
		peer, ok := c.peers[key]
		c.mu.Unlock()
		if !ok {
			c.emit(ClientError{Err: fmt.Errorf("invite-from unknown peer %s", key)})
			return
		}
		c.emit(InviteReceived{From: peer})
	case wireproto.TypeAcceptFrom:
		// The peer accepted our invite; derive keys and announce the
		// established friendship.
		if err := c.deriveFriendship(from); err != nil {
			c.emit(ClientError{Err: fmt.Errorf("accept-from: %w", err)})
			return
		}
		c.mu.Lock()
		f := c.friends[hex.EncodeToString(from)]
		c.mu.Unlock()
		if f != nil {
			c.emit(FriendshipEstablished{Peer: f.peer})
		}
	case wireproto.TypeRejectFrom:
		c.emit(InviteRejected{Ed25519Pub: from})
	case wireproto.TypeInviteDeferred:
		c.emit(InviteDeferred{Ed25519Pub: from})
	case wireproto.TypeInviteAutoRejected:
		c.emit(InviteAutoRejected{Ed25519Pub: from})
	}
}
