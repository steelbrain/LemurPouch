package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/coder/websocket"

	"github.com/steelbrain/lemur-pouch/internal/cryptoid"
	"github.com/steelbrain/lemur-pouch/internal/wireproto"
)

// doHandshake performs the connect-time challenge/identify/welcome exchange
// (AGENTS.md "Connection Handshake") and returns the relay's view of self.
func doHandshake(ctx context.Context, conn *websocket.Conn, id *cryptoid.Identity) (PeerInfo, error) {
	// 1. Receive challenge.
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("read challenge: %w", err)
	}
	if typ != websocket.MessageText {
		return PeerInfo{}, fmt.Errorf("expected text challenge frame, got %v", typ)
	}
	name, err := wireproto.PeekType(data)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("peek challenge type: %w", err)
	}
	if name != wireproto.TypeChallenge {
		return PeerInfo{}, fmt.Errorf("expected %q, got %q", wireproto.TypeChallenge, name)
	}
	var challenge wireproto.ChallengeMsg
	if err := json.Unmarshal(data, &challenge); err != nil {
		return PeerInfo{}, fmt.Errorf("unmarshal challenge: %w", err)
	}
	if len(challenge.Nonce) == 0 {
		return PeerInfo{}, fmt.Errorf("challenge nonce is empty")
	}

	// 2. Send identify, proving liveness and binding X25519 to the identity.
	identify, err := wireproto.MarshalIdentify(wireproto.IdentifyMsg{
		Ed25519Pub:  id.Ed25519Pub,
		X25519Pub:   id.X25519Pub.Bytes(),
		SigLiveness: id.SignLiveness(challenge.Nonce),
		SigBinding:  id.SignBinding(),
	})
	if err != nil {
		return PeerInfo{}, fmt.Errorf("marshal identify: %w", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, identify); err != nil {
		return PeerInfo{}, fmt.Errorf("write identify: %w", err)
	}

	// 3. Receive welcome.
	typ, data, err = conn.Read(ctx)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("read welcome: %w", err)
	}
	if typ != websocket.MessageText {
		return PeerInfo{}, fmt.Errorf("expected text welcome frame, got %v", typ)
	}
	name, err = wireproto.PeekType(data)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("peek welcome type: %w", err)
	}
	if name == wireproto.TypeError {
		var em wireproto.ErrorMsg
		_ = json.Unmarshal(data, &em)
		return PeerInfo{}, fmt.Errorf("relay rejected handshake [%s]: %s", em.Code, em.Message)
	}
	if name != wireproto.TypeWelcome {
		return PeerInfo{}, fmt.Errorf("expected %q, got %q", wireproto.TypeWelcome, name)
	}
	var welcome wireproto.WelcomeMsg
	if err := json.Unmarshal(data, &welcome); err != nil {
		return PeerInfo{}, fmt.Errorf("unmarshal welcome: %w", err)
	}
	you := welcome.You
	return peerInfoFrom(you.Ed25519Pub, you.X25519Pub, you.IP, you.Port), nil
}
