// Package wireproto defines the JSON message types exchanged between the
// relay and clients over WebSocket text frames. See AGENTS.md "Wire
// Protocol > Cleartext Control" for the canonical schema; if these structs
// drift from the spec, both Go and TS sides break.
//
// Binary frames carrying encrypted peer-to-peer envelopes are handled
// elsewhere (AGENTS.md "Encrypted Envelopes"); this package is JSON-only.
package wireproto

import (
	"encoding/json"
	"fmt"
)

// Type discriminators for cleartext JSON messages.
const (
	TypeChallenge          = "challenge"
	TypeIdentify           = "identify"
	TypeWelcome            = "welcome"
	TypeError              = "error"
	TypePeerList           = "peer-list"
	TypePeerJoined         = "peer-joined"
	TypePeerLeft           = "peer-left"
	TypeInvite             = "invite"
	TypeAccept             = "accept"
	TypeReject             = "reject"
	TypeInviteFrom         = "invite-from"
	TypeAcceptFrom         = "accept-from"
	TypeRejectFrom         = "reject-from"
	TypeInviteDeferred     = "invite-deferred"
	TypeInviteAutoRejected = "invite-auto-rejected"
)

// ErrorCode discriminators for ErrorMsg.Code. Stable strings — clients
// match against these to decide whether to retry / surface an error UI.
const (
	ErrCodeMalformed        = "malformed"
	ErrCodeInvalidSignature = "invalid-signature"
	ErrCodeInternal         = "internal-error"
)

// JSON encoding caveat for []byte fields: callers MUST populate every []byte
// field on these message structs before marshaling. encoding/json marshals a
// nil []byte as the literal `null` (not `""`, and not the base64 of the empty
// string), which the TS side may not expect when it does a length check or a
// base64 decode on the wire string. If a future field is genuinely optional,
// use `omitempty` plus an explicit unmarshal-time check rather than relying
// on `null`-vs-`""` ambiguity. There is a pinning test in wireproto_test.go
// (TestNilByteFieldsMarshalAsNull) so a refactor that changes this behavior
// fails loudly.

// PeerRecord is the discovery-row representation of a peer. Clients render
// the six-word BIP-39 fingerprint of Ed25519Pub for human verification, and
// use SigBinding to verify locally that X25519Pub is bound to the identity.
//
// IP is the bare IP literal as returned by net.SplitHostPort — IPv6 addresses
// are NOT bracketed, so callers reconstructing a URL must re-bracket (e.g.
// `net.JoinHostPort(record.IP, strconv.Itoa(record.Port))` produces a
// URL-safe authority).
type PeerRecord struct {
	Ed25519Pub []byte `json:"ed25519_pub"`
	X25519Pub  []byte `json:"x25519_pub"`
	SigBinding []byte `json:"sig_binding"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
}

// ChallengeMsg is the relay's connect-time nonce challenge. Sent by the
// relay as the first message on every WebSocket connection.
type ChallengeMsg struct {
	Type  string `json:"type"`
	Nonce []byte `json:"nonce"`
}

// IdentifyMsg is the client's response to a ChallengeMsg.
//   - SigLiveness = sign_ed25519(Nonce) — proves possession of ed25519_priv.
//   - SigBinding  = sign_ed25519("LemurPouch/v1/bind-x25519:" || x25519_pub)
//     — proves x25519_pub is bound to this identity, forwardable via discovery.
type IdentifyMsg struct {
	Type        string `json:"type"`
	Ed25519Pub  []byte `json:"ed25519_pub"`
	X25519Pub   []byte `json:"x25519_pub"`
	SigLiveness []byte `json:"sig_liveness"`
	SigBinding  []byte `json:"sig_binding"`
}

// WelcomeLimits is the optional capability block on WelcomeMsg. Old relays
// omit it entirely; clients treat absence as max_chunk_bytes = 64 KiB
// (legacy floor). See AGENTS.md "Flow Control & Negotiated Limits".
type WelcomeLimits struct {
	// MaxChunkBytes is the largest raw chunk-data size the relay will
	// forward. The actual SetReadLimit is larger (frame = chunk + envelope
	// overhead + headroom).
	MaxChunkBytes int `json:"max_chunk_bytes"`
}

// WelcomeMsg is the relay's confirmation that identification succeeded.
// You is the relay's view of the connecting peer (including the source IP
// and ephemeral port the relay observed). Limits is optional (omitempty).
type WelcomeMsg struct {
	Type   string         `json:"type"`
	You    PeerRecord     `json:"you"`
	Limits *WelcomeLimits `json:"limits,omitempty"`
}

// ErrorMsg is the relay's rejection of a malformed or unauthorized message.
// Code is one of the ErrCode* constants; Message is human-readable detail.
type ErrorMsg struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PeekType reads only the "type" field of a JSON message — used by the
// relay (and the client) to dispatch to the correct concrete struct for
// full unmarshalling without committing to a type up front.
func PeekType(data []byte) (string, error) {
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return "", fmt.Errorf("wireproto: peek type: %w", err)
	}
	return env.Type, nil
}

// MarshalChallenge / MarshalIdentify / MarshalWelcome / MarshalError are
// thin wrappers that set the Type field to the spec-mandated string before
// JSON-encoding. Keeping the type string in one place per message prevents
// callers from accidentally constructing a struct with the wrong type
// discriminator.

func MarshalChallenge(m ChallengeMsg) ([]byte, error) {
	m.Type = TypeChallenge
	return json.Marshal(m)
}

func MarshalIdentify(m IdentifyMsg) ([]byte, error) {
	m.Type = TypeIdentify
	return json.Marshal(m)
}

func MarshalWelcome(m WelcomeMsg) ([]byte, error) {
	m.Type = TypeWelcome
	return json.Marshal(m)
}

func MarshalError(m ErrorMsg) ([]byte, error) {
	m.Type = TypeError
	return json.Marshal(m)
}
