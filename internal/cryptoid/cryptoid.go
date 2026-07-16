// Package cryptoid implements the identity and end-to-end encryption
// primitives for the LemurPouch relay's wire protocol. See AGENTS.md
// "Identity", "End-to-End Encryption", and "Wire Protocol".
//
// Two keypairs per peer, both session-lifetime:
//   - Ed25519 for identity authentication and binding the X25519 key.
//   - X25519 for ECDH; reused across all friendships in a session.
//
// Per-friendship session keys are derived via HKDF-SHA256 from the X25519
// shared secret, with two directional keys (one per direction of message
// flow). Encryption is XChaCha20-Poly1305 with a fresh random 24-byte
// nonce per envelope.
package cryptoid

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/chacha20poly1305"
)

// Domain-separator strings. The wire protocol depends on these being
// byte-identical across the Go relay and the TS browser client; if they
// drift, the two sides won't agree on session keys or signatures.
// See AGENTS.md "Wire Protocol > Domain Separators".
const (
	BindContext = "LemurPouch/v1/bind-x25519:"
	SessionInfo = "LemurPouch/v1/session:"
)

// canonicalWordList is a package-private snapshot of the BIP-39 English
// wordlist taken at init time. Fingerprint indexes this snapshot rather
// than calling bip39.GetWordList() per call, so a downstream
// bip39.SetWordList(...) executed after init() cannot retroactively change
// any fingerprint the relay renders. AGENTS.md "MITM Resistance" makes the
// wordlist load-bearing for trust.
var canonicalWordList []string

// init pins the BIP-39 English wordlist for Fingerprint(). The bip39
// package exposes SetWordList/GetWordList as global mutators; if some
// other package imported into the relay binary swaps in a different
// language, every fingerprint we render would silently change. Sentinel-
// check at startup so any drift fails loudly here, not in the field, and
// snapshot the list into canonicalWordList so subsequent SetWordList calls
// cannot affect us.
func init() {
	list := bip39.GetWordList()
	if len(list) != 2048 || list[0] != "abandon" || list[2047] != "zoo" {
		panic("cryptoid: bip39 wordlist is not the canonical English list — fingerprints depend on it")
	}
	canonicalWordList = make([]string, len(list))
	copy(canonicalWordList, list)
}

// Identity holds a peer's session-lifetime keypairs.
//
// An Identity is safe for concurrent use by multiple goroutines after
// GenerateIdentity returns: the underlying stdlib types (ed25519.Sign and
// (*ecdh.PrivateKey).ECDH) are concurrency-safe. Callers must not mutate
// the exported fields after construction; treat them as read-only.
type Identity struct {
	Ed25519Priv ed25519.PrivateKey
	Ed25519Pub  ed25519.PublicKey
	X25519Priv  *ecdh.PrivateKey
	X25519Pub   *ecdh.PublicKey
}

// GenerateIdentity creates a fresh per-session identity from secure randomness.
func GenerateIdentity() (*Identity, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	return &Identity{
		Ed25519Priv: edPriv,
		Ed25519Pub:  edPub,
		X25519Priv:  xPriv,
		X25519Pub:   xPriv.PublicKey(),
	}, nil
}

// SignLiveness signs the relay's connection-time nonce, proving possession
// of the Ed25519 private key for this connection.
//
// Panics if id.Ed25519Priv is not a valid Ed25519 private key (which can
// only happen if Identity was constructed manually rather than via
// GenerateIdentity).
func (id *Identity) SignLiveness(nonce []byte) []byte {
	if len(nonce) == 0 {
		panic("cryptoid: nonce must be non-empty")
	}
	return ed25519.Sign(id.Ed25519Priv, nonce)
}

// VerifyLiveness checks a peer's nonce signature against their Ed25519
// public key. Returns false (without panicking) on malformed inputs.
func VerifyLiveness(ed25519Pub ed25519.PublicKey, nonce, sig []byte) bool {
	if len(ed25519Pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519Pub, nonce, sig)
}

// SignBinding produces the signature that ties this identity's X25519 public
// key to its Ed25519 identity. The signature is forwarded to other peers via
// discovery so they can verify the binding locally.
//
// Panics if id has zero or malformed key fields (see GenerateIdentity).
func (id *Identity) SignBinding() []byte {
	msg := append([]byte(BindContext), id.X25519Pub.Bytes()...)
	return ed25519.Sign(id.Ed25519Priv, msg)
}

// VerifyBinding checks that x25519Pub is bound to ed25519Pub by sig.
// Returns false (without panicking) on malformed inputs. x25519Pub must be
// exactly 32 bytes — anything else is structurally invalid for X25519
// regardless of whether the signature happens to verify, and we'd rather
// reject early than verify a malformed message and have the call site
// fail later when it tries to use the bytes as an X25519 public key.
func VerifyBinding(ed25519Pub ed25519.PublicKey, x25519Pub, sig []byte) bool {
	if len(ed25519Pub) != ed25519.PublicKeySize || len(x25519Pub) != 32 {
		return false
	}
	msg := append([]byte(BindContext), x25519Pub...)
	return ed25519.Verify(ed25519Pub, msg, sig)
}

// sharedSecret computes X25519(my_priv, peer_pub).
//
// Takes peer's *ecdh.PublicKey rather than raw bytes so the type system
// prevents accidentally passing an ed25519 public key (both are 32 bytes
// of seemingly indistinguishable []byte).
//
// Unexported: the spec requires the raw ECDH output to be wrapped in HKDF
// with directional separation (see FriendshipKeys). Exposing it on the
// public API is a footgun — a future caller could silently bypass HKDF
// and reuse keys across friendships. Use FriendshipKeys instead.
func (id *Identity) sharedSecret(peerX25519Pub *ecdh.PublicKey) ([]byte, error) {
	return id.X25519Priv.ECDH(peerX25519Pub)
}

// ErrSelfFriendship is returned by FriendshipKeys when the peer's Ed25519
// public key matches the local identity's. Friending self is a programming
// bug; failing loudly at the API boundary is better than the silent
// degenerate-key behavior the underlying derivation would otherwise produce.
var ErrSelfFriendship = errors.New("cryptoid: cannot derive friendship keys with self")

// ErrInvalidEd25519PubKey is returned by FriendshipKeys when the peer's
// Ed25519 public key is not exactly 32 bytes. Catching the malformed input
// at the API boundary produces a clear error here, rather than letting the
// wrong-length bytes flow into HKDF and producing keys the peer's correct
// implementation can't reproduce — which would surface much later as an
// inscrutable AEAD authentication failure at decrypt time.
var ErrInvalidEd25519PubKey = errors.New("cryptoid: peer ed25519 pub must be 32 bytes")

// FriendshipKeys derives the two directional session keys for the friendship
// between this identity and the peer.
//
//	sendKey is for messages this identity encrypts and sends to peer.
//	recvKey is for messages peer sends to this identity.
//
// Both peers compute the same pair of keys; whichever is "send" or "recv"
// from each side's perspective is determined by the lex order of the two
// Ed25519 public keys (see AGENTS.md "Wire Protocol > Domain Separators").
//
// Returns ErrInvalidEd25519PubKey if peerEd25519Pub is not 32 bytes, or
// ErrSelfFriendship if peerEd25519Pub matches id.Ed25519Pub.
func (id *Identity) FriendshipKeys(peerEd25519Pub ed25519.PublicKey, peerX25519Pub *ecdh.PublicKey) (sendKey, recvKey [32]byte, err error) {
	if len(peerEd25519Pub) != ed25519.PublicKeySize {
		return sendKey, recvKey, ErrInvalidEd25519PubKey
	}
	if bytes.Equal(id.Ed25519Pub, peerEd25519Pub) {
		return sendKey, recvKey, ErrSelfFriendship
	}
	shared, err := id.sharedSecret(peerX25519Pub)
	if err != nil {
		return sendKey, recvKey, err
	}
	keyAtoB, keyBtoA, err := deriveSessionKeys(shared, id.Ed25519Pub, peerEd25519Pub)
	if err != nil {
		return sendKey, recvKey, err
	}
	if bytes.Compare(id.Ed25519Pub, peerEd25519Pub) < 0 {
		// I am 'a': I send a-to-b, I receive b-to-a.
		return keyAtoB, keyBtoA, nil
	}
	// I am 'b': I send b-to-a, I receive a-to-b.
	return keyBtoA, keyAtoB, nil
}

// deriveSessionKeys returns the two directional keys for a friendship.
// keyAtoB is for messages from the lex-smaller identity ("a") to the larger ("b").
func deriveSessionKeys(shared, pubA, pubB []byte) (keyAtoB, keyBtoA [32]byte, err error) {
	salt := lexSortedConcat(pubA, pubB)
	atobBytes, err := hkdf.Key(sha256.New, shared, salt, SessionInfo+"a-to-b", 32)
	if err != nil {
		return keyAtoB, keyBtoA, fmt.Errorf("hkdf a-to-b: %w", err)
	}
	btoaBytes, err := hkdf.Key(sha256.New, shared, salt, SessionInfo+"b-to-a", 32)
	if err != nil {
		return keyAtoB, keyBtoA, fmt.Errorf("hkdf b-to-a: %w", err)
	}
	copy(keyAtoB[:], atobBytes)
	copy(keyBtoA[:], btoaBytes)
	return keyAtoB, keyBtoA, nil
}

// lexSortedConcat returns min(a, b) || max(a, b), comparing byte-wise.
func lexSortedConcat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	if bytes.Compare(a, b) < 0 {
		out = append(out, a...)
		out = append(out, b...)
	} else {
		out = append(out, b...)
		out = append(out, a...)
	}
	return out
}

// EncryptEnvelope returns (nonce, ciphertext) for the given plaintext, with
// the inner-type byte bound into the AEAD tag as additional authenticated
// data. XChaCha20-Poly1305's 192-bit nonce makes the random nonce safe with
// negligible birthday-bound collision probability.
//
// innerType is the wire-protocol's inner-type byte (0x01 for JSON control,
// 0x02 for file chunk; see AGENTS.md "Encrypted Envelopes"). Single-byte
// type rather than []byte AAD because the spec is unambiguous: the AAD is
// always exactly the inner-type byte. Encoding that as a single byte
// removes a class of misuse where a caller passes the whole frame header.
func EncryptEnvelope(key [32]byte, plaintext []byte, innerType byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("aead init: %w", err)
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, []byte{innerType})
	return nonce, ciphertext, nil
}

// DecryptEnvelope reverses EncryptEnvelope. Returns an error if the AEAD
// authentication tag fails (tampered ciphertext, tampered nonce, mismatched
// inner-type, or wrong key).
func DecryptEnvelope(key [32]byte, nonce, ciphertext []byte, innerType byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce length")
	}
	pt, err := aead.Open(nil, nonce, ciphertext, []byte{innerType})
	if err != nil {
		return nil, fmt.Errorf("aead open: %w", err)
	}
	return pt, nil
}

// Fingerprint renders an Ed25519 public key as the six-word BIP-39 fingerprint
// described in AGENTS.md: the first 66 bits of SHA-256(ed25519_pub) split
// into six 11-bit chunks, each indexing the BIP-39 English wordlist, joined
// by hyphens (e.g. "abandon-ladder-quantum-tribe-yellow-velvet").
func Fingerprint(ed25519Pub []byte) string {
	hash := sha256.Sum256(ed25519Pub)
	// 66 bits don't fit in a uint64, so handle the first 64 bits separately
	// from the trailing 2 bits that come from hash[8].
	hi := binary.BigEndian.Uint64(hash[:8]) // hash bits 0..63
	lo := hash[8]                           // hash bits 64..71

	wordList := canonicalWordList
	words := make([]string, 6)

	// Words 0..4 cover hash bits 0..54 — entirely within hi. In hi, hash
	// bit p sits at uint64 position (63 - p) (big-endian packing). So word
	// i's lowest bit (hash bit 11i+10) sits at hi position 53 - 11i; shift
	// hi right by that amount and mask 11 bits.
	for i := 0; i < 5; i++ {
		shift := uint(53 - 11*i) // 53, 42, 31, 20, 9
		words[i] = wordList[(hi>>shift)&0x7FF]
	}

	// Word 5 covers hash bits 55..65 — the bottom 9 bits of hi (hash bits
	// 55..63) followed by the top 2 bits of lo (hash bits 64..65).
	word5 := (hi&0x1FF)<<2 | uint64(lo>>6)
	words[5] = wordList[word5]

	return strings.Join(words, "-")
}
