package cryptoid

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func mustGenerate(t *testing.T) *Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func TestSignLivenessRoundTrip(t *testing.T) {
	id := mustGenerate(t)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}

	sig := id.SignLiveness(nonce)
	if !VerifyLiveness(id.Ed25519Pub, nonce, sig) {
		t.Fatal("VerifyLiveness rejected its own signature")
	}

	// Tampered nonce must fail.
	tampered := append([]byte(nil), nonce...)
	tampered[0] ^= 0x01
	if VerifyLiveness(id.Ed25519Pub, tampered, sig) {
		t.Fatal("VerifyLiveness accepted a tampered nonce")
	}

	// Wrong public key must fail.
	other := mustGenerate(t)
	if VerifyLiveness(other.Ed25519Pub, nonce, sig) {
		t.Fatal("VerifyLiveness accepted a foreign public key")
	}
}

func TestSignBindingRoundTrip(t *testing.T) {
	id := mustGenerate(t)

	sig := id.SignBinding()
	if !VerifyBinding(id.Ed25519Pub, id.X25519Pub.Bytes(), sig) {
		t.Fatal("VerifyBinding rejected its own signature")
	}

	// Tampered X25519 pub must fail (would defeat MITM resistance otherwise).
	tampered := append([]byte(nil), id.X25519Pub.Bytes()...)
	tampered[0] ^= 0x01
	if VerifyBinding(id.Ed25519Pub, tampered, sig) {
		t.Fatal("VerifyBinding accepted a tampered X25519 public key")
	}

	// A signature with the wrong domain separator must fail. We forge one
	// that signs just the X25519 pub without the BindContext prefix and
	// confirm VerifyBinding rejects it.
	rawSig := ed25519.Sign(id.Ed25519Priv, id.X25519Pub.Bytes())
	if VerifyBinding(id.Ed25519Pub, id.X25519Pub.Bytes(), rawSig) {
		t.Fatal("VerifyBinding accepted a signature lacking the bind-x25519 domain separator")
	}
}

func TestSharedSecretSymmetric(t *testing.T) {
	a := mustGenerate(t)
	b := mustGenerate(t)

	secretA, err := a.sharedSecret(b.X25519Pub)
	if err != nil {
		t.Fatalf("a.sharedSecret: %v", err)
	}
	secretB, err := b.sharedSecret(a.X25519Pub)
	if err != nil {
		t.Fatalf("b.sharedSecret: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("shared secrets differ: a=%x b=%x", secretA, secretB)
	}
}

func TestFriendshipKeysSymmetric(t *testing.T) {
	a := mustGenerate(t)
	b := mustGenerate(t)

	aSend, aRecv, err := a.FriendshipKeys(b.Ed25519Pub, b.X25519Pub)
	if err != nil {
		t.Fatalf("a.FriendshipKeys: %v", err)
	}
	bSend, bRecv, err := b.FriendshipKeys(a.Ed25519Pub, a.X25519Pub)
	if err != nil {
		t.Fatalf("b.FriendshipKeys: %v", err)
	}

	// A's send key should equal B's recv key, and vice versa.
	if aSend != bRecv {
		t.Fatalf("aSend != bRecv: aSend=%x bRecv=%x", aSend, bRecv)
	}
	if aRecv != bSend {
		t.Fatalf("aRecv != bSend: aRecv=%x bSend=%x", aRecv, bSend)
	}
	// The two directional keys should be distinct.
	if aSend == aRecv {
		t.Fatal("aSend == aRecv — directional keys should differ")
	}
}

func TestSelfFriendshipReturnsError(t *testing.T) {
	id := mustGenerate(t)
	_, _, err := id.FriendshipKeys(id.Ed25519Pub, id.X25519Pub)
	if !errors.Is(err, ErrSelfFriendship) {
		t.Fatalf("FriendshipKeys(self, self) error = %v, want ErrSelfFriendship", err)
	}
}

// TestFriendshipKeysRejectsBadEd25519PubLen confirms FriendshipKeys returns
// ErrInvalidEd25519PubKey for malformed peer ed25519 public keys, rather
// than silently producing wrong-length-input HKDF output that the peer's
// correct implementation can't reproduce.
func TestFriendshipKeysRejectsBadEd25519PubLen(t *testing.T) {
	a := mustGenerate(t)
	b := mustGenerate(t)
	for _, badPub := range [][]byte{nil, {}, bytes.Repeat([]byte{0xAA}, 31), bytes.Repeat([]byte{0xAA}, 33)} {
		_, _, err := a.FriendshipKeys(ed25519.PublicKey(badPub), b.X25519Pub)
		if !errors.Is(err, ErrInvalidEd25519PubKey) {
			t.Errorf("FriendshipKeys with %d-byte ed25519 pub: err = %v, want ErrInvalidEd25519PubKey", len(badPub), err)
		}
	}
}

// TestFriendshipKeysDistinctAcrossPeers confirms that distinct peer-pairs
// produce disjoint friendship keys. Guards against a regression that
// dropped the X25519 shared secret from deriveSessionKeys and used only
// the public-key-based salt — which would produce the same key for every
// friendship in a session and pass every other test.
func TestFriendshipKeysDistinctAcrossPeers(t *testing.T) {
	a := mustGenerate(t)
	b := mustGenerate(t)
	c := mustGenerate(t)

	abSend, abRecv, err := a.FriendshipKeys(b.Ed25519Pub, b.X25519Pub)
	if err != nil {
		t.Fatalf("a.FriendshipKeys(b): %v", err)
	}
	acSend, acRecv, err := a.FriendshipKeys(c.Ed25519Pub, c.X25519Pub)
	if err != nil {
		t.Fatalf("a.FriendshipKeys(c): %v", err)
	}
	bcSend, bcRecv, err := b.FriendshipKeys(c.Ed25519Pub, c.X25519Pub)
	if err != nil {
		t.Fatalf("b.FriendshipKeys(c): %v", err)
	}

	pairs := []struct {
		name string
		x, y [32]byte
	}{
		{"a→b send vs a→c send", abSend, acSend},
		{"a→b send vs a→c recv", abSend, acRecv},
		{"a→b recv vs a→c send", abRecv, acSend},
		{"a→b recv vs a→c recv", abRecv, acRecv},
		{"a→b send vs b→c send", abSend, bcSend},
		{"a→b send vs b→c recv", abSend, bcRecv},
		{"a→b recv vs b→c send", abRecv, bcSend},
		{"a→b recv vs b→c recv", abRecv, bcRecv},
		{"a→c send vs b→c send", acSend, bcSend},
		{"a→c send vs b→c recv", acSend, bcRecv},
		{"a→c recv vs b→c send", acRecv, bcSend},
		{"a→c recv vs b→c recv", acRecv, bcRecv},
	}
	for _, p := range pairs {
		if p.x == p.y {
			t.Errorf("%s: keys collide (%x) — friendship keys should differ across peer-pairs", p.name, p.x)
		}
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}

	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	const innerType byte = 0x01 // simulate the wire protocol's inner-type byte
	nonce, ciphertext, err := EncryptEnvelope(key, plaintext, innerType)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	if len(nonce) != 24 {
		t.Fatalf("nonce length = %d, want 24", len(nonce))
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext — encryption no-op?")
	}

	decoded, err := DecryptEnvelope(key, nonce, ciphertext, innerType)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decoded != plaintext\n got: %q\nwant: %q", decoded, plaintext)
	}
}

// TestEncryptEnvelopeFreshNoncePerCall confirms that two calls to
// EncryptEnvelope with the same key, plaintext, and innerType produce
// distinct nonces (and therefore distinct ciphertexts). XChaCha20-Poly1305
// nonce reuse is catastrophic, so a regression to a static or counter-
// based nonce inside EncryptEnvelope must be caught here — the round-trip
// and tamper tests both pass under any nonce policy.
func TestEncryptEnvelopeFreshNoncePerCall(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	plaintext := []byte("identical plaintext")
	const innerType byte = 0x01

	nonce1, ct1, err := EncryptEnvelope(key, plaintext, innerType)
	if err != nil {
		t.Fatalf("EncryptEnvelope #1: %v", err)
	}
	nonce2, ct2, err := EncryptEnvelope(key, plaintext, innerType)
	if err != nil {
		t.Fatalf("EncryptEnvelope #2: %v", err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Fatalf("two EncryptEnvelope calls produced identical nonces (%x) — nonce is not fresh per call", nonce1)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatalf("two EncryptEnvelope calls produced identical ciphertexts — nonce reuse implied")
	}
}

func TestDecryptFailsOnTamper(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	const innerType byte = 0x01
	nonce, ciphertext, err := EncryptEnvelope(key, []byte("payload"), innerType)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	// Flip a ciphertext byte; AEAD authentication must fail.
	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0x01
	if _, err := DecryptEnvelope(key, nonce, tampered, innerType); err == nil {
		t.Fatal("DecryptEnvelope accepted a tampered ciphertext")
	}

	// Flip a nonce byte; AEAD authentication must fail.
	tamperedNonce := append([]byte(nil), nonce...)
	tamperedNonce[0] ^= 0x01
	if _, err := DecryptEnvelope(key, tamperedNonce, ciphertext, innerType); err == nil {
		t.Fatal("DecryptEnvelope accepted a tampered nonce")
	}

	// Wrong key must fail.
	var wrongKey [32]byte
	if _, err := rand.Read(wrongKey[:]); err != nil {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := DecryptEnvelope(wrongKey, nonce, ciphertext, innerType); err == nil {
		t.Fatal("DecryptEnvelope accepted ciphertext under a foreign key")
	}
}

// TestInnerTypeMismatchFailsDecryption confirms that flipping the inner-type
// byte (the AAD bound by EncryptEnvelope) breaks decryption — defending
// against a tampering relay flipping 0x01 ↔ 0x02 to confuse the recipient
// about how to interpret the plaintext (AGENTS.md "Encrypted Envelopes").
func TestInnerTypeMismatchFailsDecryption(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	plaintext := []byte("typed payload")
	nonce, ciphertext, err := EncryptEnvelope(key, plaintext, 0x01)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	// Tampering relay flips the inner-type byte mid-flight.
	if _, err := DecryptEnvelope(key, nonce, ciphertext, 0x02); err == nil {
		t.Fatal("DecryptEnvelope accepted a flipped inner-type byte")
	}

	// Sanity: the original inner-type still works.
	if _, err := DecryptEnvelope(key, nonce, ciphertext, 0x01); err != nil {
		t.Fatalf("DecryptEnvelope failed with the original inner-type: %v", err)
	}
}

func TestFingerprintFormat(t *testing.T) {
	id := mustGenerate(t)
	fp := Fingerprint(id.Ed25519Pub)

	parts := strings.Split(fp, "-")
	if len(parts) != 6 {
		t.Fatalf("fingerprint = %q, want 6 hyphenated words, got %d parts", fp, len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Fatalf("fingerprint word %d is empty: %q", i, fp)
		}
	}

	// Determinism: same input → same output.
	if Fingerprint(id.Ed25519Pub) != fp {
		t.Fatal("Fingerprint is non-deterministic for the same input")
	}

	// Distinct identities should (overwhelmingly) yield distinct fingerprints.
	other := mustGenerate(t)
	if Fingerprint(other.Ed25519Pub) == fp {
		t.Fatal("two random identities produced the same fingerprint — exceedingly unlikely")
	}
}

// TestKnownVectors pins the canonical wire-protocol outputs for a fixed pair
// of identities. Any change to the domain-separator strings, HKDF inputs,
// signing/binding construction, or fingerprint bit math will break this test.
// The TypeScript implementation must replicate these byte-identical values.
//
// Ed25519 signing in Go's stdlib is RFC 8032 deterministic, so the binding
// signatures are stable across runs and machines.
//
// EncryptEnvelope's ciphertext is non-deterministic (random nonce per call),
// so the round-trip test pins behavior. For byte-stable cross-implementation
// AEAD checking, we additionally seal a known plaintext with a known nonce
// and pin that ciphertext — see the fixedNonceCiphertext check below.
func TestKnownVectors(t *testing.T) {
	// Deterministic Ed25519 keys derived from fixed seeds.
	seedA := bytes.Repeat([]byte{0x01}, 32)
	seedB := bytes.Repeat([]byte{0x02}, 32)
	edPrivA := ed25519.NewKeyFromSeed(seedA)
	edPrivB := ed25519.NewKeyFromSeed(seedB)
	edPubA := edPrivA.Public().(ed25519.PublicKey)
	edPubB := edPrivB.Public().(ed25519.PublicKey)

	// Deterministic X25519 keys from fixed scalars.
	xPrivABytes := bytes.Repeat([]byte{0x11}, 32)
	xPrivBBytes := bytes.Repeat([]byte{0x22}, 32)
	xPrivA, err := ecdh.X25519().NewPrivateKey(xPrivABytes)
	if err != nil {
		t.Fatalf("xPrivA: %v", err)
	}
	xPrivB, err := ecdh.X25519().NewPrivateKey(xPrivBBytes)
	if err != nil {
		t.Fatalf("xPrivB: %v", err)
	}

	idA := &Identity{
		Ed25519Priv: edPrivA, Ed25519Pub: edPubA,
		X25519Priv: xPrivA, X25519Pub: xPrivA.PublicKey(),
	}
	idB := &Identity{
		Ed25519Priv: edPrivB, Ed25519Pub: edPubB,
		X25519Priv: xPrivB, X25519Pub: xPrivB.PublicKey(),
	}

	// Bind signatures must verify.
	bindA := idA.SignBinding()
	bindB := idB.SignBinding()
	if !VerifyBinding(idA.Ed25519Pub, idA.X25519Pub.Bytes(), bindA) {
		t.Fatal("idA bind signature failed verification")
	}
	if !VerifyBinding(idB.Ed25519Pub, idB.X25519Pub.Bytes(), bindB) {
		t.Fatal("idB bind signature failed verification")
	}

	// Pin the raw X25519 shared-secret bytes too. The friendship-key check
	// below transitively covers the secret, but a compensating-error
	// regression (wrong shared secret + compensating salt) could still
	// pass that test. Pinning the secret directly closes that gap, and
	// the same pinned hex appears in the TS-side TestKnownVectors.
	sharedAB, err := idA.sharedSecret(idB.X25519Pub)
	if err != nil {
		t.Fatalf("idA.sharedSecret(idB): %v", err)
	}
	const wantSharedAB = "9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056"
	if got := hex.EncodeToString(sharedAB); got != wantSharedAB {
		t.Errorf("shared_secret_a_b mismatch\n got:  %s\n want: %s", got, wantSharedAB)
	}

	// Friendship keys must agree across both peers' perspectives.
	aSend, aRecv, err := idA.FriendshipKeys(idB.Ed25519Pub, idB.X25519Pub)
	if err != nil {
		t.Fatalf("idA.FriendshipKeys: %v", err)
	}
	bSend, bRecv, err := idB.FriendshipKeys(idA.Ed25519Pub, idA.X25519Pub)
	if err != nil {
		t.Fatalf("idB.FriendshipKeys: %v", err)
	}
	if aSend != bRecv || aRecv != bSend {
		t.Fatal("friendship keys disagree between the two perspectives")
	}

	// Encrypt/decrypt with the derived keys to confirm end-to-end works.
	plaintext := []byte("hello from the test vector")
	nonce, ct, err := EncryptEnvelope(aSend, plaintext, 0x01)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	got, err := DecryptEnvelope(bRecv, nonce, ct, 0x01)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got=%q want=%q", got, plaintext)
	}

	// Pinned canonical outputs. The TS implementation must reproduce these
	// byte-identically given the same fixed inputs.
	checks := []struct {
		name string
		got  []byte
		want string
	}{
		{"ed25519_pub_a", idA.Ed25519Pub, "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"},
		{"ed25519_pub_b", idB.Ed25519Pub, "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"},
		{"x25519_pub_a", idA.X25519Pub.Bytes(), "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"},
		{"x25519_pub_b", idB.X25519Pub.Bytes(), "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"},
		// Re-pinned after project rename (BindContext / SessionInfo use
		// "LemurPouch/v1/…"); pub keys and fingerprints are unchanged.
		{"sig_binding_a", bindA, "ab139c475be82663df061235f90ba673fc2bd03d538fdc1abbac7f389ea004155e859b2101245ba5c517f4042575ed60f8b7807bd4d6f31116b0b6bfe95b620e"},
		{"sig_binding_b", bindB, "8d7dd65774c7b9a634bcf9c587d59b310fc32010f27700c06f9ddb4222591daba719a68d04abc5ff559f3bbc29d19dae59219144606befdc484a0be5f2a56b0e"},
		{"a_send_key", aSend[:], "11182abd48889b89121dd5a5ebcacb5909d61b1af54ddb52de58c0b196a16d92"},
		{"a_recv_key", aRecv[:], "23e9e976c36df982e2f05f997c47ee698f1e4f2a6253716f53380bc184f2253b"},
	}
	for _, c := range checks {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s mismatch\n got:  %s\n want: %s", c.name, got, c.want)
		}
	}

	if got := Fingerprint(idA.Ed25519Pub); got != "crucial-position-tower-kingdom-panther-layer" {
		t.Errorf("fingerprint_a = %q", got)
	}
	if got := Fingerprint(idB.Ed25519Pub); got != "health-scale-voice-thing-october-bench" {
		t.Errorf("fingerprint_b = %q", got)
	}

	// Pin a fixed-nonce ciphertext so the TS port can byte-check the AEAD
	// path — the round-trip alone wouldn't catch a bug where Go and TS
	// implement XChaCha20-Poly1305 (or its AAD binding) differently.
	fixedNonce := bytes.Repeat([]byte{0x33}, 24)
	aead, err := chacha20poly1305.NewX(aSend[:])
	if err != nil {
		t.Fatalf("aead init: %v", err)
	}
	fixedCT := aead.Seal(nil, fixedNonce, []byte("hello, fixed nonce"), []byte{0x01})
	const wantFixedCT = "8cf5b924f35a2da205a24834a118a1ea9230e71f8a8f306db1d65bdc651ad80524bc"
	if got := hex.EncodeToString(fixedCT); got != wantFixedCT {
		t.Errorf("fixed-nonce ciphertext mismatch\n got:  %s\n want: %s", got, wantFixedCT)
	}
}

// TestVerifyHandlesShortKeys confirms the Verify* helpers return false (not
// panic) when given mismatched-length keys. The underlying stdlib calls
// (ed25519.Verify on the ed25519 pub, the message construction on the
// x25519 pub) need length-guards in front of them for safe handling of
// malformed network input.
func TestVerifyHandlesShortKeys(t *testing.T) {
	id := mustGenerate(t)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	sig := id.SignLiveness(nonce)
	bindSig := id.SignBinding()

	// Cover both shorter and longer than 32 — guards are `!=`, not `<`.
	badLengths := [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{0xAA}, 31),
		bytes.Repeat([]byte{0xAA}, 33),
	}
	for _, badKey := range badLengths {
		if VerifyLiveness(badKey, nonce, sig) {
			t.Errorf("VerifyLiveness accepted a %d-byte ed25519 pub", len(badKey))
		}
		if VerifyBinding(badKey, id.X25519Pub.Bytes(), bindSig) {
			t.Errorf("VerifyBinding accepted a %d-byte ed25519 pub", len(badKey))
		}
		// Also exercise the x25519Pub length guard added in round 3.
		if VerifyBinding(id.Ed25519Pub, badKey, bindSig) {
			t.Errorf("VerifyBinding accepted a %d-byte x25519 pub", len(badKey))
		}
	}
}

// TestDecryptHandlesShortNonce confirms DecryptEnvelope returns an error
// (not panic) when given a nonce of unexpected length. chacha20poly1305.Open
// panics on wrong nonce length; the length check in DecryptEnvelope is
// load-bearing for safe handling of malformed network input.
func TestDecryptHandlesShortNonce(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("key: %v", err)
	}
	_, ct, err := EncryptEnvelope(key, []byte("payload"), 0x01)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	for _, badNonce := range [][]byte{nil, {}, bytes.Repeat([]byte{0x01}, 23), bytes.Repeat([]byte{0x01}, 25)} {
		if _, err := DecryptEnvelope(key, badNonce, ct, 0x01); err == nil {
			t.Errorf("DecryptEnvelope accepted a %d-byte nonce", len(badNonce))
		}
	}
}

// TestSignLivenessRejectsEmptyNonce confirms that SignLiveness panics on
// an empty nonce. Signing an empty/all-zero nonce would let a relay replay
// a fixed signature across reconnects (the liveness handshake re-uses the
// signature as freshness proof); failing loudly at the API boundary stops
// that footgun.
func TestSignLivenessRejectsEmptyNonce(t *testing.T) {
	id := mustGenerate(t)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("SignLiveness with an empty nonce did not panic")
		}
	}()
	id.SignLiveness(nil)
}

// TestFriendshipKeysWrongDirection confirms that B can only decrypt A's
// messages with B's recv key (not B's send key). This guards against a
// mistake where the directional mapping in FriendshipKeys regresses.
func TestFriendshipKeysWrongDirection(t *testing.T) {
	a := mustGenerate(t)
	b := mustGenerate(t)

	aSend, _, err := a.FriendshipKeys(b.Ed25519Pub, b.X25519Pub)
	if err != nil {
		t.Fatalf("a.FriendshipKeys: %v", err)
	}
	bSend, bRecv, err := b.FriendshipKeys(a.Ed25519Pub, a.X25519Pub)
	if err != nil {
		t.Fatalf("b.FriendshipKeys: %v", err)
	}

	plaintext := []byte("from A to B")
	nonce, ct, err := EncryptEnvelope(aSend, plaintext, 0x01)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}

	if _, err := DecryptEnvelope(bRecv, nonce, ct, 0x01); err != nil {
		t.Fatalf("decrypting with bRecv (the correct key) failed: %v", err)
	}
	if _, err := DecryptEnvelope(bSend, nonce, ct, 0x01); err == nil {
		t.Fatal("decrypting A→B with bSend (B's outbound key) succeeded — directional mapping is broken")
	}
}
