package credproto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

func makeBundle(t *testing.T, identPub ed25519.PublicKey, identPriv ed25519.PrivateKey, expiresAt time.Time) *credproto.ConsumerBundle {
	t.Helper()
	sessionPub := make([]byte, 32)
	rand.Read(sessionPub)

	b := &credproto.ConsumerBundle{
		ConsumerID:     "pty-mcp",
		SessionID:      "sess-test",
		SessionPubKey:  sessionPub,
		IdentityPubKey: []byte(identPub),
		ExpiresAt:      expiresAt,
	}
	b.Signature = ed25519.Sign(identPriv, credproto.MarshalBundleBytes(b))
	return b
}

func TestVerifyBundle_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := makeBundle(t, pub, priv, time.Now().Add(time.Hour))

	if err := credproto.VerifyBundle(b); err != nil {
		t.Fatalf("expected valid bundle, got: %v", err)
	}
}

func TestVerifyBundle_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := makeBundle(t, pub, priv, time.Now().Add(-time.Second))

	err := credproto.VerifyBundle(b)
	if !errors.Is(err, credproto.ErrBundleExpired) {
		t.Fatalf("expected ErrBundleExpired, got: %v", err)
	}
}

func TestVerifyBundle_BadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := makeBundle(t, pub, priv, time.Now().Add(time.Hour))
	b.Signature[0] ^= 0xff // corrupt

	err := credproto.VerifyBundle(b)
	if !errors.Is(err, credproto.ErrInvalidSig) {
		t.Fatalf("expected ErrInvalidSig, got: %v", err)
	}
}

func TestVerifyBundle_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	b := makeBundle(t, wrongPub, priv, time.Now().Add(time.Hour))

	err := credproto.VerifyBundle(b)
	if !errors.Is(err, credproto.ErrInvalidSig) {
		t.Fatalf("expected ErrInvalidSig, got: %v", err)
	}
}

func TestVerifyBundle_BadIdentityKeySize(t *testing.T) {
	b := &credproto.ConsumerBundle{
		ConsumerID:     "pty-mcp",
		SessionID:      "sess-test",
		SessionPubKey:  make([]byte, 32),
		IdentityPubKey: make([]byte, 10), // wrong size
		ExpiresAt:      time.Now().Add(time.Hour),
		Signature:      make([]byte, 64),
	}

	err := credproto.VerifyBundle(b)
	if !errors.Is(err, credproto.ErrBadKeySize) {
		t.Fatalf("expected ErrBadKeySize, got: %v", err)
	}
}

func TestVerifyBundle_BadSessionKeySize(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b := &credproto.ConsumerBundle{
		ConsumerID:     "pty-mcp",
		SessionID:      "sess-test",
		SessionPubKey:  make([]byte, 10), // wrong size
		IdentityPubKey: []byte(pub),
		ExpiresAt:      time.Now().Add(time.Hour),
		Signature:      make([]byte, 64),
	}

	err := credproto.VerifyBundle(b)
	if !errors.Is(err, credproto.ErrBadKeySize) {
		t.Fatalf("expected ErrBadKeySize, got: %v", err)
	}
}
