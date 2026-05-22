package consumersdk_test

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/raychao-oao/cred-proto/pkg/consumersdk"
	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

func TestLoadOrGenerateIdentityKey_CreatesNew(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	k, err := consumersdk.LoadOrGenerateIdentityKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateIdentityKey: %v", err)
	}
	if len(k.PublicKeyBytes()) != 32 {
		t.Fatalf("expected 32-byte pubkey, got %d", len(k.PublicKeyBytes()))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
}

func TestLoadOrGenerateIdentityKey_LoadsExisting(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	k1, _ := consumersdk.LoadOrGenerateIdentityKey(path)
	k2, err := consumersdk.LoadOrGenerateIdentityKey(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if string(k1.PublicKeyBytes()) != string(k2.PublicKeyBytes()) {
		t.Fatal("loaded key differs from generated key")
	}
}

func TestGenerateSessionKey(t *testing.T) {
	sk, err := consumersdk.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey: %v", err)
	}
	if len(sk.PublicKeyBytes()) != 32 {
		t.Fatalf("expected 32-byte X25519 pubkey, got %d", len(sk.PublicKeyBytes()))
	}
}

func TestNewBundle_PassesVerify(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	ik, _ := consumersdk.LoadOrGenerateIdentityKey(path)
	sk, _ := consumersdk.GenerateSessionKey()

	bundle, err := consumersdk.NewBundle(ik, sk, "pty-mcp", time.Hour)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if err := credproto.VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if bundle.ConsumerID != "pty-mcp" {
		t.Fatalf("ConsumerID mismatch")
	}
}

func TestNewBundle_SessionIDUnique(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	ik, _ := consumersdk.LoadOrGenerateIdentityKey(path)
	sk1, _ := consumersdk.GenerateSessionKey()
	sk2, _ := consumersdk.GenerateSessionKey()

	b1, _ := consumersdk.NewBundle(ik, sk1, "pty-mcp", time.Hour)
	b2, _ := consumersdk.NewBundle(ik, sk2, "pty-mcp", time.Hour)
	if b1.SessionID == b2.SessionID {
		t.Fatal("session IDs should be unique per bundle")
	}
}

// sealForTest creates a SealedBox using raw HPKE, mirroring what cred-mcp/internal/seal does.
// It only needs the bundle's SessionPubKey — no access to the private key required.
func sealForTest(t *testing.T, bundle *credproto.ConsumerBundle, itemID, purpose, boxID string, boxExp time.Time, plaintext []byte) *credproto.SealedBox {
	t.Helper()
	info := credproto.MarshalInfo(bundle.ConsumerID, bundle.SessionID, itemID, purpose, bundle.ExpiresAt, boxExp, boxID)
	ecdhPub, err := ecdh.X25519().NewPublicKey(bundle.SessionPubKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	pub, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		t.Fatalf("NewDHKEMPublicKey: %v", err)
	}
	encappedKey, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return &credproto.SealedBox{
		BoxID: boxID, ConsumerID: bundle.ConsumerID, SessionID: bundle.SessionID,
		ItemID: itemID, Purpose: purpose, EncappedKey: encappedKey, Ciphertext: ct, ExpiresAt: boxExp,
	}
}

func TestOpen_RoundTrip(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	ik, _ := consumersdk.LoadOrGenerateIdentityKey(path)
	sk, _ := consumersdk.GenerateSessionKey()
	bundle, _ := consumersdk.NewBundle(ik, sk, "pty-mcp", time.Hour)

	boxExp := time.Now().Add(5 * time.Minute).UTC()
	want := []byte("s3cr3t-p4ssword")
	box := sealForTest(t, bundle, "item-42", "ssh-login", "box-abc", boxExp, want)

	got, err := consumersdk.Open(box, sk, bundle)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, want)
	}
}

func TestOpen_ExpiredBox(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	ik, _ := consumersdk.LoadOrGenerateIdentityKey(path)
	sk, _ := consumersdk.GenerateSessionKey()
	bundle, _ := consumersdk.NewBundle(ik, sk, "pty-mcp", time.Hour)

	boxExp := time.Now().Add(-time.Second).UTC() // already expired
	box := sealForTest(t, bundle, "item-42", "ssh-login", "box-abc", boxExp, []byte("s3cr3t"))
	box.ExpiresAt = boxExp

	_, err := consumersdk.Open(box, sk, bundle)
	if err == nil {
		t.Fatal("expected error for expired box")
	}
}

func TestBundle_JSONRoundTrip(t *testing.T) {
	path := t.TempDir() + "/identity.key"
	ik, _ := consumersdk.LoadOrGenerateIdentityKey(path)
	sk, _ := consumersdk.GenerateSessionKey()
	bundle, _ := consumersdk.NewBundle(ik, sk, "pty-mcp", time.Hour)

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var b2 credproto.ConsumerBundle
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := credproto.VerifyBundle(&b2); err != nil {
		t.Fatalf("VerifyBundle after JSON round-trip: %v", err)
	}
}

// ensure rand is imported
var _ = rand.Reader
