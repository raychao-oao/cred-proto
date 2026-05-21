package consumersdk

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

// fileHeader is a magic prefix stored at the start of an identity key file.
// It prevents accidentally loading an unrelated binary file as a key.
var fileHeader = []byte("CRED-PROTO-ID\x01")

// IdentityKey is a persistent Ed25519 keypair that proves a consumer's identity
// to cred-mcp. It is loaded from or saved to a file on disk.
type IdentityKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// LoadOrGenerateIdentityKey loads the Ed25519 identity key from path, or
// generates a new one and saves it if the file does not exist.
func LoadOrGenerateIdentityKey(path string) (*IdentityKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err == nil {
		return parseIdentityKeyFile(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("consumersdk: read identity key %s: %w", path, err)
	}
	return generateAndSaveIdentityKey(path)
}

func parseIdentityKeyFile(data []byte) (*IdentityKey, error) {
	hlen := len(fileHeader)
	if len(data) < hlen+ed25519.SeedSize || string(data[:hlen]) != string(fileHeader) {
		return nil, errors.New("consumersdk: identity key file has wrong format or header")
	}
	seed := data[hlen : hlen+ed25519.SeedSize]
	priv := ed25519.NewKeyFromSeed(seed)
	return &IdentityKey{pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
}

func generateAndSaveIdentityKey(path string) (*IdentityKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("consumersdk: generate identity key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("consumersdk: create key dir: %w", err)
	}
	data := append(append([]byte{}, fileHeader...), priv.Seed()...)
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return nil, fmt.Errorf("consumersdk: save identity key %s: %w", path, err)
	}
	return &IdentityKey{pub: pub, priv: priv}, nil
}

// PublicKeyBytes returns the raw 32-byte Ed25519 public key.
func (k *IdentityKey) PublicKeyBytes() []byte { return []byte(k.pub) }

// SessionKey is an ephemeral X25519 keypair for a single credential delivery.
// Generate one per bundle; discard after Open().
type SessionKey struct {
	priv *ecdh.PrivateKey
}

// GenerateSessionKey creates a new ephemeral X25519 session keypair.
func GenerateSessionKey() (*SessionKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("consumersdk: generate session key: %w", err)
	}
	return &SessionKey{priv: priv}, nil
}

// PublicKeyBytes returns the raw 32-byte X25519 public key.
func (k *SessionKey) PublicKeyBytes() []byte { return k.priv.PublicKey().Bytes() }

// NewBundle creates a signed ConsumerBundle valid for ttl. The bundle embeds
// the session public key so cred-mcp can HPKE-encrypt against it.
func NewBundle(identityKey *IdentityKey, sessionKey *SessionKey, consumerID string, ttl time.Duration) (*credproto.ConsumerBundle, error) {
	sessionID, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	b := &credproto.ConsumerBundle{
		ConsumerID:     consumerID,
		SessionID:      sessionID,
		SessionPubKey:  sessionKey.PublicKeyBytes(),
		IdentityPubKey: identityKey.PublicKeyBytes(),
		ExpiresAt:      time.Now().Add(ttl).UTC(),
	}
	b.Signature = ed25519.Sign(identityKey.priv, credproto.MarshalBundleBytes(b))
	return b, nil
}

// ErrBoxExpired is returned by Open when the SealedBox has passed its ExpiresAt.
var ErrBoxExpired = errors.New("consumersdk: sealed box has expired")

// Open decrypts a SealedBox using the consumer's session private key.
// The bundle is required to reconstruct the canonical HPKE info parameter.
// The returned plaintext slice should be zeroized by the caller after use.
func Open(box *credproto.SealedBox, sessionKey *SessionKey, bundle *credproto.ConsumerBundle) ([]byte, error) {
	if time.Now().After(box.ExpiresAt) {
		return nil, ErrBoxExpired
	}
	info := credproto.MarshalInfo(
		bundle.ConsumerID, bundle.SessionID,
		box.ItemID, box.Purpose,
		bundle.ExpiresAt, box.ExpiresAt, box.BoxID,
	)
	hpkePriv, err := hpke.NewDHKEMPrivateKey(sessionKey.priv)
	if err != nil {
		return nil, fmt.Errorf("consumersdk: wrap private key: %w", err)
	}
	recipient, err := hpke.NewRecipient(box.EncappedKey, hpkePriv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, fmt.Errorf("consumersdk: create recipient: %w", err)
	}
	plaintext, err := recipient.Open(nil, box.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("consumersdk: open: %w", err)
	}
	return plaintext, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
