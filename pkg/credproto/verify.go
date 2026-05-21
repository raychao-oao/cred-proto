package credproto

import (
	"crypto/ed25519"
	"errors"
	"time"
)

var (
	ErrBundleExpired = errors.New("credproto: bundle has expired")
	ErrInvalidSig    = errors.New("credproto: bundle signature invalid")
	ErrBadKeySize    = errors.New("credproto: key has wrong size")
)

// VerifyBundle checks the Ed25519 signature on a ConsumerBundle and that it
// has not expired. It does NOT verify registry membership or ACLs — that is
// cred-mcp's responsibility.
func VerifyBundle(b *ConsumerBundle) error {
	if len(b.IdentityPubKey) != ed25519.PublicKeySize {
		return ErrBadKeySize
	}
	if len(b.SessionPubKey) != 32 { // X25519
		return ErrBadKeySize
	}
	if time.Now().After(b.ExpiresAt) {
		return ErrBundleExpired
	}
	if !ed25519.Verify(b.IdentityPubKey, MarshalBundleBytes(b), b.Signature) {
		return ErrInvalidSig
	}
	return nil
}
