package credproto

import "time"

// ConsumerBundle is the signed payload that a consumer MCP sends to cred-mcp.
// It proves the consumer's identity and provides the ephemeral session public key
// that cred-mcp will HPKE-encrypt against.
//
// The Signature field covers all other fields via MarshalBundleBytes.
type ConsumerBundle struct {
	ConsumerID     string    `json:"consumer_id"`
	SessionID      string    `json:"session_id"`
	SessionPubKey  []byte    `json:"session_pub_key"`  // X25519, 32 bytes
	IdentityPubKey []byte    `json:"identity_pub_key"` // Ed25519, 32 bytes
	ExpiresAt      time.Time `json:"expires_at"`
	Signature      []byte    `json:"sig"` // Ed25519 over MarshalBundleBytes
}

// SealedBox is the HPKE-encrypted result from cred-mcp.vault_seal.
// AI agents carry this as opaque ciphertext — they cannot decrypt it.
// The consumer MCP calls consumersdk.Open to recover the plaintext.
type SealedBox struct {
	BoxID       string    `json:"box_id"`
	ConsumerID  string    `json:"consumer_id"`
	SessionID   string    `json:"session_id"`
	ItemID      string    `json:"item_id"`
	Purpose     string    `json:"purpose"`
	EncappedKey []byte    `json:"encapped_key"` // HPKE encapsulated key
	Ciphertext  []byte    `json:"ciphertext"`   // HPKE ciphertext (includes AEAD tag)
	ExpiresAt   time.Time `json:"expires_at"`
}
