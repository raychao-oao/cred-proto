// Package credproto defines the wire types and canonical encoding for the
// AI-native PAM protocol used between cred-mcp (provider) and consumer MCPs.
//
// The protocol uses HPKE (RFC 9180) with DHKEM(X25519)+HKDF-SHA256+ChaCha20Poly1305.
// AI agents act as untrusted transport — they carry only ciphertext.
package credproto
