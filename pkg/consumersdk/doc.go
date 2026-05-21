// Package consumersdk provides the consumer-side SDK for the AI-native PAM protocol.
//
// Consumer MCPs (pty-mcp, imap-mcp, ad-mcp, etc.) import this package to:
//   - Manage identity keys (Ed25519, persistent) and session keys (X25519, ephemeral)
//   - Generate signed ConsumerBundles for cred-mcp to seal against
//   - Open SealedBoxes and inject secrets via SecretSink
//
// The SDK never touches plaintext outside of InjectSecret, and zeroizes immediately after use.
package consumersdk
