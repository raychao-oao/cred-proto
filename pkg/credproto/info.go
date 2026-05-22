package credproto

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const protocolVersion = "ai-pam-v1"
const bundleVersion = "ai-pam-bundle-v1"

// MarshalInfo returns the canonical HPKE info bytes that bind a SealedBox to
// its metadata. Both sealer (cred-mcp) and opener (consumer) must call this
// with identical arguments to produce matching HPKE info — preventing replay.
func MarshalInfo(consumerID, sessionID, itemID, purpose string, bundleExpiresAt, boxExpiresAt time.Time, boxID string) []byte {
	fields := []string{
		protocolVersion,
		consumerID,
		sessionID,
		itemID,
		purpose,
		strconv.FormatInt(bundleExpiresAt.Unix(), 10),
		strconv.FormatInt(boxExpiresAt.Unix(), 10),
		boxID,
	}
	return []byte(strings.Join(fields, "\x00"))
}

// MarshalBundleBytes returns the canonical bytes that the consumer signs when
// producing a ConsumerBundle, and that cred-mcp verifies.
func MarshalBundleBytes(b *ConsumerBundle) []byte {
	fields := []string{
		bundleVersion,
		b.ConsumerID,
		b.SessionID,
		fmt.Sprintf("%x", b.SessionPubKey),
		fmt.Sprintf("%x", b.IdentityPubKey),
		strconv.FormatInt(b.ExpiresAt.Unix(), 10),
	}
	return []byte(strings.Join(fields, "\x00"))
}
