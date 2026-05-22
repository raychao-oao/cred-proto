package credproto_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

func TestMarshalInfo_Deterministic(t *testing.T) {
	bundleExp := time.Unix(1748000000, 0).UTC()
	boxExp := time.Unix(1748001000, 0).UTC()

	a := credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "ssh-login", bundleExp, boxExp, "box-xyz")
	b := credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "ssh-login", bundleExp, boxExp, "box-xyz")

	if !bytes.Equal(a, b) {
		t.Fatal("MarshalInfo not deterministic")
	}
}

func TestMarshalInfo_DistinguishesByField(t *testing.T) {
	bundleExp := time.Unix(1748000000, 0).UTC()
	boxExp := time.Unix(1748001000, 0).UTC()

	base := credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "ssh-login", bundleExp, boxExp, "box-xyz")

	cases := [][]byte{
		credproto.MarshalInfo("OTHER", "sess-1", "item-42", "ssh-login", bundleExp, boxExp, "box-xyz"),
		credproto.MarshalInfo("pty-mcp", "OTHER", "item-42", "ssh-login", bundleExp, boxExp, "box-xyz"),
		credproto.MarshalInfo("pty-mcp", "sess-1", "OTHER", "ssh-login", bundleExp, boxExp, "box-xyz"),
		credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "OTHER", bundleExp, boxExp, "box-xyz"),
		credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "ssh-login", bundleExp.Add(time.Second), boxExp, "box-xyz"),
		credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "ssh-login", bundleExp, boxExp.Add(time.Second), "box-xyz"),
		credproto.MarshalInfo("pty-mcp", "sess-1", "item-42", "ssh-login", bundleExp, boxExp, "OTHER"),
	}

	for i, c := range cases {
		if bytes.Equal(base, c) {
			t.Errorf("case %d: changing field did not change info bytes", i)
		}
	}
}

func TestMarshalBundleBytes_Deterministic(t *testing.T) {
	b := &credproto.ConsumerBundle{
		ConsumerID:     "pty-mcp",
		SessionID:      "sess-1",
		SessionPubKey:  make([]byte, 32),
		IdentityPubKey: make([]byte, 32),
		ExpiresAt:      time.Unix(1748000000, 0).UTC(),
	}

	x := credproto.MarshalBundleBytes(b)
	y := credproto.MarshalBundleBytes(b)

	if !bytes.Equal(x, y) {
		t.Fatal("MarshalBundleBytes not deterministic")
	}
}

func TestMarshalBundleBytes_DistinguishesByField(t *testing.T) {
	base := &credproto.ConsumerBundle{
		ConsumerID:     "pty-mcp",
		SessionID:      "sess-1",
		SessionPubKey:  make([]byte, 32),
		IdentityPubKey: make([]byte, 32),
		ExpiresAt:      time.Unix(1748000000, 0).UTC(),
	}
	baseBytes := credproto.MarshalBundleBytes(base)

	altSessionKey := make([]byte, 32)
	altSessionKey[0] = 1
	altIdentityKey := make([]byte, 32)
	altIdentityKey[0] = 1

	cases := []*credproto.ConsumerBundle{
		{ConsumerID: "OTHER", SessionID: "sess-1", SessionPubKey: make([]byte, 32), IdentityPubKey: make([]byte, 32), ExpiresAt: base.ExpiresAt},
		{ConsumerID: "pty-mcp", SessionID: "OTHER", SessionPubKey: make([]byte, 32), IdentityPubKey: make([]byte, 32), ExpiresAt: base.ExpiresAt},
		{ConsumerID: "pty-mcp", SessionID: "sess-1", SessionPubKey: altSessionKey, IdentityPubKey: make([]byte, 32), ExpiresAt: base.ExpiresAt},
		{ConsumerID: "pty-mcp", SessionID: "sess-1", SessionPubKey: make([]byte, 32), IdentityPubKey: altIdentityKey, ExpiresAt: base.ExpiresAt},
		{ConsumerID: "pty-mcp", SessionID: "sess-1", SessionPubKey: make([]byte, 32), IdentityPubKey: make([]byte, 32), ExpiresAt: base.ExpiresAt.Add(time.Second)},
	}

	for i, c := range cases {
		if bytes.Equal(baseBytes, credproto.MarshalBundleBytes(c)) {
			t.Errorf("case %d: changing field did not change bundle bytes", i)
		}
	}
}
