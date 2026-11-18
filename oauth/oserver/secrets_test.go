package oserver

import (
	"encoding/base64"
	"testing"
)

func TestOpaqueTokensAreRandomAndStoredByDigest(t *testing.T) {
	first, err := newOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two generated bearer credentials were identical")
	}
	raw, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil || len(raw) != opaqueTokenBytes {
		t.Fatalf("generated credential has %d decoded bytes, err=%v", len(raw), err)
	}
	if hashOpaqueToken(first) == first || hashOpaqueToken(first) == hashOpaqueToken(second) {
		t.Fatal("token digest does not separate plaintext credentials")
	}
}
