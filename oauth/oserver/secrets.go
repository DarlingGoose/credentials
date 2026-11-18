package oserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const opaqueTokenBytes = 32

func newOpaqueToken() (string, error) {
	raw := make([]byte, opaqueTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashOpaqueToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
