package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	rotatingCookieVersion = "v1"
	maxSessionCookieSize  = 4096
)

// GetSessionFromCookie reads and verifies the session cookie
func GetSessionFromCookie(r *http.Request, secret []byte) (*UserSessionData, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	return decode(c, secret)
}

// GetSessionFromCookieWithKeyRing reads a versioned cookie and verifies it
// against the active or a recently retired signing key.
func GetSessionFromCookieWithKeyRing(r *http.Request, keys *RotatingKeyRing) (*UserSessionData, error) {
	u, _, err := getSessionFromCookieWithKeyRing(r, keys)
	return u, err
}

func getSessionFromCookieWithKeyRing(r *http.Request, keys *RotatingKeyRing) (*UserSessionData, bool, error) {
	if keys == nil {
		return nil, false, errors.New("session key ring is nil")
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false, err
	}
	if len(c.Value) > maxSessionCookieSize {
		return nil, false, errors.New("session cookie is too large")
	}

	parts := strings.Split(c.Value, "|")
	if len(parts) == 2 {
		// Accept the pre-rotation format once and refresh it using the current
		// derived key. This keeps deployments backward compatible.
		u, err := decode(c, keys.root)
		return u, err == nil, err
	}
	if len(parts) != 4 || parts[0] != rotatingCookieVersion {
		return nil, false, errors.New("invalid session cookie format")
	}

	keyID, value, sig := parts[1], parts[2], parts[3]
	key, ok := keys.verificationKey(keyID)
	if !ok || !validateHMAC(value, sig, key) {
		return nil, false, errors.New("invalid session signature")
	}
	u, err := decodeSessionValue(value)
	if err != nil {
		return nil, false, err
	}
	return u, !keys.isCurrent(keyID), nil
}

func decode(c *http.Cookie, secret []byte) (*UserSessionData, error) {
	if len(c.Value) > maxSessionCookieSize {
		return nil, errors.New("session cookie is too large")
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 2 {
		return nil, errors.New("invalid session cookie format")
	}
	value, sig := parts[0], parts[1]
	if !validateHMAC(value, sig, secret) {
		return nil, errors.New("invalid session signature")
	}
	return decodeSessionValue(value)
}

func decodeSessionValue(value string) (*UserSessionData, error) {
	jsonData, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		jsonData, err = base64.RawURLEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, fmt.Errorf("decode session cookie: %w", err)
	}
	var u UserSessionData
	if err := json.Unmarshal(jsonData, &u); err != nil {
		return nil, fmt.Errorf("decode session data: %w", err)
	}
	// Check expiration
	if u.ExpiresAt <= 0 || time.Now().Unix() >= u.ExpiresAt {
		return nil, errors.New("session expired")
	}
	return &u, nil
}

//""
