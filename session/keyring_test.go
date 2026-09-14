package session

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewRotatingKeyRingValidation(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	tests := []struct {
		name     string
		secret   []byte
		rotation time.Duration
		grace    time.Duration
		wantErr  error
	}{
		{name: "short root secret", secret: []byte("short"), rotation: time.Hour, grace: time.Hour, wantErr: ErrRootSecretTooShort},
		{name: "zero rotation", secret: root, rotation: 0, grace: time.Hour, wantErr: ErrInvalidRotation},
		{name: "negative grace", secret: root, rotation: time.Hour, grace: -time.Second, wantErr: ErrInvalidGrace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRotatingKeyRing(tt.secret, tt.rotation, tt.grace)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewRotatingKeyRing() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRotatingCookieLifecycle(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	keys, err := NewRotatingKeyRing(root, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Hour).Add(10 * time.Minute)
	keys.now = func() time.Time { return now }

	u := &UserSessionData{UserID: "user-1", SignedIn: true, ExpiresAt: time.Now().Add(24 * time.Hour).Unix()}
	rr := httptest.NewRecorder()
	if err := SetSessionCookieWithKeyRing(rr, u, keys); err != nil {
		t.Fatal(err)
	}
	cookie := rr.Result().Cookies()[0]
	if !cookie.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if !strings.HasPrefix(cookie.Value, rotatingCookieVersion+"|") {
		t.Fatalf("cookie has unexpected format: %q", cookie.Value)
	}

	read := func() error {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(cookie)
		got, err := GetSessionFromCookieWithKeyRing(req, keys)
		if err == nil && got.UserID != u.UserID {
			t.Fatalf("UserID = %q, want %q", got.UserID, u.UserID)
		}
		return err
	}
	if err := read(); err != nil {
		t.Fatalf("current key rejected: %v", err)
	}
	wrongKeys, _ := NewRotatingKeyRing([]byte("abcdef0123456789abcdef0123456789"), time.Hour, 2*time.Hour)
	wrongKeys.now = keys.now
	wrongRequest := httptest.NewRequest("GET", "/", nil)
	wrongRequest.AddCookie(cookie)
	if _, err := GetSessionFromCookieWithKeyRing(wrongRequest, wrongKeys); err == nil {
		t.Fatal("cookie signed with a different root secret was accepted")
	}

	now = now.Truncate(time.Hour).Add(time.Hour + time.Minute)
	if err := read(); err != nil {
		t.Fatalf("retired key rejected during grace period: %v", err)
	}

	now = now.Truncate(time.Hour).Add(3*time.Hour + time.Second)
	if err := read(); err == nil {
		t.Fatal("retired key accepted after grace period")
	}
}

func TestRotatingKeyRingIsDeterministicAndConcurrentSafe(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	first, _ := NewRotatingKeyRing(root, time.Hour, time.Hour)
	second, _ := NewRotatingKeyRing(root, time.Hour, time.Hour)
	now := time.Now().Truncate(time.Hour)
	first.now = func() time.Time { return now }
	second.now = func() time.Time { return now }

	id, key, err := first.currentKey()
	if err != nil {
		t.Fatal(err)
	}
	other, ok := second.verificationKey(id)
	if !ok || !validateHMAC("message", computeHMAC("message", key), other) {
		t.Fatal("instances with the same root secret derived different keys")
	}

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keyID, signingKey, err := first.currentKey()
			if err != nil {
				t.Errorf("currentKey: %v", err)
				return
			}
			verificationKey, ok := first.verificationKey(keyID)
			if !ok || !validateHMAC("message", computeHMAC("message", signingKey), verificationKey) {
				t.Error("concurrent signing or verification failed")
			}
		}()
	}
	wg.Wait()
}

func TestRotatingClientMigratesLegacyCookie(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	keys, _ := NewRotatingKeyRing(root, time.Hour, 2*time.Hour)
	client, err := NewClientWithKeyRing(nil, nil, keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	u := &UserSessionData{UserID: "legacy-user", SignedIn: true, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	legacyResponse := httptest.NewRecorder()
	if err := SetSessionCookie(legacyResponse, u, root); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(legacyResponse.Result().Cookies()[0])
	response := httptest.NewRecorder()
	got, _, err := client.Authenticate(response, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != u.UserID {
		t.Fatalf("UserID = %q, want %q", got.UserID, u.UserID)
	}
	refreshed := response.Result().Cookies()
	if len(refreshed) != 1 || !strings.HasPrefix(refreshed[0].Value, rotatingCookieVersion+"|") {
		t.Fatal("legacy cookie was not refreshed with a rotating key")
	}
}
