package session

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DarlingGoose/credentials/oauth/oserver"
)

func TestRotatingClientConstructorValidation(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	shortGrace, err := NewRotatingKeyRing(root, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		keys *RotatingKeyRing
		ttl  time.Duration
	}{
		{name: "nil key ring", keys: nil, ttl: time.Hour},
		{name: "zero TTL", keys: shortGrace, ttl: 0},
		{name: "negative TTL", keys: shortGrace, ttl: -time.Second},
		{name: "grace shorter than TTL", keys: shortGrace, ttl: time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClientWithKeyRing(nil, nil, tt.keys, tt.ttl); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}

	if _, err := NewAutoRotatingClient(nil, nil, []byte("short"), time.Hour, time.Minute); err == nil {
		t.Fatal("NewAutoRotatingClient accepted a short root secret")
	}
	client, err := NewAutoRotatingClient(nil, nil, root, time.Hour, time.Minute)
	if err != nil || client == nil {
		t.Fatalf("NewAutoRotatingClient() = %v, %v", client, err)
	}
	if client.keys.RotationInterval() != time.Minute {
		t.Fatalf("rotation interval = %v, want %v", client.keys.RotationInterval(), time.Minute)
	}
}

func TestRotatingCookieRejectsInvalidInput(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	keys, _ := NewRotatingKeyRing(root, time.Hour, time.Hour)
	now := time.Now().Truncate(time.Hour).Add(time.Minute)
	keys.now = func() time.Time { return now }
	keyID, key, err := keys.currentKey()
	if err != nil {
		t.Fatal(err)
	}

	signedCookie := func(value string) *http.Cookie {
		return &http.Cookie{
			Name:  sessionCookieName,
			Value: strings.Join([]string{rotatingCookieVersion, keyID, value, computeHMAC(value, key)}, "|"),
		}
	}
	validJSON := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"u","signed_in":true,"expires_at":4102444800}`))

	tests := []struct {
		name   string
		cookie *http.Cookie
		keys   *RotatingKeyRing
	}{
		{name: "nil key ring", cookie: signedCookie(validJSON), keys: nil},
		{name: "oversized", cookie: &http.Cookie{Name: sessionCookieName, Value: strings.Repeat("x", maxSessionCookieSize+1)}, keys: keys},
		{name: "wrong part count", cookie: &http.Cookie{Name: sessionCookieName, Value: "v1|key|value"}, keys: keys},
		{name: "unknown version", cookie: &http.Cookie{Name: sessionCookieName, Value: "v2|key|value|sig"}, keys: keys},
		{name: "invalid key id", cookie: &http.Cookie{Name: sessionCookieName, Value: "v1|not-a-key|value|sig"}, keys: keys},
		{name: "invalid signature", cookie: &http.Cookie{Name: sessionCookieName, Value: strings.Join([]string{rotatingCookieVersion, keyID, validJSON, "bad"}, "|")}, keys: keys},
		{name: "invalid base64", cookie: signedCookie("%%%"), keys: keys},
		{name: "invalid JSON", cookie: signedCookie(base64.RawURLEncoding.EncodeToString([]byte("not-json"))), keys: keys},
		{name: "missing expiration", cookie: signedCookie(base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"u"}`))), keys: keys},
		{name: "expired", cookie: signedCookie(base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"u","expires_at":1}`))), keys: keys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(tt.cookie)
			if _, err := GetSessionFromCookieWithKeyRing(req, tt.keys); err == nil {
				t.Fatal("invalid cookie was accepted")
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := GetSessionFromCookieWithKeyRing(req, keys); err == nil {
		t.Fatal("missing cookie was accepted")
	}
}

func TestSetAndClearCookieValidation(t *testing.T) {
	root := []byte("0123456789abcdef0123456789abcdef")
	keys, _ := NewRotatingKeyRing(root, time.Hour, time.Hour)

	if err := SetSessionCookieWithKeyRing(httptest.NewRecorder(), nil, keys); err == nil {
		t.Fatal("nil session data was accepted")
	}
	if err := SetSessionCookieWithKeyRing(httptest.NewRecorder(), &UserSessionData{ExpiresAt: time.Now().Add(time.Hour).Unix()}, nil); err == nil {
		t.Fatal("nil key ring was accepted")
	}
	if err := SetSessionCookie(httptest.NewRecorder(), &UserSessionData{ExpiresAt: time.Now().Unix()}, root); err == nil {
		t.Fatal("expired session was accepted")
	}
	large := &UserSessionData{
		UserID:    strings.Repeat("x", maxSessionCookieSize),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := SetSessionCookie(httptest.NewRecorder(), large, root); err == nil {
		t.Fatal("oversized session was accepted")
	}

	rr := httptest.NewRecorder()
	ClearSessionCookie(rr)
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("unexpected clearing cookie: %#v", cookies)
	}
}

func TestAuthenticateActiveBearerToken(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	oauth := &oserver.MockOServer{
		IntrospectFunc: func(_ context.Context, req oserver.IntrospectRequest) (*oserver.IntrospectResponse, error) {
			if req.Token != "access-token" {
				t.Fatalf("token = %q", req.Token)
			}
			return &oserver.IntrospectResponse{Active: true, UserID: "service-example", AccountID: "account-1", Exp: expires}, nil
		},
	}
	client := NewClient(oauth, nil, []byte("static-secret"), time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	rr := httptest.NewRecorder()

	got, ctx, err := client.Authenticate(rr, req)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SignedIn || !got.ServiceAccount || got.AccountID != "account-1" {
		t.Fatalf("unexpected session: %#v", got)
	}
	fromContext, err := GetSession(ctx)
	if err != nil || fromContext.UserID != got.UserID {
		t.Fatalf("context session = %#v, %v", fromContext, err)
	}
	if len(rr.Result().Cookies()) != 1 {
		t.Fatal("authenticated session cookie was not set")
	}
}
