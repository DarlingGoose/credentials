package user

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DarlingGoose/credentials/session"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type memoryUserStore struct {
	byID       map[string]*User
	byUsername map[string]*User
}

func newMemoryUserStore(users ...*User) *memoryUserStore {
	store := &memoryUserStore{byID: make(map[string]*User), byUsername: make(map[string]*User)}
	for _, current := range users {
		store.byID[current.ID] = current
		store.byUsername[current.Username] = current
	}
	return store
}

func (s *memoryUserStore) GetUserByID(_ context.Context, id string) (*User, error) {
	if current, ok := s.byID[id]; ok {
		return current, nil
	}
	return nil, errors.New("user not found")
}

func (s *memoryUserStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	if current, ok := s.byUsername[username]; ok {
		return current, nil
	}
	return nil, errors.New("user not found")
}

func (s *memoryUserStore) CreateUser(_ context.Context, current *User) error {
	s.byID[current.ID] = current
	s.byUsername[current.Username] = current
	return nil
}

func (s *memoryUserStore) UpdateUser(_ context.Context, current *User) error {
	s.byID[current.ID] = current
	s.byUsername[current.Username] = current
	return nil
}

func (s *memoryUserStore) DeleteUser(_ context.Context, id string) error {
	delete(s.byID, id)
	return nil
}

func (*memoryUserStore) AddPasskey(context.Context, string, webauthn.Credential) error {
	return nil
}

func (*memoryUserStore) GetPasskeysByUserID(context.Context, string) ([]webauthn.Credential, error) {
	return nil, nil
}

func (*memoryUserStore) GetPasskeyByCredentialID(context.Context, []byte) (*webauthn.Credential, *User, error) {
	return nil, nil, errors.New("credential not found")
}

func (*memoryUserStore) UpdatePasskey(context.Context, string, webauthn.Credential) error {
	return nil
}

func (*memoryUserStore) DeletePasskey(context.Context, string, []byte) error { return nil }

func TestUnitValidateCredentials(t *testing.T) {
	validUsernames := []string{"Alice_1", "ab3"}
	for _, username := range validUsernames {
		if err := ValidateUsername(username); err != nil {
			t.Errorf("ValidateUsername(%q): %v", username, err)
		}
	}
	invalidUsernames := []string{"", "a", "ab", "1alice", "alice-name", strings.Repeat("a", 21)}
	for _, username := range invalidUsernames {
		if err := ValidateUsername(username); err == nil {
			t.Errorf("ValidateUsername(%q) unexpectedly succeeded", username)
		}
	}

	validPasswords := []string{"Valid123!", "Correct-Horse7"}
	for _, password := range validPasswords {
		if err := ValidatePassword(password); err != nil {
			t.Errorf("ValidatePassword(%q): %v", password, err)
		}
	}
	invalidPasswords := []string{
		"Short1!",
		"NOLOWERCASE1!",
		"nouppercase1!",
		"NoDigits!",
		"NoSpecial123",
		strings.Repeat("Aa1!", 17),
	}
	for _, password := range invalidPasswords {
		if err := ValidatePassword(password); err == nil {
			t.Errorf("ValidatePassword(%q) unexpectedly succeeded", password)
		}
	}

	if err := ValidateCredentials("bad-name", "Valid123!"); err == nil {
		t.Fatal("ValidateCredentials accepted an invalid username")
	}
	if err := ValidateCredentials("Alice_1", "password"); err == nil {
		t.Fatal("ValidateCredentials accepted an invalid password")
	}
	if err := ValidateCredentials("Alice_1", "Valid123!"); err != nil {
		t.Fatalf("ValidateCredentials rejected valid credentials: %v", err)
	}
}

func TestUnitLoginPasswordHandler(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("Valid123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	current := &User{ID: "user-1", Username: "alice", PasswordHash: hash, Roles: []string{"user"}}
	secret := []byte("test-session-secret")

	t.Run("malformed request", func(t *testing.T) {
		server := testServer(newMemoryUserStore(current), secret)
		rr := serveJSON(server.LoginPasswordHandler, `{`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		server := testServer(newMemoryUserStore(), secret)
		rr := serveJSON(server.LoginPasswordHandler, `{"username":"nobody","password":"Valid123!"}`)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		server := testServer(newMemoryUserStore(current), secret)
		rr := serveJSON(server.LoginPasswordHandler, `{"username":"alice","password":"Wrong123!"}`)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("successful login", func(t *testing.T) {
		server := testServer(newMemoryUserStore(current), secret)
		rr := serveJSON(server.LoginPasswordHandler, `{"username":"alice","password":"Valid123!"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		cookies := rr.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure {
			t.Fatalf("unexpected session cookies: %#v", cookies)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(cookies[0])
		got, err := session.GetSessionFromCookie(req, secret)
		if err != nil || got.UserID != current.ID || !got.SignedIn {
			t.Fatalf("session = %#v, error = %v", got, err)
		}
	})
}

func TestUnitPasswordAndTOTPLogin(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "example.com", AccountName: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("Valid123!"), bcrypt.MinCost)
	current := &User{
		ID:           "user-2",
		Username:     "alice",
		PasswordHash: hash,
		Roles:        []string{"user"},
		TOTPEnabled:  true,
		TOTPSecret:   key.Secret(),
	}
	secret := []byte("test-session-secret")
	server := testServer(newMemoryUserStore(current), secret)

	start := serveJSON(server.LoginPasswordHandler, `{"username":"alice","password":"Valid123!"}`)
	if start.Code != http.StatusAccepted {
		t.Fatalf("password status = %d, body = %s", start.Code, start.Body.String())
	}
	var challenge map[string]string
	if err := json.Unmarshal(start.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	sessionID := challenge["sessionId"]
	if sessionID == "" || server.getTopChallenge(sessionID) == nil {
		t.Fatal("TOTP challenge was not stored")
	}

	bad := serveJSON(server.LoginTOTPHandler, `{"sessionId":"missing","totpCode":"000000"}`)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("invalid challenge status = %d", bad.Code)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"sessionId": sessionID, "totpCode": code})
	finish := serveJSON(server.LoginTOTPHandler, string(body))
	if finish.Code != http.StatusOK || len(finish.Result().Cookies()) != 1 {
		t.Fatalf("TOTP status = %d, body = %s", finish.Code, finish.Body.String())
	}
	if server.getTopChallenge(sessionID) != nil {
		t.Fatal("used TOTP challenge was not removed")
	}
}

func TestUnitAuthMiddleware(t *testing.T) {
	current := &User{ID: "user-1", Username: "alice"}
	store := newMemoryUserStore(current)
	secret := []byte("test-session-secret")
	server := testServer(store, secret)

	t.Run("anonymous request continues without user", func(t *testing.T) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if _, err := GetUserFromContext(r.Context()); err == nil {
				t.Error("anonymous request had a user")
			}
			w.WriteHeader(http.StatusNoContent)
		})
		rr := httptest.NewRecorder()
		server.AuthMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
		if !called || rr.Code != http.StatusNoContent {
			t.Fatalf("called = %t, status = %d", called, rr.Code)
		}
	})

	t.Run("valid session attaches user", func(t *testing.T) {
		cookie := staticSessionCookie(t, secret, current.ID)
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, err := GetUserFromContext(r.Context())
			if err != nil || got.ID != current.ID {
				t.Errorf("context user = %#v, %v", got, err)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		server.AuthMiddleware(next).ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("deleted user clears cookie", func(t *testing.T) {
		cookie := staticSessionCookie(t, secret, "deleted-user")
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		server.AuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)
		cookies := rr.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Value != "" {
			t.Fatalf("session cookie was not cleared: %#v", cookies)
		}
	})

	t.Run("rotating session is refreshed", func(t *testing.T) {
		root := []byte("0123456789abcdef0123456789abcdef")
		keys, _ := session.NewRotatingKeyRing(root, time.Hour, defaultSessionTTL)
		rotatingServer := testServer(store, nil)
		rotatingServer.SessionKeys = keys
		rrCookie := httptest.NewRecorder()
		if err := session.SetSessionCookieWithKeyRing(rrCookie, &session.UserSessionData{
			UserID: current.ID, SignedIn: true, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}, keys); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(rrCookie.Result().Cookies()[0])
		rr := httptest.NewRecorder()
		rotatingServer.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rr, req)
		if len(rr.Result().Cookies()) != 1 {
			t.Fatal("rotating session was not refreshed")
		}
	})
}

func TestUnitRotatingServerConstructorValidation(t *testing.T) {
	if _, err := NewServerWithKeyRing(nil, nil, nil, "example.com", "Example", "https://example.com"); err == nil {
		t.Fatal("nil key ring was accepted")
	}
	root := []byte("0123456789abcdef0123456789abcdef")
	shortGrace, _ := session.NewRotatingKeyRing(root, time.Hour, time.Hour)
	if _, err := NewServerWithKeyRing(nil, nil, shortGrace, "example.com", "Example", "https://example.com"); err == nil {
		t.Fatal("short verification grace period was accepted")
	}
	if _, err := NewAutoRotatingServer(nil, nil, []byte("short"), time.Hour, "example.com", "Example", "https://example.com"); err == nil {
		t.Fatal("short root secret was accepted")
	}
}

func TestUnitUserAndCredentialConversion(t *testing.T) {
	flags := protocol.FlagUserPresent | protocol.FlagUserVerified
	original := webauthn.Credential{
		ID:              []byte("credential-id"),
		PublicKey:       []byte("public-key"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid},
		Flags:           webauthn.NewCredentialFlags(flags),
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("0123456789abcdef"),
			SignCount: 42,
		},
	}
	stored := FromWebAuthnCredential(original)
	restored := stored.ToWebAuthnCredential()
	if string(restored.ID) != string(original.ID) || string(restored.PublicKey) != string(original.PublicKey) {
		t.Fatalf("credential bytes did not round trip: %#v", restored)
	}
	if restored.Authenticator.SignCount != original.Authenticator.SignCount || restored.Flags.ProtocolValue() != flags {
		t.Fatalf("credential metadata did not round trip: %#v", restored)
	}
	if len(restored.Transport) != 2 || restored.Transport[1] != protocol.Hybrid {
		t.Fatalf("credential transports did not round trip: %#v", restored.Transport)
	}

	current := &User{ID: "id-1", Username: "alice", Passkeys: []WebAuthnCredential{stored}}
	if string(current.WebAuthnID()) != current.ID || current.WebAuthnName() != current.Username || current.WebAuthnDisplayName() != current.Username || current.UserID() != current.ID {
		t.Fatal("user WebAuthn identity methods returned inconsistent values")
	}
	if credentials := current.WebAuthnCredentials(); len(credentials) != 1 || string(credentials[0].ID) != string(original.ID) {
		t.Fatalf("WebAuthnCredentials() = %#v", credentials)
	}
}

func TestUnitAccountManagementHandlers(t *testing.T) {
	current := &User{ID: "user-1", Username: "alice", Roles: []string{"user"}}
	store := newMemoryUserStore(current)
	server := testServer(store, []byte("test-session-secret"))

	t.Run("logout", func(t *testing.T) {
		rr := serveJSON(server.LogoutHandler, `{}`)
		if rr.Code != http.StatusOK || len(rr.Result().Cookies()) != 1 || rr.Result().Cookies()[0].Value != "" {
			t.Fatalf("status = %d, cookies = %#v", rr.Code, rr.Result().Cookies())
		}
	})

	t.Run("get user requires authentication", func(t *testing.T) {
		rr := httptest.NewRecorder()
		server.GetUser(rr, httptest.NewRequest(http.MethodGet, "/user", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("get authenticated user", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/user", nil)
		req = req.WithContext(context.WithValue(req.Context(), userCtxKey, current))
		rr := httptest.NewRecorder()
		server.GetUser(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"username":"alice"`) {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("manage roles validates input", func(t *testing.T) {
		for _, body := range []string{`{`, `{"userId":"user-1"}`, `{"roles":["admin"]}`} {
			rr := serveJSON(server.ManageUserHandler, body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("body %q: status = %d", body, rr.Code)
			}
		}
	})

	t.Run("manage roles updates user", func(t *testing.T) {
		rr := serveJSON(server.ManageUserHandler, `{"userId":"user-1","roles":["admin"]}`)
		if rr.Code != http.StatusOK || len(current.Roles) != 1 || current.Roles[0] != "admin" {
			t.Fatalf("status = %d, roles = %#v", rr.Code, current.Roles)
		}
	})

	t.Run("delete validates input", func(t *testing.T) {
		for _, body := range []string{`{`, `{}`} {
			rr := serveJSON(server.DeleteUserHandler, body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("body %q: status = %d", body, rr.Code)
			}
		}
	})

	t.Run("delete user", func(t *testing.T) {
		rr := serveJSON(server.DeleteUserHandler, `{"userId":"user-1"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		if _, err := store.GetUserByID(context.Background(), current.ID); err == nil {
			t.Fatal("user still exists after deletion")
		}
	})
}

func testServer(store Store, secret []byte) *Server {
	return &Server{
		Store:              store,
		SessionSecret:      secret,
		totpChallengeStore: make(map[string]totpChallengeData),
		challengeStore:     make(map[string]*webauthn.SessionData),
	}
}

func serveJSON(handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func staticSessionCookie(t *testing.T, secret []byte, userID string) *http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	if err := session.SetSessionCookie(rr, &session.UserSessionData{
		UserID: userID, SignedIn: true, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, secret); err != nil {
		t.Fatal(err)
	}
	return rr.Result().Cookies()[0]
}
