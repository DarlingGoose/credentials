package providerlogin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type memoryStore struct {
	mu         sync.Mutex
	attempts   map[string]LoginAttempt
	identities map[string]ExternalIdentity
}

func newMemoryStore() *memoryStore {
	return &memoryStore{attempts: make(map[string]LoginAttempt), identities: make(map[string]ExternalIdentity)}
}

func (s *memoryStore) CreateAttempt(_ context.Context, attempt LoginAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[base64.RawURLEncoding.EncodeToString(attempt.StateHash)] = attempt
	return nil
}

func (s *memoryStore) ConsumeAttempt(_ context.Context, hash []byte, now time.Time) (*LoginAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := base64.RawURLEncoding.EncodeToString(hash)
	attempt, ok := s.attempts[key]
	delete(s.attempts, key)
	if !ok || !attempt.ExpiresAt.After(now) {
		return nil, ErrInvalidState
	}
	return &attempt, nil
}

func identityKey(issuer, subject string) string { return issuer + "\x00" + subject }

func (s *memoryStore) GetIdentity(_ context.Context, issuer, subject string) (*ExternalIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.identities[identityKey(issuer, subject)]
	if !ok {
		return nil, nil
	}
	return &identity, nil
}

func (s *memoryStore) LinkIdentity(_ context.Context, identity ExternalIdentity) (*ExternalIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identityKey(identity.Issuer, identity.Subject)
	if existing, ok := s.identities[key]; ok && existing.UserID != identity.UserID {
		return nil, ErrIdentityCollision
	}
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now()
	}
	identity.UpdatedAt = time.Now()
	s.identities[key] = identity
	copy := identity
	return &copy, nil
}

type testProvider struct {
	issuer        string
	client        *http.Client
	privateKey    *rsa.PrivateKey
	nonce         string
	wantVerifier  string
	emailVerified bool
	audience      string
	issuerClaim   string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testProvider{issuer: "http://issuer.test", privateKey: privateKey, emailVerified: true, audience: "client"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": p.issuer, "authorization_endpoint": p.issuer + "/authorize",
			"token_endpoint": p.issuer + "/token", "jwks_uri": p.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "test-key", "kty": "RSA", "alg": "RS256", "n": n, "e": "AQAB",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("code_verifier") != p.wantVerifier {
			t.Errorf("code_verifier = %q, want stored verifier", r.Form.Get("code_verifier"))
		}
		issuer := p.issuerClaim
		if issuer == "" {
			issuer = p.issuer
		}
		claims := idTokenClaims{
			Email: "Person@Example.COM", EmailVerified: p.emailVerified, Nonce: p.nonce,
			TenantID: "tenant-1", Name: "Person",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: issuer, Subject: "subject-1", Audience: jwt.ClaimStrings{p.audience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key"
		signed, err := token.SignedString(privateKey)
		if err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "discarded", "token_type": "Bearer", "expires_in": 3600, "id_token": signed,
		})
	})
	p.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder.Result(), nil
	})}
	return p
}

func testManager(t *testing.T, provider *testProvider, store *memoryStore, resolve *int) *Manager {
	t.Helper()
	manager, err := NewManager(store, AccountResolverFunc(func(_ context.Context, claims IdentityClaims) (string, error) {
		*resolve++
		if claims.Email != "person@example.com" {
			t.Fatalf("email was not normalized: %q", claims.Email)
		}
		return "user-1", nil
	}), Provider{Name: "company", Issuer: provider.issuer, ClientID: "client",
		ClientSecret: "top-secret", RedirectURL: "http://localhost/callback", AllowInsecureIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	manager.client = provider.client
	return manager
}

func beginState(t *testing.T, manager *Manager, provider *testProvider, store *memoryStore) string {
	t.Helper()
	redirect, err := manager.Begin(context.Background(), "company")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("incomplete authorization redirect: %s", redirect)
	}
	hash := sha256.Sum256([]byte(state))
	attempt := store.attempts[base64.RawURLEncoding.EncodeToString(hash[:])]
	provider.nonce = attempt.Nonce
	provider.wantVerifier = attempt.PKCEVerifier
	return state
}

func TestOIDCLoginLinksIdentityAndRejectsReplay(t *testing.T) {
	provider := newTestProvider(t)
	store := newMemoryStore()
	resolveCalls := 0
	manager := testManager(t, provider, store, &resolveCalls)
	state := beginState(t, manager, provider, store)

	result, err := manager.Complete(context.Background(), state, "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID != "user-1" || !result.NewLink || result.Claims.TenantID != "tenant-1" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if resolveCalls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolveCalls)
	}
	if _, err := manager.Complete(context.Background(), state, "authorization-code"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replayed state error = %v, want ErrInvalidState", err)
	}

	state = beginState(t, manager, provider, store)
	result, err = manager.Complete(context.Background(), state, "authorization-code")
	if err != nil || result.NewLink {
		t.Fatalf("existing identity result = %#v, %v", result, err)
	}
	if resolveCalls != 1 {
		t.Fatalf("existing identity invoked resolver; calls = %d", resolveCalls)
	}
}

func TestOIDCLoginRejectsTokenValidationFailures(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testProvider)
		want      error
	}{
		{name: "unverified email", configure: func(p *testProvider) { p.emailVerified = false }, want: ErrUnverifiedEmail},
		{name: "wrong audience", configure: func(p *testProvider) { p.audience = "other-client" }},
		{name: "wrong issuer", configure: func(p *testProvider) { p.issuerClaim = "https://attacker.invalid" }},
		{name: "wrong nonce", configure: func(p *testProvider) { p.nonce = "wrong" }, want: ErrIdentityIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newTestProvider(t)
			store := newMemoryStore()
			calls := 0
			manager := testManager(t, provider, store, &calls)
			state := beginState(t, manager, provider, store)
			tt.configure(provider)
			_, err := manager.Complete(context.Background(), state, "code")
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("Complete() error = %v, want %v", err, tt.want)
			}
			if calls != 0 {
				t.Fatal("resolver called for an invalid token")
			}
		})
	}
}

func TestProviderSecretsAreRedacted(t *testing.T) {
	provider := Provider{Name: "company", Issuer: "https://issuer.example", ClientID: "client",
		ClientSecret: "must-not-leak", RedirectURL: "https://app.example/callback"}
	encoded, err := json.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || contains(string(encoded), provider.ClientSecret) {
		t.Fatalf("provider JSON leaked secret: %s", encoded)
	}
	if rendered := fmt.Sprintf("%+v %#v", provider, provider); contains(rendered, provider.ClientSecret) {
		t.Fatalf("provider formatting leaked secret: %s", rendered)
	}
}

func contains(value, substring string) bool {
	return len(substring) > 0 && len(value) >= len(substring) && stringContains(value, substring)
}

func stringContains(value, substring string) bool {
	for i := 0; i+len(substring) <= len(value); i++ {
		if value[i:i+len(substring)] == substring {
			return true
		}
	}
	return false
}
