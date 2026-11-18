package providerlogin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	defaultAttemptTTL = 10 * time.Minute
	maxHTTPBody       = 1 << 20
)

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type cachedDiscovery struct {
	doc       discoveryDocument
	expiresAt time.Time
}

// Manager performs OIDC discovery, authorization-code exchange, ID-token
// verification, and immutable external-identity linking.
type Manager struct {
	store      Store
	resolver   AccountResolver
	client     *http.Client
	now        func() time.Time
	attemptTTL time.Duration

	mu        sync.Mutex
	providers map[string]Provider
	discovery map[string]cachedDiscovery
	keys      map[string]cachedKeys
}

type cachedKeys struct {
	keys      map[string]any
	expiresAt time.Time
}

func NewManager(store Store, resolver AccountResolver, providers ...Provider) (*Manager, error) {
	if store == nil {
		return nil, errors.New("provider login: nil store")
	}
	if resolver == nil {
		return nil, errors.New("provider login: nil account resolver")
	}
	m := &Manager{
		store: store, resolver: resolver, client: &http.Client{Timeout: 15 * time.Second}, now: time.Now,
		attemptTTL: defaultAttemptTTL, providers: make(map[string]Provider),
		discovery: make(map[string]cachedDiscovery), keys: make(map[string]cachedKeys),
	}
	for _, provider := range providers {
		if err := validateProvider(provider); err != nil {
			return nil, err
		}
		if _, exists := m.providers[provider.Name]; exists {
			return nil, fmt.Errorf("provider login: duplicate provider %q", provider.Name)
		}
		provider.Issuer = strings.TrimSuffix(provider.Issuer, "/")
		if len(provider.Scopes) == 0 {
			provider.Scopes = []string{"openid", "email", "profile"}
		}
		m.providers[provider.Name] = provider
	}
	return m, nil
}

func validateProvider(provider Provider) error {
	if provider.Name == "" || provider.Issuer == "" || provider.ClientID == "" ||
		provider.ClientSecret == "" || provider.RedirectURL == "" {
		return errors.New("provider login: provider name, issuer, client ID, client secret, and redirect URL are required")
	}
	issuer, err := url.Parse(provider.Issuer)
	if err != nil || !validServerURL(issuer, provider.AllowInsecureIssuer) {
		return fmt.Errorf("provider login: issuer for %q must be an absolute HTTPS URL", provider.Name)
	}
	redirect, err := url.Parse(provider.RedirectURL)
	if err != nil {
		return fmt.Errorf("provider login: redirect URL for %q must use HTTPS", provider.Name)
	}
	loopbackHTTP := redirect.Scheme == "http" && (redirect.Hostname() == "localhost" || redirect.Hostname() == "127.0.0.1")
	if redirect.User != nil || redirect.Host == "" || (redirect.Scheme != "https" && !loopbackHTTP) {
		return fmt.Errorf("provider login: redirect URL for %q must use HTTPS", provider.Name)
	}
	return nil
}

func validServerURL(endpoint *url.URL, allowHTTP bool) bool {
	if endpoint == nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return false
	}
	return endpoint.Scheme == "https" || (allowHTTP && endpoint.Scheme == "http")
}

func (m *Manager) PublicProviders() []PublicProvider {
	m.mu.Lock()
	defer m.mu.Unlock()
	providers := make([]PublicProvider, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, PublicProvider{Name: provider.Name, Issuer: provider.Issuer})
	}
	return providers
}

// Begin creates a one-time login attempt and returns the provider redirect.
func (m *Manager) Begin(ctx context.Context, providerName string) (string, error) {
	provider, ok := m.providers[providerName]
	if !ok {
		return "", errors.New("provider login: unknown provider")
	}
	doc, err := m.discover(ctx, provider)
	if err != nil {
		return "", err
	}
	state, err := randomValue(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomValue(32)
	if err != nil {
		return "", err
	}
	verifier, err := randomValue(64)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(state))
	attempt := LoginAttempt{
		StateHash: hash[:], Provider: provider.Name, Nonce: nonce, PKCEVerifier: verifier,
		RedirectURL: provider.RedirectURL, ExpiresAt: m.now().Add(m.attemptTTL).UTC(),
	}
	if err := m.store.CreateAttempt(ctx, attempt); err != nil {
		return "", fmt.Errorf("provider login: persist attempt: %w", err)
	}
	config := oauth2.Config{ClientID: provider.ClientID, ClientSecret: provider.ClientSecret,
		Endpoint:    oauth2.Endpoint{AuthURL: doc.AuthorizationEndpoint, TokenURL: doc.TokenEndpoint},
		RedirectURL: provider.RedirectURL, Scopes: provider.Scopes}
	return config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256")), nil
}

// Complete consumes state exactly once, exchanges the code with PKCE, verifies
// the ID token and nonce, then resolves or creates the immutable identity link.
func (m *Manager) Complete(ctx context.Context, state, code string) (*Result, error) {
	if state == "" || code == "" {
		return nil, ErrInvalidState
	}
	hash := sha256.Sum256([]byte(state))
	attempt, err := m.store.ConsumeAttempt(ctx, hash[:], m.now())
	if err != nil {
		return nil, err
	}
	provider, ok := m.providers[attempt.Provider]
	if !ok || attempt.RedirectURL != provider.RedirectURL {
		return nil, ErrInvalidState
	}
	doc, err := m.discover(ctx, provider)
	if err != nil {
		return nil, err
	}
	config := oauth2.Config{ClientID: provider.ClientID, ClientSecret: provider.ClientSecret,
		Endpoint:    oauth2.Endpoint{AuthURL: doc.AuthorizationEndpoint, TokenURL: doc.TokenEndpoint},
		RedirectURL: attempt.RedirectURL, Scopes: provider.Scopes}
	exchangeContext := context.WithValue(ctx, oauth2.HTTPClient, m.client)
	token, err := config.Exchange(exchangeContext, code, oauth2.SetAuthURLParam("code_verifier", attempt.PKCEVerifier))
	if err != nil {
		return nil, fmt.Errorf("provider login: code exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("provider login: token response has no ID token")
	}
	claims, err := m.verifyIDToken(ctx, provider, doc, rawIDToken, attempt.Nonce)
	if err != nil {
		return nil, err
	}
	existing, err := m.store.GetIdentity(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Refresh verified email metadata without permitting ownership changes.
		existing.Email = claims.Email
		linked, err := m.store.LinkIdentity(ctx, *existing)
		if err != nil {
			return nil, err
		}
		return &Result{Provider: provider.Name, UserID: linked.UserID, Claims: claims}, nil
	}
	userID, err := m.resolver.ResolveAccount(ctx, claims)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, errors.New("provider login: account resolver returned an empty user ID")
	}
	linked, err := m.store.LinkIdentity(ctx, ExternalIdentity{
		Issuer: claims.Issuer, Subject: claims.Subject, UserID: userID, Email: claims.Email,
	})
	if err != nil {
		return nil, err
	}
	return &Result{Provider: provider.Name, UserID: linked.UserID, Claims: claims, NewLink: true}, nil
}

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func pkceChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (m *Manager) discover(ctx context.Context, provider Provider) (discoveryDocument, error) {
	m.mu.Lock()
	cached, ok := m.discovery[provider.Issuer]
	m.mu.Unlock()
	if ok && cached.expiresAt.After(m.now()) {
		return cached.doc, nil
	}
	var doc discoveryDocument
	if err := m.getJSON(ctx, provider.Issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return doc, fmt.Errorf("provider login: discovery: %w", err)
	}
	if doc.Issuer != provider.Issuer || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return doc, errors.New("provider login: invalid discovery document")
	}
	for _, endpoint := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		u, err := url.Parse(endpoint)
		if err != nil || !validServerURL(u, provider.AllowInsecureIssuer) {
			return doc, errors.New("provider login: discovery returned an insecure endpoint")
		}
	}
	m.mu.Lock()
	m.discovery[provider.Issuer] = cachedDiscovery{doc: doc, expiresAt: m.now().Add(time.Hour)}
	m.mu.Unlock()
	return doc, nil
}

func (m *Manager) getJSON(ctx context.Context, endpoint string, destination any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	response, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, maxHTTPBody)).Decode(destination)
}

type idTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Nonce         string `json:"nonce"`
	TenantID      string `json:"tid"`
	Name          string `json:"name"`
	jwt.RegisteredClaims
}

func (m *Manager) verifyIDToken(ctx context.Context, provider Provider, doc discoveryDocument, rawToken, nonce string) (IdentityClaims, error) {
	claims := &idTokenClaims{}
	parsed, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		if !allowedAlgorithm(token.Method.Alg()) {
			return nil, errors.New("provider login: unsupported ID-token algorithm")
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("provider login: ID token has no key ID")
		}
		return m.signingKey(ctx, doc.JWKSURI, kid)
	}, jwt.WithAudience(provider.ClientID), jwt.WithIssuer(provider.Issuer),
		jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		return IdentityClaims{}, fmt.Errorf("provider login: invalid ID token: %w", err)
	}
	if claims.Subject == "" || claims.Nonce == "" || claims.Nonce != nonce {
		return IdentityClaims{}, ErrIdentityIncomplete
	}
	if claims.Email == "" || !claims.EmailVerified {
		return IdentityClaims{}, ErrUnverifiedEmail
	}
	return IdentityClaims{Issuer: provider.Issuer, Subject: claims.Subject,
		Email: strings.ToLower(strings.TrimSpace(claims.Email)), EmailVerified: true,
		TenantID: claims.TenantID, Name: claims.Name}, nil
}

func allowedAlgorithm(algorithm string) bool {
	switch algorithm {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

type jwkSet struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (m *Manager) signingKey(ctx context.Context, jwksURI, kid string) (any, error) {
	m.mu.Lock()
	cached, ok := m.keys[jwksURI]
	m.mu.Unlock()
	if ok && cached.expiresAt.After(m.now()) {
		if key := cached.keys[kid]; key != nil {
			return key, nil
		}
	}
	var set jwkSet
	if err := m.getJSON(ctx, jwksURI, &set); err != nil {
		return nil, fmt.Errorf("provider login: fetch signing keys: %w", err)
	}
	keys := make(map[string]any, len(set.Keys))
	for _, encoded := range set.Keys {
		key, err := encoded.publicKey()
		if err == nil && encoded.Kid != "" {
			keys[encoded.Kid] = key
		}
	}
	m.mu.Lock()
	m.keys[jwksURI] = cachedKeys{keys: keys, expiresAt: m.now().Add(time.Hour)}
	m.mu.Unlock()
	key := keys[kid]
	if key == nil {
		return nil, errors.New("provider login: signing key not found")
	}
	return key, nil
}

func (key jsonWebKey) publicKey() (any, error) {
	decode := func(value string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(value) }
	switch key.Kty {
	case "RSA":
		n, err := decode(key.N)
		if err != nil {
			return nil, err
		}
		e, err := decode(key.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid RSA exponent")
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
	case "EC":
		curves := map[string]struct {
			curve elliptic.Curve
			size  int
		}{
			"P-256": {curve: elliptic.P256(), size: 32},
			"P-384": {curve: elliptic.P384(), size: 48},
			"P-521": {curve: elliptic.P521(), size: 66},
		}
		curve, ok := curves[key.Crv]
		if !ok {
			return nil, errors.New("unsupported EC curve")
		}
		x, err := decode(key.X)
		if err != nil {
			return nil, err
		}
		y, err := decode(key.Y)
		if err != nil {
			return nil, err
		}
		if len(x) == 0 || len(x) > curve.size || len(y) == 0 || len(y) > curve.size {
			return nil, errors.New("invalid EC point")
		}
		encoded := make([]byte, 1+2*curve.size)
		encoded[0] = 4
		copy(encoded[1+curve.size-len(x):1+curve.size], x)
		copy(encoded[1+2*curve.size-len(y):], y)
		public, err := ecdsa.ParseUncompressedPublicKey(curve.curve, encoded)
		if err != nil {
			return nil, errors.New("invalid EC point")
		}
		return public, nil
	default:
		return nil, errors.New("unsupported signing key type")
	}
}
