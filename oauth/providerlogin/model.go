// Package providerlogin implements reusable, server-side OpenID Connect login.
// It deliberately keeps deployment admission and local-user provisioning policy
// outside this package.
package providerlogin

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidState       = errors.New("provider login: invalid or expired state")
	ErrUnverifiedEmail    = errors.New("provider login: provider did not verify the email")
	ErrIdentityCollision  = errors.New("provider login: external identity is already linked to another user")
	ErrIdentityIncomplete = errors.New("provider login: identity is missing required claims")
)

// Provider is secret-backed server configuration. ClientSecret is never
// included in JSON output or returned by this package's result types.
type Provider struct {
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes,omitempty"`

	// AllowInsecureIssuer is intended only for local tests. Production issuers
	// must use HTTPS.
	AllowInsecureIssuer bool `json:"-"`
}

func (p Provider) String() string {
	return fmt.Sprintf("Provider{Name:%q, Issuer:%q, ClientID:%q, ClientSecret:[REDACTED], RedirectURL:%q}",
		p.Name, p.Issuer, p.ClientID, p.RedirectURL)
}

func (p Provider) GoString() string { return p.String() }

// PublicProvider is safe to expose in diagnostics and login-provider lists.
type PublicProvider struct {
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
}

// LoginAttempt contains callback correlation data. StateHash is a SHA-256
// digest; the bearer state value sent to the browser is never persisted.
type LoginAttempt struct {
	StateHash    []byte
	Provider     string
	Nonce        string
	PKCEVerifier string
	RedirectURL  string
	ExpiresAt    time.Time
}

// IdentityClaims are the security-relevant claims obtained from a verified ID
// token. Email must be provider-verified before it is populated.
type IdentityClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	TenantID      string
	Name          string
}

// ExternalIdentity is an immutable link from an OIDC issuer and subject to one
// local user. Email is mutable provider metadata and is not an identity key.
type ExternalIdentity struct {
	Issuer    string
	Subject   string
	UserID    string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store persists one-time login attempts and durable external identities.
type Store interface {
	CreateAttempt(context.Context, LoginAttempt) error
	ConsumeAttempt(context.Context, []byte, time.Time) (*LoginAttempt, error)
	GetIdentity(context.Context, string, string) (*ExternalIdentity, error)
	LinkIdentity(context.Context, ExternalIdentity) (*ExternalIdentity, error)
}

// AccountResolver applies application-owned account linking/provisioning and
// admission policy. It is called only after cryptographic token validation and
// only when the issuer+subject has no existing link.
type AccountResolver interface {
	ResolveAccount(context.Context, IdentityClaims) (userID string, err error)
}

type AccountResolverFunc func(context.Context, IdentityClaims) (string, error)

func (f AccountResolverFunc) ResolveAccount(ctx context.Context, claims IdentityClaims) (string, error) {
	return f(ctx, claims)
}

// Result is returned after a successful callback. Provider tokens are never
// retained in the store or exposed here.
type Result struct {
	Provider string
	UserID   string
	Claims   IdentityClaims
	NewLink  bool
}
