package oserver

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const authorizationCodeTTL = 10 * time.Minute

var (
	ErrAuthenticationRequired = errors.New("authentication required")
	ErrInvalidAuthorization   = errors.New("invalid authorization request")
	ErrInvalidRedirectURI     = errors.New("invalid redirect_uri")
)

// ValidateAuthorizationRequest applies protocol and registered-client policy
// before consent, code issuance, or any redirect to a client-controlled URI.
func ValidateAuthorizationRequest(ctx context.Context, server OServer, req AuthRequest) (*OAuthClient, error) {
	if req.ResponseType != "code" || req.ClientID == "" || req.RedirectURI == "" {
		return nil, ErrInvalidAuthorization
	}
	client, err := server.GetClient(ctx, req.ClientID)
	if err != nil || client == nil {
		return nil, ErrInvalidAuthorization
	}
	if !containsExact(client.RedirectURIs, req.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}
	if !containsExact(client.GrantTypes, string(GrantTypeAuthorizationCode)) ||
		!containsExact(client.ResponseTypes, "code") {
		return nil, ErrInvalidAuthorization
	}
	if req.CodeChallengeMethod != "S256" || !validS256Challenge(req.CodeChallenge) {
		return nil, ErrInvalidAuthorization
	}
	allowedScopes := make(map[string]struct{}, len(client.Scopes))
	for _, scope := range client.Scopes {
		allowedScopes[scope] = struct{}{}
	}
	for _, scope := range strings.Fields(req.Scope) {
		if _, ok := allowedScopes[scope]; !ok {
			return nil, ErrInvalidAuthorization
		}
	}
	return client, nil
}

func validateAuthorizationPrincipal(principal AuthorizationPrincipal) error {
	if strings.TrimSpace(principal.UserID) == "" {
		return ErrAuthenticationRequired
	}
	return nil
}

func validS256Challenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == 32
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateTokenClient(ctx context.Context, server OServer, req TokenRequest) error {
	if req.ClientID == "" {
		return errors.New("invalid client credentials")
	}
	client, err := server.GetClient(ctx, req.ClientID)
	if err != nil || client == nil {
		return errors.New("invalid client credentials")
	}
	switch client.TokenEndpointAuth {
	case "none":
		if req.ClientSecret != "" || req.ClientAuthMethod != "" {
			return errors.New("public client must not use a client secret")
		}
		return nil
	case "client_secret_post", "client_secret_basic":
		if req.ClientAuthMethod != client.TokenEndpointAuth {
			return errors.New("invalid client authentication method")
		}
		if client.ClientSecret == "" || req.ClientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(req.ClientSecret)) != 1 {
			return errors.New("invalid client credentials")
		}
		return nil
	default:
		return errors.New("unsupported token endpoint authentication method")
	}
}
