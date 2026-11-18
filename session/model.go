package session

import (
	"context"
)

type contextKey string

const (
	sessionKey contextKey = "USER_SESSION_DATA"
)
const sessionCookieName = "session"

// UserSessionData holds authenticated user information
type UserSessionData struct {
	UserID         string   `json:"user_id"`
	AccountID      string   `json:"account_id,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	SignedIn       bool     `json:"signed_in"`
	ServiceAccount bool     `json:"service_account,omitempty"`
	IssuedAt       int64    `json:"issued_at,omitempty"`
	ExpiresAt      int64    `json:"expires_at"`
	SessionID      string   `json:"session_id,omitempty"`
	AuthTime       int64    `json:"auth_time,omitempty"`
	AuthMethods    []string `json:"auth_methods,omitempty"`
	SessionVersion uint64   `json:"session_version,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	Audience       []string `json:"audience,omitempty"`
	Domain         string   `json:"domain,omitempty"`
}

// WithContext attaches session data to context
func (u *UserSessionData) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, sessionKey, u)
}

type TokenInfo struct {
	UserID    string
	AccountID string
	ExpiresIn int64
	Scopes    []string
}
