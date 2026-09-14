package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/DarlingGoose/credentials/oauth/oserver"
	"github.com/DarlingGoose/credentials/utils"
	"github.com/DarlingGoose/rbac"
	"github.com/google/uuid"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client manages authentication, session cookies, and role loading
type Client struct {
	ttl         time.Duration
	secret      []byte
	keys        *RotatingKeyRing
	oauthServer oserver.OServer
	rbacManager *rbac.Manager
}

// NewClient constructs a Client
func NewClient(oauthServer oserver.OServer, rbacManager *rbac.Manager, secret []byte, sessionTTL time.Duration) *Client {
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	return &Client{
		ttl:         sessionTTL,
		secret:      secretCopy,
		oauthServer: oauthServer,
		rbacManager: rbacManager,
	}
}

// NewClientWithKeyRing constructs a Client whose cookie signing keys rotate
// automatically. The grace period must cover the full session lifetime.
func NewClientWithKeyRing(oauthServer oserver.OServer, rbacManager *rbac.Manager, keys *RotatingKeyRing, sessionTTL time.Duration) (*Client, error) {
	if keys == nil {
		return nil, errors.New("session key ring is nil")
	}
	if sessionTTL <= 0 {
		return nil, errors.New("session TTL must be positive")
	}
	if keys.VerificationGracePeriod() < sessionTTL {
		return nil, errors.New("session key verification grace period must be at least the session TTL")
	}
	return &Client{
		ttl:         sessionTTL,
		keys:        keys,
		oauthServer: oauthServer,
		rbacManager: rbacManager,
	}, nil
}

// NewAutoRotatingClient is a convenience constructor for the common case.
func NewAutoRotatingClient(oauthServer oserver.OServer, rbacManager *rbac.Manager, rootSecret []byte, sessionTTL, rotationInterval time.Duration) (*Client, error) {
	keys, err := NewRotatingKeyRing(rootSecret, rotationInterval, sessionTTL)
	if err != nil {
		return nil, err
	}
	return NewClientWithKeyRing(oauthServer, rbacManager, keys, sessionTTL)
}

// Authenticate loads or creates a session, storing it in a cookie and context
func (c *Client) Authenticate(w http.ResponseWriter, r *http.Request) (*UserSessionData, context.Context, error) {
	// Try cookie
	u, refresh, err := c.readSession(r)
	if err == nil {
		if refresh {
			if err := c.writeSession(w, u); err != nil {
				return nil, r.Context(), err
			}
		}
		// attach to context
		reqCtx := u.WithContext(r.Context())
		return u, reqCtx, nil
	}
	// Fall back to OAuth introspection
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") && c.oauthServer != nil {
		token := strings.TrimSpace(authHeader[7:])
		info, err := c.oauthServer.Introspect(r.Context(), oserver.IntrospectRequest{
			Token: token,
		})
		if err == nil && info != nil && info.Active {
			// build session
			u = &UserSessionData{
				UserID:         info.UserID,
				AccountID:      info.AccountID,
				SignedIn:       true,
				ServiceAccount: strings.HasPrefix(info.UserID, "service-"),
				ExpiresAt:      info.Exp,
				Domain:         utils.GetDomain(r),
			}
			// load roles
			if c.rbacManager != nil {
				roles, err := c.rbacManager.ListRolesForUser(r.Context(), u.UserID)
				if err == nil {
					u.Roles = roles
				}
			}
			// set cookie
			if err := c.writeSession(w, u); err != nil {
				return nil, r.Context(), err
			}
			reqCtx := u.WithContext(r.Context())
			return u, reqCtx, nil
		}
	}

	u = &UserSessionData{
		UserID:    fmt.Sprintf("anon-%s", GenerateBase64Hash(time.Now(), uuid.New())),
		SignedIn:  false,
		ExpiresAt: time.Now().Add(c.ttl).Unix(),
		Roles:     []string{"default"},
		Domain:    utils.GetDomain(r),
	}
	if set, _ := strconv.ParseBool(r.URL.Query().Get("login")); !set {
		// Anonymous session
		if err := c.writeSession(w, u); err != nil {
			return nil, r.Context(), err
		}
	}
	reqCtx := u.WithContext(r.Context())
	return u, reqCtx, nil
}

func (c *Client) readSession(r *http.Request) (*UserSessionData, bool, error) {
	if c.keys != nil {
		return getSessionFromCookieWithKeyRing(r, c.keys)
	}
	u, err := GetSessionFromCookie(r, c.secret)
	return u, false, err
}

func (c *Client) writeSession(w http.ResponseWriter, u *UserSessionData) error {
	if c.keys != nil {
		return SetSessionCookieWithKeyRing(w, u, c.keys)
	}
	return SetSessionCookie(w, u, c.secret)
}

func GenerateBase64Hash(ts time.Time, id uuid.UUID) string {
	// 1) Serialize the inputs. Using UnixNano gives you full precision.
	//    Feel free to change the separator or format if you need something different.
	input := fmt.Sprintf("%d:%s", ts.UnixNano(), id.String())

	// 2) Compute SHA-256
	sum := sha256.Sum256([]byte(input))

	// 3) Return Base64 (URL‐safe, without padding)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
