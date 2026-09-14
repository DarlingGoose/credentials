// Package userserver demonstrates constructing and routing the full user
// authentication server with rotating session signing keys.
package userserver

import (
	"net/http"
	"time"

	"github.com/DarlingGoose/credentials/user"
	"github.com/DarlingGoose/rbac"
)

// Config contains the deployment-specific WebAuthn and session settings.
type Config struct {
	RootSecret []byte
	RPID       string
	RPName     string
	RPOrigins  []string
}

// New constructs an auth server. RootSecret must contain at least 32 random
// bytes loaded from persistent secret-manager storage.
func New(store user.Store, manager *rbac.Manager, cfg Config) (*user.Server, error) {
	return user.NewAutoRotatingServer(
		store,
		manager,
		cfg.RootSecret,
		24*time.Hour,
		cfg.RPID,
		cfg.RPName,
		cfg.RPOrigins...,
	)
}

// Routes exposes a minimal set of public authentication endpoints and mounts
// an authenticated application handler under /app/. Add the remaining TOTP,
// passkey-registration, and account-management handlers as needed.
func Routes(auth *user.Server, application http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", auth.RegisterHandler)
	mux.HandleFunc("POST /auth/login/password", auth.LoginPasswordHandler)
	mux.HandleFunc("POST /auth/login/totp", auth.LoginTOTPHandler)
	mux.HandleFunc("POST /auth/login/passkey/begin", auth.BeginPasskeyLoginHandler)
	mux.HandleFunc("POST /auth/login/passkey/finish", auth.FinishPasskeyLoginHandler)
	mux.HandleFunc("POST /auth/logout", auth.LogoutHandler)

	// AuthMiddleware loads a valid user into the request context. requireUser
	// turns the optional authentication middleware into an enforced boundary.
	mux.Handle("/app/", auth.AuthMiddleware(requireUser(application)))
	return mux
}

func requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := user.GetUserFromContext(r.Context()); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
