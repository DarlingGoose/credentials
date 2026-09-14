// Package directcookies demonstrates the low-level rotating cookie API for an
// application that does not use session.Client.
package directcookies

import (
	"net/http"
	"time"

	"github.com/DarlingGoose/credentials/session"
)

// Issue should be called only after the application has authenticated userID.
func Issue(w http.ResponseWriter, keys *session.RotatingKeyRing, userID string) error {
	return session.SetSessionCookieWithKeyRing(w, &session.UserSessionData{
		UserID:    userID,
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, keys)
}

// Authenticate rejects requests without a valid signed cookie and makes the
// decoded session available to downstream handlers through request context.
func Authenticate(keys *session.RotatingKeyRing, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current, err := session.GetSessionFromCookieWithKeyRing(r, keys)
		if err != nil || !current.SignedIn {
			session.ClearSessionCookie(w)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(current.WithContext(r.Context())))
	})
}
