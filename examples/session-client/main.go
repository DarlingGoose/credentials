// Command session-client demonstrates rotating signed sessions in a small HTTP
// application. It uses anonymous sessions so the example does not require an
// OAuth server or RBAC backend.
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/DarlingGoose/credentials/session"
)

func main() {
	rootSecret, err := loadRootSecret()
	if err != nil {
		log.Fatal(err)
	}

	client, err := session.NewAutoRotatingClient(
		nil, // Supply an oauth/oserver.OServer to accept Bearer tokens.
		nil, // Supply an *rbac.Manager to load authenticated user roles.
		rootSecret,
		7*24*time.Hour, // Session lifetime and retired-key grace period.
		24*time.Hour,   // Derive a fresh signing key daily.
	)
	if err != nil {
		log.Fatalf("configure session client: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		current, err := session.GetSession(r.Context())
		if err != nil {
			http.Error(w, "session unavailable", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "session user: %s; signed in: %t\n", current.UserID, current.SignedIn)
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           authenticate(client, mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("listening on https://localhost%s", server.Addr)
	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}

func authenticate(client *session.Client, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ctx, err := client.Authenticate(w, r)
		if err != nil {
			http.Error(w, "authentication failed", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loadRootSecret() ([]byte, error) {
	encoded := os.Getenv("SESSION_ROOT_SECRET")
	if encoded == "" {
		return nil, fmt.Errorf("SESSION_ROOT_SECRET is required")
	}
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode SESSION_ROOT_SECRET: %w", err)
	}
	return secret, nil
}
