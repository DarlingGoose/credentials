package oserver

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRefreshTokenReuseRevokesSQLFamily(t *testing.T) {
	t.Run("postgres", func(t *testing.T) {
		runRefreshFamilySuite(t, newTestPostgresOServer(t))
	})
	t.Run("mysql", func(t *testing.T) {
		runRefreshFamilySuite(t, newTestMySQLOServer(t))
	})
}

func runRefreshFamilySuite(t *testing.T, server OServer) {
	t.Helper()
	ctx := context.Background()
	client, err := server.RegisterClient(ctx, &OAuthClient{
		Name:              "refresh-family-test",
		RedirectURIs:      []string{"https://client.example/callback"},
		Scopes:            []string{"openid", "offline_access"},
		GrantTypes:        []string{string(GrantTypeAuthorizationCode), string(GrantTypeRefreshToken)},
		ResponseTypes:     []string{"code"},
		TokenEndpointAuth: "none",
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := server.Authorize(ctx, AuthorizationPrincipal{UserID: "user-1", AccountID: "account-1"}, AuthRequest{
		ResponseType: "code", ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0],
		Scope: "openid offline_access", CodeChallenge: GenerateCodeChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := server.Token(ctx, TokenRequest{
		GrantType: string(GrantTypeAuthorizationCode), Code: auth.Code, ClientID: client.ClientID,
		RedirectURI: client.RedirectURIs[0], CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	rotated, err := server.Token(ctx, TokenRequest{
		GrantType: string(GrantTypeRefreshToken), RefreshToken: issued.RefreshToken, ClientID: client.ClientID,
	})
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == issued.RefreshToken {
		t.Fatal("refresh token did not rotate")
	}
	_, err = server.Token(ctx, TokenRequest{
		GrantType: string(GrantTypeRefreshToken), RefreshToken: issued.RefreshToken, ClientID: client.ClientID,
	})
	if err == nil || !strings.Contains(err.Error(), "reuse detected") {
		t.Fatalf("expected reuse detection, got %v", err)
	}
	introspection, err := server.Introspect(ctx, IntrospectRequest{Token: rotated.AccessToken})
	if err != nil {
		t.Fatalf("introspect revoked access token: %v", err)
	}
	if introspection.Active {
		t.Fatal("refresh-token reuse did not revoke the family's access token")
	}
}

func newTestPostgresOServer(t *testing.T) OServer {
	t.Helper()
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("oserver"), tcpostgres.WithUsername("testuser"), tcpostgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	server, err := NewPostgresServer(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func newTestMySQLOServer(t *testing.T) OServer {
	t.Helper()
	ctx := context.Background()
	container, err := tcmysql.Run(ctx, "mysql:8",
		tcmysql.WithDatabase("oserver"), tcmysql.WithUsername("testuser"), tcmysql.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(wait.ForLog("port: 3306  MySQL Community Server").WithStartupTimeout(60*time.Second)))
	if err != nil {
		t.Fatalf("start mysql: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "3306")
	if err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("testuser:testpass@tcp(%s:%s)/oserver?parseTime=true", host, port.Port())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	server, err := NewMySQLServer(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	return server
}
