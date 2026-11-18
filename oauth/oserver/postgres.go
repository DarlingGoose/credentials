// file: oserver/postgres_server.go
package oserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ OServer = &PostgresServer{}

// PostgresServer implements the OAuth2 OServer interface backed by PostgreSQL.
type PostgresServer struct {
	db *pgxpool.Pool
}

// NewPostgresServer creates a new PostgresServer and ensures the schema exists.
func NewPostgresServer(ctx context.Context, db *pgxpool.Pool) (*PostgresServer, error) {
	s := &PostgresServer{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("postgres_server: ensure schema: %w", err)
	}
	return s, nil
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

func (s *PostgresServer) ensureSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS oauth_clients (
			client_id                  TEXT        PRIMARY KEY,
			account_id                 TEXT        NOT NULL DEFAULT '',
			client_secret              TEXT        NOT NULL,
			name                       TEXT        NOT NULL,
			image_url                  TEXT        NOT NULL DEFAULT '',
			redirect_uris              TEXT[]      NOT NULL DEFAULT '{}',
			scopes                     TEXT[]      NOT NULL DEFAULT '{}',
			grant_types                TEXT[]      NOT NULL DEFAULT '{}',
			response_types             TEXT[]      NOT NULL DEFAULT '{}',
			token_endpoint_auth_method TEXT        NOT NULL DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS oauth_tokens (
			id                   BIGSERIAL   PRIMARY KEY,
			code                 TEXT        UNIQUE,
			access_token         TEXT        UNIQUE,
			refresh_token        TEXT        UNIQUE,
			client_id            TEXT        NOT NULL,
			user_id              TEXT        NOT NULL DEFAULT '',
			account_id           TEXT        NOT NULL DEFAULT '',
			redirect_uri         TEXT        NOT NULL DEFAULT '',
			scope                TEXT        NOT NULL DEFAULT '',
			grant_type           TEXT        NOT NULL DEFAULT '',
			code_challenge       TEXT        NOT NULL DEFAULT '',
			code_challenge_method TEXT       NOT NULL DEFAULT '',
			expires_at           BIGINT      NOT NULL DEFAULT 0,
			created_at           BIGINT      NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
			token_hash  TEXT   PRIMARY KEY,
			family_id   TEXT   NOT NULL,
			client_id   TEXT   NOT NULL,
			generation  BIGINT NOT NULL,
			consumed_at BIGINT NOT NULL DEFAULT 0,
			revoked_at  BIGINT NOT NULL DEFAULT 0,
			created_at  BIGINT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family_idx
			ON oauth_refresh_tokens (family_id);

		CREATE TABLE IF NOT EXISTS oauth_jwks (
			id  BIGSERIAL PRIMARY KEY,
			key JSONB     NOT NULL
		);

		CREATE TABLE IF NOT EXISTS oauth_client_images (
			client_id    TEXT  PRIMARY KEY,
			data         BYTEA NOT NULL,
			content_type TEXT  NOT NULL DEFAULT '',
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	return err
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func generateSecretPG(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --------------------------------------------------------------------------
// Client management
// --------------------------------------------------------------------------

// RegisterClient inserts a new OAuth client.
func (s *PostgresServer) RegisterClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"client_credentials"}
	}
	if client.TokenEndpointAuth == "" {
		client.TokenEndpointAuth = "client_secret_post"
	}
	if len(client.RedirectURIs) == 0 {
		return nil, fmt.Errorf("no redirect_uris provided")
	}
	if client.Name == "" {
		return nil, fmt.Errorf("no name provided")
	}

	client.ClientID = uuid.New().String()
	secret, err := generateSecretPG(32)
	if err != nil {
		return nil, err
	}
	client.ClientSecret = secret

	_, err = s.db.Exec(ctx, `
		INSERT INTO oauth_clients
			(client_id, account_id, client_secret, name, image_url,
			 redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		client.ClientID,
		client.AccountID,
		client.ClientSecret,
		client.Name,
		client.ImageURL,
		client.RedirectURIs,
		client.Scopes,
		client.GrantTypes,
		client.ResponseTypes,
		client.TokenEndpointAuth,
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GetClient retrieves a client by ID.
func (s *PostgresServer) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	row := s.db.QueryRow(ctx, `
		SELECT client_id, account_id, client_secret, name, image_url,
		       redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method
		FROM oauth_clients WHERE client_id = $1`, clientID)

	c := &OAuthClient{}
	err := row.Scan(
		&c.ClientID, &c.AccountID, &c.ClientSecret, &c.Name, &c.ImageURL,
		&c.RedirectURIs, &c.Scopes, &c.GrantTypes, &c.ResponseTypes, &c.TokenEndpointAuth,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListClients returns clients filtered by accountID (pass "" for all).
func (s *PostgresServer) ListClients(ctx context.Context, accountID string) ([]*OAuthClient, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if accountID != "" {
		rows, err = s.db.Query(ctx, `
			SELECT client_id, account_id, name, redirect_uris, scopes, grant_types, response_types
			FROM oauth_clients WHERE account_id = $1`, accountID)
	} else {
		rows, err = s.db.Query(ctx, `
			SELECT client_id, account_id, name, redirect_uris, scopes, grant_types, response_types
			FROM oauth_clients`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*OAuthClient
	for rows.Next() {
		c := &OAuthClient{}
		if err := rows.Scan(
			&c.ClientID, &c.AccountID, &c.Name,
			&c.RedirectURIs, &c.Scopes, &c.GrantTypes, &c.ResponseTypes,
		); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// UpdateClient updates the mutable fields of an existing client.
func (s *PostgresServer) UpdateClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	_, err := s.db.Exec(ctx, `
		UPDATE oauth_clients SET
			name                       = $1,
			image_url                  = $2,
			redirect_uris              = $3,
			scopes                     = $4,
			grant_types                = $5,
			response_types             = $6,
			token_endpoint_auth_method = $7
		WHERE client_id = $8`,
		client.Name,
		client.ImageURL,
		client.RedirectURIs,
		client.Scopes,
		client.GrantTypes,
		client.ResponseTypes,
		client.TokenEndpointAuth,
		client.ClientID,
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// DeleteClient removes a client by ID.
func (s *PostgresServer) DeleteClient(ctx context.Context, clientID string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM oauth_clients WHERE client_id = $1`, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("client not found")
	}
	return nil
}

// --------------------------------------------------------------------------
// Authorization code
// --------------------------------------------------------------------------

// Authorize issues an authorization code.

func (s *PostgresServer) Authorize(ctx context.Context, principal AuthorizationPrincipal, req AuthRequest) (*AuthResponse, error) {
	if err := validateAuthorizationPrincipal(principal); err != nil {
		return nil, err
	}
	if _, err := ValidateAuthorizationRequest(ctx, s, req); err != nil {
		return nil, err
	}
	code, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO oauth_tokens
			(code, client_id, user_id, account_id, redirect_uri, scope,
			 code_challenge, code_challenge_method, grant_type, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		hashOpaqueToken(code),
		req.ClientID,
		principal.UserID,
		principal.AccountID,
		req.RedirectURI,
		req.Scope,
		req.CodeChallenge,
		req.CodeChallengeMethod,
		string(GrantTypeAuthorizationCode),
		time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{Code: code, State: req.State}, nil
}

// --------------------------------------------------------------------------
// Token
// --------------------------------------------------------------------------

// Token handles authorization_code, refresh_token, and client_credentials grants.
func (s *PostgresServer) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	now := time.Now()

	switch req.GrantType {
	case string(GrantTypeAuthorizationCode):
		return s.tokenFromCode(ctx, req, now)
	case string(GrantTypeRefreshToken):
		return s.tokenFromRefresh(ctx, req, now)
	case "client_credentials":
		return s.tokenFromClientCredentials(ctx, req, now)
	default:
		return nil, errors.New("unsupported grant_type")
	}
}

func (s *PostgresServer) tokenFromCode(ctx context.Context, req TokenRequest, now time.Time) (*TokenResponse, error) {
	if err := validateTokenClient(ctx, s, req); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var (
		clientID            string
		redirectURI         string
		scope               string
		codeChallenge       string
		codeChallengeMethod string
		createdAt           int64
	)
	codeHash := hashOpaqueToken(req.Code)
	err = tx.QueryRow(ctx, `
		SELECT client_id, redirect_uri, scope, code_challenge, code_challenge_method, created_at
		FROM oauth_tokens WHERE code = $1 FOR UPDATE`, codeHash).
		Scan(&clientID, &redirectURI, &scope, &codeChallenge, &codeChallengeMethod, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid authorization code")
	}
	if err != nil {
		return nil, err
	}

	if redirectURI != req.RedirectURI {
		return nil, errors.New("redirect_uri mismatch")
	}
	if clientID != req.ClientID {
		return nil, errors.New("authorization code client mismatch")
	}
	if createdAt <= 0 || now.After(time.Unix(createdAt, 0).Add(authorizationCodeTTL)) {
		return nil, errors.New("authorization code expired")
	}

	if codeChallengeMethod != "S256" || codeChallenge == "" || !ValidateCodeChallenge(req.CodeVerifier, codeChallenge) {
		return nil, errors.New("invalid code_verifier")
	}

	accessToken, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	refreshToken, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(time.Hour).Unix()
	familyID, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}

	tag, err := tx.Exec(ctx, `
		UPDATE oauth_tokens
		SET code = NULL, access_token = $1, refresh_token = $2, expires_at = $3
		WHERE code = $4 AND client_id = $5`,
		hashOpaqueToken(accessToken), hashOpaqueToken(refreshToken), expiresAt, codeHash, req.ClientID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errors.New("authorization code already consumed")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens
		(token_hash, family_id, client_id, generation, created_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashOpaqueToken(refreshToken), familyID, req.ClientID, 0, now.Unix()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Hour.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func (s *PostgresServer) tokenFromRefresh(ctx context.Context, req TokenRequest, now time.Time) (*TokenResponse, error) {
	if err := validateTokenClient(ctx, s, req); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	refreshHash := hashOpaqueToken(req.RefreshToken)
	var familyID, clientID string
	var generation, consumedAt, revokedAt int64
	err = tx.QueryRow(ctx, `
		SELECT family_id, client_id, generation, consumed_at, revoked_at
		FROM oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE`, refreshHash).
		Scan(&familyID, &clientID, &generation, &consumedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid refresh token")
	}
	if err != nil {
		return nil, err
	}

	if clientID != req.ClientID {
		return nil, errors.New("refresh token client mismatch")
	}
	if revokedAt != 0 {
		return nil, errors.New("refresh token family revoked")
	}
	if consumedAt != 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE oauth_refresh_tokens SET revoked_at = $1
			WHERE family_id = $2 AND revoked_at = 0`, now.Unix(), familyID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE oauth_tokens SET access_token = NULL, refresh_token = NULL, expires_at = 0
			WHERE refresh_token IN (
				SELECT token_hash FROM oauth_refresh_tokens
				WHERE family_id = $1 AND consumed_at = 0
			)`, familyID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errors.New("refresh token reuse detected")
	}

	var scope string
	err = tx.QueryRow(ctx, `
		SELECT scope FROM oauth_tokens
		WHERE refresh_token = $1 AND client_id = $2 FOR UPDATE`, refreshHash, req.ClientID).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("refresh token is not current")
	}
	if err != nil {
		return nil, err
	}
	accessToken, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	refreshToken, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(time.Hour).Unix()
	newRefreshHash := hashOpaqueToken(refreshToken)

	tag, err := tx.Exec(ctx, `
		UPDATE oauth_tokens SET access_token = $1, refresh_token = $2, expires_at = $3
		WHERE refresh_token = $4 AND client_id = $5`,
		hashOpaqueToken(accessToken), newRefreshHash, expiresAt, refreshHash, req.ClientID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errors.New("refresh token already used")
	}
	tag, err = tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens SET consumed_at = $1
		WHERE token_hash = $2 AND consumed_at = 0 AND revoked_at = 0`, now.Unix(), refreshHash)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errors.New("refresh token already used")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens
		(token_hash, family_id, client_id, generation, created_at)
		VALUES ($1,$2,$3,$4,$5)`, newRefreshHash, familyID, req.ClientID, generation+1, now.Unix()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Hour.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func (s *PostgresServer) tokenFromClientCredentials(ctx context.Context, req TokenRequest, now time.Time) (*TokenResponse, error) {
	var (
		clientSecret string
		scopes       []string
		grantTypes   []string
	)
	err := s.db.QueryRow(ctx, `
		SELECT client_secret, scopes, grant_types
		FROM oauth_clients WHERE client_id = $1`, req.ClientID).
		Scan(&clientSecret, &scopes, &grantTypes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid client credentials")
	}
	if err != nil {
		return nil, err
	}

	if clientSecret != req.ClientSecret {
		return nil, errors.New("invalid client credentials")
	}

	allowed := false
	for _, gt := range grantTypes {
		if gt == "client_credentials" {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("grant_type not allowed")
	}

	accessToken, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(time.Hour).Unix()
	scopeStr := strings.Join(scopes, " ")

	_, err = s.db.Exec(ctx, `
		INSERT INTO oauth_tokens
			(access_token, client_id, scope, grant_type, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		hashOpaqueToken(accessToken), req.ClientID, scopeStr, "client_credentials", expiresAt, now.Unix())
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Hour.Seconds()),
		Scope:       scopeStr,
	}, nil
}

// --------------------------------------------------------------------------
// Revocation & Introspection
// --------------------------------------------------------------------------

// Revoke invalidates an access or refresh token.
func (s *PostgresServer) Revoke(ctx context.Context, req RevocationRequest) error {
	tokenHash := hashOpaqueToken(req.Token)
	_, err := s.db.Exec(ctx, `
		DELETE FROM oauth_tokens
		WHERE access_token = $1 OR refresh_token = $1`, tokenHash)
	return err
}

// Introspect returns the active state and metadata of a token.
func (s *PostgresServer) Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error) {
	var (
		clientID  string
		userID    string
		accountID string
		scope     string
		expiresAt int64
	)
	err := s.db.QueryRow(ctx, `
		SELECT client_id, user_id, account_id, scope, expires_at
		FROM oauth_tokens WHERE access_token = $1`, hashOpaqueToken(req.Token)).
		Scan(&clientID, &userID, &accountID, &scope, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return &IntrospectResponse{Active: false}, nil
	}
	if err != nil {
		return nil, err
	}

	return &IntrospectResponse{
		Active:    time.Now().Unix() < expiresAt,
		ClientID:  clientID,
		Scope:     scope,
		Exp:       expiresAt,
		UserID:    userID,
		AccountID: accountID,
	}, nil
}

// --------------------------------------------------------------------------
// JWKs
// --------------------------------------------------------------------------

// JWKs returns the stored JWK set.
func (s *PostgresServer) JWKs(ctx context.Context) (*JWKSet, error) {
	rows, err := s.db.Query(ctx, `SELECT key FROM oauth_jwks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []json.RawMessage
	for rows.Next() {
		var key json.RawMessage
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return &JWKSet{Keys: keys}, rows.Err()
}

// --------------------------------------------------------------------------
// Client images
// --------------------------------------------------------------------------

// SetClientImage uploads or replaces the image for a client.
func (s *PostgresServer) SetClientImage(r *http.Request, clientID string) error {
	ctx := r.Context()
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return err
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, `
		INSERT INTO oauth_client_images (client_id, data, content_type, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (client_id) DO UPDATE
			SET data         = EXCLUDED.data,
			    content_type = EXCLUDED.content_type,
			    updated_at   = NOW()`,
		clientID, data, header.Header.Get("Content-Type"))
	return err
}

// SendClientImage streams the stored image to the HTTP response.
func (s *PostgresServer) SendClientImage(w http.ResponseWriter, r *http.Request, clientID string) error {
	ctx := r.Context()

	var (
		data        []byte
		contentType string
	)
	err := s.db.QueryRow(ctx, `
		SELECT data, content_type FROM oauth_client_images WHERE client_id = $1`, clientID).
		Scan(&data, &contentType)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return nil
	}
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, err = w.Write(data)
	return err
}

// --------------------------------------------------------------------------
// Access check
// --------------------------------------------------------------------------

// HasAccess validates a Bearer token and delegates the RBAC decision.
func (s *PostgresServer) HasAccess(r *http.Request, resource string, hasRbacAccess func(resource, userID, accountID string, scopes ...string) bool) (bool, error) {
	ctx := r.Context()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return hasRbacAccess(resource, "", ""), nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	var (
		userID    string
		accountID string
		scope     string
		expiresAt int64
	)
	err := s.db.QueryRow(ctx, `
		SELECT user_id, account_id, scope, expires_at
		FROM oauth_tokens WHERE access_token = $1`, hashOpaqueToken(token)).
		Scan(&userID, &accountID, &scope, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if time.Now().Unix() >= expiresAt {
		return false, nil
	}

	var scopes []string
	if scope != "" {
		scopes = strings.Fields(scope)
	}
	return hasRbacAccess(resource, userID, accountID, scopes...), nil
}
