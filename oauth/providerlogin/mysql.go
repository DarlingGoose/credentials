package providerlogin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MySQLStore persists provider-login state in the caller-owned database.
type MySQLStore struct{ db *sql.DB }

func NewMySQLStore(ctx context.Context, db *sql.DB) (*MySQLStore, error) {
	if db == nil {
		return nil, errors.New("provider login: nil database")
	}
	s := &MySQLStore{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("provider login schema: %w", err)
	}
	return s, nil
}

func (s *MySQLStore) ensureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS credentials_oidc_login_attempts (
			state_hash VARBINARY(32) NOT NULL PRIMARY KEY,
			provider VARCHAR(128) NOT NULL,
			nonce VARCHAR(128) NOT NULL,
			pkce_verifier VARCHAR(128) NOT NULL,
			redirect_url TEXT NOT NULL,
			expires_at TIMESTAMP(6) NOT NULL,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			INDEX idx_oidc_attempt_expiry (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS credentials_external_identities (
			identity_key BINARY(32) NOT NULL PRIMARY KEY,
			issuer TEXT NOT NULL,
			subject TEXT NOT NULL,
			user_id VARCHAR(64) NOT NULL,
			email VARCHAR(320) NOT NULL,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
			INDEX idx_external_identity_user (user_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *MySQLStore) CreateAttempt(ctx context.Context, attempt LoginAttempt) error {
	// Bound abandoned state rows without requiring a separate maintenance job.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM credentials_oidc_login_attempts WHERE expires_at <= UTC_TIMESTAMP(6)`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO credentials_oidc_login_attempts
		(state_hash, provider, nonce, pkce_verifier, redirect_url, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, attempt.StateHash, attempt.Provider, attempt.Nonce,
		attempt.PKCEVerifier, attempt.RedirectURL, attempt.ExpiresAt.UTC())
	return err
}

func (s *MySQLStore) ConsumeAttempt(ctx context.Context, stateHash []byte, now time.Time) (*LoginAttempt, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var attempt LoginAttempt
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT state_hash, provider, nonce, pkce_verifier, redirect_url, expires_at
		FROM credentials_oidc_login_attempts WHERE state_hash = ? FOR UPDATE`, stateHash).Scan(
		&attempt.StateHash, &attempt.Provider, &attempt.Nonce, &attempt.PKCEVerifier, &attempt.RedirectURL, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidState
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM credentials_oidc_login_attempts WHERE state_hash = ?`, stateHash); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	attempt.ExpiresAt = expires.UTC()
	if !attempt.ExpiresAt.After(now) {
		return nil, ErrInvalidState
	}
	return &attempt, nil
}

func (s *MySQLStore) GetIdentity(ctx context.Context, issuer, subject string) (*ExternalIdentity, error) {
	var identity ExternalIdentity
	key := externalIdentityKey(issuer, subject)
	err := s.db.QueryRowContext(ctx, `SELECT issuer, subject, user_id, email, created_at, updated_at
		FROM credentials_external_identities WHERE identity_key = ?`, key[:]).Scan(
		&identity.Issuer, &identity.Subject, &identity.UserID, &identity.Email,
		&identity.CreatedAt, &identity.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err == nil && (identity.Issuer != issuer || identity.Subject != subject) {
		return nil, ErrIdentityCollision
	}
	return &identity, err
}

func (s *MySQLStore) LinkIdentity(ctx context.Context, identity ExternalIdentity) (*ExternalIdentity, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	key := externalIdentityKey(identity.Issuer, identity.Subject)

	var existingIssuer, existingSubject, existingUser string
	err = tx.QueryRowContext(ctx, `SELECT issuer, subject, user_id FROM credentials_external_identities
		WHERE identity_key = ? FOR UPDATE`, key[:]).Scan(&existingIssuer, &existingSubject, &existingUser)
	switch {
	case err == nil && (existingIssuer != identity.Issuer || existingSubject != identity.Subject):
		return nil, ErrIdentityCollision
	case err == nil && existingUser != identity.UserID:
		return nil, ErrIdentityCollision
	case err == nil:
		if _, err = tx.ExecContext(ctx, `UPDATE credentials_external_identities SET email = ?
			WHERE identity_key = ?`, identity.Email, key[:]); err != nil {
			return nil, err
		}
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO credentials_external_identities
			(identity_key, issuer, subject, user_id, email) VALUES (?, ?, ?, ?, ?)`,
			key[:], identity.Issuer, identity.Subject, identity.UserID, identity.Email)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetIdentity(ctx, identity.Issuer, identity.Subject)
}

func externalIdentityKey(issuer, subject string) [32]byte {
	return sha256.Sum256([]byte(issuer + "\x00" + subject))
}
