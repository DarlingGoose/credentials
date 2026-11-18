package session

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	minimumRootSecretSize = 32
	derivedSigningKeySize = 32
)

var (
	ErrRootSecretTooShort = fmt.Errorf("session root secret must be at least %d bytes", minimumRootSecretSize)
	ErrInvalidRotation    = errors.New("session key rotation interval must be positive")
	ErrInvalidGrace       = errors.New("session key verification grace period must be non-negative")
)

// RotatingKeyRing derives a new HMAC signing key for every rotation window.
// Derivation is deterministic, so instances sharing the same root secret and
// clock can verify each other's cookies without synchronizing generated keys.
// The root secret itself should be supplied by a secret manager and rotated
// separately when an immediate, global session revocation is required.
type RotatingKeyRing struct {
	root              []byte
	rotationInterval  time.Duration
	verificationGrace time.Duration
	now               func() time.Time
}

// NewRotatingKeyRing constructs a session signing key ring. The grace period
// should be at least as long as the maximum session lifetime to avoid expiring
// otherwise-valid sessions after their signing key rotates.
func NewRotatingKeyRing(rootSecret []byte, rotationInterval, verificationGrace time.Duration) (*RotatingKeyRing, error) {
	if len(rootSecret) < minimumRootSecretSize {
		return nil, ErrRootSecretTooShort
	}
	if rotationInterval <= 0 {
		return nil, ErrInvalidRotation
	}
	if verificationGrace < 0 {
		return nil, ErrInvalidGrace
	}

	root := make([]byte, len(rootSecret))
	copy(root, rootSecret)
	return &RotatingKeyRing{
		root:              root,
		rotationInterval:  rotationInterval,
		verificationGrace: verificationGrace,
		now:               time.Now,
	}, nil
}

// RotationInterval reports how frequently a new signing key becomes active.
func (k *RotatingKeyRing) RotationInterval() time.Duration { return k.rotationInterval }

// VerificationGracePeriod reports how long a retired key remains valid.
func (k *RotatingKeyRing) VerificationGracePeriod() time.Duration { return k.verificationGrace }

func (k *RotatingKeyRing) currentKey() (string, []byte, error) {
	period := k.periodAt(k.now())
	key, err := k.derive(period)
	return strconv.FormatInt(period, 36), key, err
}

func (k *RotatingKeyRing) verificationKey(keyID string) ([]byte, bool) {
	period, err := strconv.ParseInt(keyID, 36, 64)
	if err != nil || period < 0 {
		return nil, false
	}

	now := k.now()
	current := k.periodAt(now)
	if period > current {
		return nil, false
	}
	periodEnd := time.Unix(0, 0).Add(time.Duration(period+1) * k.rotationInterval)
	if now.After(periodEnd.Add(k.verificationGrace)) {
		return nil, false
	}

	key, err := k.derive(period)
	return key, err == nil
}

func (k *RotatingKeyRing) isCurrent(keyID string) bool {
	return keyID == strconv.FormatInt(k.periodAt(k.now()), 36)
}

func (k *RotatingKeyRing) periodAt(t time.Time) int64 {
	return t.UnixNano() / k.rotationInterval.Nanoseconds()
}

func (k *RotatingKeyRing) derive(period int64) ([]byte, error) {
	info := "github.com/DarlingGoose/credentials/session/v1/" + strconv.FormatInt(period, 10)
	key, err := hkdf.Key(sha256.New, k.root, nil, info, derivedSigningKeySize)
	if err != nil {
		return nil, fmt.Errorf("derive session signing key: %w", err)
	}
	return key, nil
}
