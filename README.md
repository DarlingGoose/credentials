# credentials

`credentials` provides Go packages for signed sessions, user authentication,
WebAuthn, TOTP, RBAC integration, and OAuth 2.0 server/client storage.

## Installation

```sh
go get github.com/DarlingGoose/credentials
```

## Automatically rotating session keys

The recommended session configuration uses `session.RotatingKeyRing`. It
derives a new HMAC-SHA256 signing key at each configured time boundary using
HKDF-SHA256.

Because derivation is deterministic, application instances that share the same
root secret and have synchronized clocks can verify each other's cookies. No
generated key files or background rotation goroutine are required.

Create a persistent, random root secret once and store it in your deployment's
secret manager. For example:

```sh
openssl rand -base64 32
```

Do not generate a new root secret each time the application starts. Replacing
the root secret invalidates all existing sessions and should be treated as an
explicit global sign-out operation.

### Complete examples

- [Runnable rotating session client](examples/session-client/main.go) shows
  environment-based root-secret loading, authentication middleware, session
  context access, server timeouts, and HTTPS serving.
- [Rotating user authentication server](examples/user-server/example.go) shows
  WebAuthn configuration, public login routes, and an enforced authenticated
  application route.
- [Direct rotating cookies](examples/direct-cookies/example.go) shows issuing
  and validating cookies without the `session.Client` wrapper.

To run the session-client example, generate a development TLS certificate and
start it with a persistent root secret:

```sh
export SESSION_ROOT_SECRET="$(openssl rand -base64 32)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
go run ./examples/session-client
```

The example expects `cert.pem` and `key.pem` in the working directory because
session cookies are `Secure` and should be exercised over HTTPS.

### Session client

For the common case, construct an automatically rotating client directly:

```go
package main

import (
	"encoding/base64"
	"log"
	"os"
	"time"

	"github.com/DarlingGoose/credentials/session"
)

func newSessionClient() *session.Client {
	rootSecret, err := base64.StdEncoding.DecodeString(os.Getenv("SESSION_ROOT_SECRET"))
	if err != nil {
		log.Fatalf("decode SESSION_ROOT_SECRET: %v", err)
	}

	client, err := session.NewAutoRotatingClient(
		oauthServer,
		rbacManager,
		rootSecret,
		7*24*time.Hour, // session lifetime
		24*time.Hour,   // signing-key rotation interval
	)
	if err != nil {
		log.Fatalf("configure sessions: %v", err)
	}
	return client
}
```

`NewAutoRotatingClient` retains retired keys for the complete session lifetime.
This lets an unexpired cookie continue working after its signing key rotates.
When an older cookie is presented, the client transparently re-signs it using
the current key.

For explicit control over the verification grace period, construct the key ring
and client separately:

```go
keys, err := session.NewRotatingKeyRing(
	rootSecret,
	24*time.Hour,   // rotation interval
	7*24*time.Hour, // retired-key verification grace period
)
if err != nil {
	return err
}

client, err := session.NewClientWithKeyRing(
	oauthServer,
	rbacManager,
	keys,
	7*24*time.Hour,
)
```

The client constructor requires the grace period to be at least as long as the
session lifetime. Root secrets must be at least 32 bytes.

### User authentication server

The `user` package issues seven-day sessions. Its convenience constructor uses
that lifetime as the retired-key grace period:

```go
authServer, err := user.NewAutoRotatingServer(
	store,
	rbacManager,
	rootSecret,
	24*time.Hour, // signing-key rotation interval
	"example.com",
	"Example App",
	"https://example.com",
)
if err != nil {
	return err
}
```

To share one key ring between the `session` and `user` packages:

```go
keys, err := session.NewRotatingKeyRing(
	rootSecret,
	24*time.Hour,
	7*24*time.Hour,
)
if err != nil {
	return err
}

sessionClient, err := session.NewClientWithKeyRing(
	oauthServer,
	rbacManager,
	keys,
	7*24*time.Hour,
)
if err != nil {
	return err
}

authServer, err := user.NewServerWithKeyRing(
	store,
	rbacManager,
	keys,
	"example.com",
	"Example App",
	"https://example.com",
)
```

## Migrating from a static session secret

The existing APIs remain available:

```go
client := session.NewClient(oauthServer, rbacManager, secret, sessionTTL)
authServer, err := user.NewServer(store, rbacManager, secret, rpID, rpName, origins...)
```

To migrate without immediately signing everyone out, pass the exact existing
session secret as the rotating key ring's root secret. Legacy two-part cookies
are accepted and upgraded to the versioned rotating format when used.

If the existing secret is shorter than 32 bytes, it cannot be used with the
rotating API. Deploying a new strong root secret will invalidate existing
cookies, so plan that change as a global sign-out.

## Session cookie security

Session cookies are:

- signed with HMAC-SHA256;
- limited to 4 KiB;
- rejected when expired or missing a valid expiration;
- marked `Secure` and `HttpOnly`;
- configured with `SameSite=None` and `Partitioned` by default.

Production deployments should use HTTPS, keep the root secret out of source
control and logs, synchronize instance clocks, and choose a rotation interval
appropriate for their threat model. Daily rotation with a grace period equal to
the maximum session lifetime is a reasonable starting point.

The cookie contents are signed but not encrypted. Do not put passwords, TOTP
secrets, access tokens, or other confidential data in `UserSessionData`.

## Direct cookie API

Applications that do not use `session.Client` can sign and verify cookies with
the rotating key ring directly:

```go
err := session.SetSessionCookieWithKeyRing(w, sessionData, keys)
sessionData, err := session.GetSessionFromCookieWithKeyRing(r, keys)
```

Always handle errors returned while creating or setting a session cookie.

## Testing

Run the session and user-authentication unit tests, including the race detector:

```sh
go test -race ./session
go test -race ./user -run '^TestUnit'
```

The complete `user` test suite also contains MySQL and PostgreSQL integration
tests backed by testcontainers, so `go test ./...` requires a working Docker
daemon.
