package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
)

// RenewFloor is the least time ahead of expiry a token is renewed, whatever
// its lifetime: a request signed now must not arrive after its token died.
//
// It is also how far ahead of expiry a long-lived stream reconnects (see
// ReconnectBy), which is why it is one constant: a stream reopened then finds a
// token inside the renewal window that is still valid, and the server renews
// only a valid token.
const RenewFloor = 2 * time.Minute

// unknownLifetimeWindow is how far ahead of expiry a token whose issue time was
// never recorded — a credential stored by an earlier version — is renewed: half
// of the longest token the server mints.
const unknownLifetimeWindow = 30 * time.Minute

// Session hands out a usable access token, renewing it before it expires.
type Session struct {
	Base   string
	Store  Store
	Creds  *Credentials
	Proofs *dpop.Builder
	HTTP   *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu sync.Mutex
}

func (s *Session) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// renewWindow is how long before expiry a credential's token is renewed: once
// half its lifetime has passed.
//
// HALF, NOT A FEW MINUTES. The server renews only a token that is still valid,
// so a token that expires between two commands cannot be renewed at all and the
// next command asks for a sign-in. A window of the last two minutes of an hour
// meant access effectively ended after the first hour for anyone whose commands
// did not happen to land in those two minutes. Renewing from the half-way point
// keeps a person who runs a command at least every half hour signed in for the
// authorization's whole lifetime.
func renewWindow(c *Credentials) time.Duration {
	window := unknownLifetimeWindow
	if !c.IssuedAt.IsZero() && c.ExpiresAt.After(c.IssuedAt) {
		window = c.ExpiresAt.Sub(c.IssuedAt) / 2
	}
	return max(window, RenewFloor)
}

// renewable reports whether renewal could extend the token at all. A token that
// already ends when its authorization does cannot: the server caps every token
// at the authorization's lifetime.
func renewable(c *Credentials) bool { return c.ExpiresAt.Before(c.AuthorizationExpiresAt) }

// Token returns the access token to present on the next request.
//
// Renewal needs a token that is STILL VALID — the server verifies the one it is
// renewing — so a token that already expired (a laptop that slept through it)
// cannot be renewed and asks for a sign-in instead. And no renewal reaches past
// the authorization's own lifetime: past that point the browser has to approve
// again, which is where Clerk re-decides whether this person still has access.
//
// A renewal that fails for any reason other than the credential itself — the
// network, a server that is briefly unavailable — does not throw away a token
// that is still good: the request goes ahead with it, and the next command
// tries again.
//
// A renewed credential is saved, and saving it does NOT make its instance the
// current one. Only `login` changes which instance an unflagged command acts
// on; a renewal for `--instance` is not a choice of default.
func (s *Session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	c := s.Creds
	if !now.Before(c.AuthorizationExpiresAt) {
		return "", LoginRequired("this computer's authorization has reached its maximum lifetime")
	}
	if !now.Before(c.ExpiresAt) {
		return "", LoginRequired("the session expired")
	}
	if c.ExpiresAt.Sub(now) > renewWindow(c) || !renewable(c) {
		return c.AccessToken, nil
	}

	renewCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := renewToken(renewCtx, s.HTTP, s.Base, s.Proofs, c.AccessToken)
	if err != nil {
		if needsLogin(err) {
			return "", LoginRequiredBy("the session could not be renewed", err)
		}
		return c.AccessToken, nil
	}
	fresh, err := resp.credentials(s.Base, c.KeyThumbprint, now)
	if err != nil {
		return c.AccessToken, nil
	}
	if fresh.InstanceID != c.InstanceID {
		return "", LoginRequired("the renewed session named a different instance")
	}
	// Persisting is best effort: the fresh token is usable either way, and a
	// failed write only means the next command renews again.
	_ = s.Store.Save(fresh)
	s.Creds = fresh
	return fresh.AccessToken, nil
}

// ReconnectBy is when a long-lived stream should be closed and reopened so that
// the request reopening it renews the token rather than finding it expired:
// RenewFloor before expiry, which is inside every renewal window. False when
// renewal cannot extend the token, and the stream should run until the server
// ends it.
func (s *Session) ReconnectBy() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !renewable(s.Creds) {
		return time.Time{}, false
	}
	return s.Creds.ExpiresAt.Add(-RenewFloor), true
}
