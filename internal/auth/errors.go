// Package auth signs this machine in: the browser authorization, the code
// exchange, the stored credential and its renewal.
package auth

import (
	"errors"

	"github.com/clerk/protect-cli/internal/httperr"
)

// ErrLoginRequired matches every error that only `clerk-protect login` can
// resolve. The CLI maps it to its own exit code, so a script can tell "sign in
// again" from "the request failed".
var ErrLoginRequired = errors.New("sign-in required")

// ErrAccessDenied means the person denied the authorization in the browser.
var ErrAccessDenied = errors.New("the authorization was denied in the browser")

type loginRequiredError struct {
	reason string
	cause  error
}

func (e *loginRequiredError) Error() string {
	if e.cause != nil {
		return e.reason + " (" + e.cause.Error() + ") — run `clerk-protect login`"
	}
	return e.reason + " — run `clerk-protect login`"
}

func (e *loginRequiredError) Is(target error) bool { return target == ErrLoginRequired }

func (e *loginRequiredError) Unwrap() error { return e.cause }

// LoginRequired builds an ErrLoginRequired with a reason a person can act on.
func LoginRequired(reason string) error { return &loginRequiredError{reason: reason} }

// LoginRequiredBy builds an ErrLoginRequired caused by a server refusal, which
// stays reachable through errors.As.
func LoginRequiredBy(reason string, cause error) error {
	return &loginRequiredError{reason: reason, cause: cause}
}

// needsLogin reports whether a server refusal means the credential itself is
// no longer good: rejected outright, past its authorization lifetime, or an
// exchange whose code is spent.
func needsLogin(err error) bool {
	var he *httperr.Error
	if !errors.As(err, &he) {
		return false
	}
	return he.Status == 401 || he.Code == "authorization_expired" || he.Code == "invalid_grant"
}
