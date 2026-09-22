// Package httpclient builds the HTTP clients this binary sends credentials
// with.
package httpclient

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrRedirect is the error every refused redirect wraps.
var ErrRedirect = errors.New("refused to follow a redirect")

// NoRedirects returns a copy of c — or, when c is nil, a new client with the
// given timeout — that refuses every redirect.
//
// A followed redirect carries the request's headers to wherever it points. Go
// drops Authorization when the host changes, but keeps it for the same host or
// a subdomain, and never drops the DPoP proof. Nothing this binary calls
// redirects, so a redirect means the request reached something other than the
// API it was signed for; it is reported, not followed.
func NoRedirects(c *http.Client, timeout time.Duration) *http.Client {
	out := &http.Client{Timeout: timeout}
	if c != nil {
		clone := *c
		out = &clone
	}
	out.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("%w: the server sent this request on to %s", ErrRedirect, req.URL.Redacted())
	}
	return out
}
