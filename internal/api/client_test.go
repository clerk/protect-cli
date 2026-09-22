package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/httpclient"
	"github.com/clerk/protect-cli/internal/httperr"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func newClient(t *testing.T, srv *httptest.Server) (*Client, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := dpop.NewBuilder(key)
	if err != nil {
		t.Fatal(err)
	}
	thumb, _ := dpop.Thumbprint(&key.PublicKey)
	return &Client{Base: srv.URL, Tokens: staticToken("tok"), Proofs: proofs, UserAgent: "clerk-protect/test"}, thumb
}

// verifying mirrors the server's device-token check: DPoP scheme, a proof for
// this method and for origin + ESCAPED path with no query, bound to the token.
func verifying(t *testing.T, base *string, thumb *string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
		if !ok || token != "tok" {
			http.Error(w, "labs session required", http.StatusUnauthorized)
			return
		}
		v, err := dpop.Verify(r.Header.Get("DPoP"), r.Method, *base+r.URL.EscapedPath(), token, time.Minute)
		if err != nil || v.Thumbprint != *thumb {
			t.Errorf("proof refused for %s %s: %v", r.Method, r.URL.EscapedPath(), err)
			http.Error(w, "labs session required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func TestClient_signsEachRequestForTheExactPathItSends(t *testing.T) {
	var base, thumb string
	var gotPath, gotQuery, gotBody string
	srv := httptest.NewServer(verifying(t, &base, &thumb, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.EscapedPath(), r.URL.RawQuery
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.String()
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	c, th := newClient(t, srv)
	base, thumb = srv.URL, th

	var out struct{ OK bool }
	path := Path("rulesets", "SIGN_IN", "rules", "id with/slash")
	if err := c.JSON(context.Background(), http.MethodPut, path, url.Values{"after": {"x y"}}, map[string]string{"a": "b"}, &out); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !out.OK {
		t.Fatal("response not decoded")
	}
	if gotPath != "/labs/api/rulesets/SIGN_IN/rules/id%20with%2Fslash" {
		t.Fatalf("path %q — an id must stay one escaped segment", gotPath)
	}
	if gotQuery != "after=x+y" || gotBody != `{"a":"b"}` {
		t.Fatalf("query %q body %q", gotQuery, gotBody)
	}
}

func TestClient_aRefusedCredentialIsASignIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "labs session required", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := newClient(t, srv)
	_, err := c.Do(context.Background(), http.MethodGet, Path("me"), nil, nil)
	if !errors.Is(err, auth.ErrLoginRequired) || !strings.Contains(err.Error(), "labs session required") {
		t.Fatalf("err = %v, want ErrLoginRequired carrying the server's text", err)
	}
}

func TestClient_surfacesTheProblemDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"type":"x","title":"invalid rule expression","status":400,"detail":"unknown field at 1:4"}`)
	}))
	defer srv.Close()
	c, _ := newClient(t, srv)
	_, err := c.Do(context.Background(), http.MethodPost, Path("rulesets", "SIGN_IN", "rules"), nil, map[string]string{})
	var he *httperr.Error
	if !errors.As(err, &he) || he.Message != "unknown field at 1:4" || he.Status != 400 {
		t.Fatalf("err = %v", err)
	}
}

func TestClient_streamsEventsUntilStopped(t *testing.T) {
	var base, thumb string
	srv := httptest.NewServer(verifying(t, &base, &thumb, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: status\ndata: {\"n\":1}\n\n: keepalive\n\nevent: decision\ndata: {\"a\":1}\n\nevent: decision\ndata: {\"a\":2}\n\n")
	}))
	defer srv.Close()
	c, th := newClient(t, srv)
	base, thumb = srv.URL, th

	var got []Event
	err := c.Stream(context.Background(), Path("trace"), nil, func(e Event) error {
		got = append(got, e)
		if len(got) == 2 {
			return ErrStop
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(got) != 2 || got[0].Name != "status" || got[1].Name != "decision" || got[1].Data != `{"a":1}` {
		t.Fatalf("events %+v", got)
	}
}

func TestReadEvents(t *testing.T) {
	in := "data: one\ndata: two\n\nevent: closed\r\ndata: {\"reason\":\"session_expired\"}\r\n\r\nevent: partial\ndata: never dispatched"
	var got []Event
	if err := ReadEvents(strings.NewReader(in), func(e Event) error { got = append(got, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (Event{Name: "message", Data: "one\ntwo"}) || got[1].Name != "closed" {
		t.Fatalf("events %+v", got)
	}
}

// No request follows a redirect — not to another host, where Go would drop
// Authorization but keep the proof, and not to the same host, where it would
// keep both.
func TestClient_refusesEveryRedirect(t *testing.T) {
	var elsewhere, sameHost atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/landing":
			sameHost.Add(1)
		case strings.HasSuffix(r.URL.Path, "/me"):
			http.Redirect(w, r, "/landing", http.StatusFound)
		default:
			http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}
	}))
	defer srv.Close()

	// Control: an ordinary client follows both redirects.
	for _, u := range []string{srv.URL + "/labs/api/me", srv.URL + "/labs/api/trace"} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if elsewhere.Load() != 1 || sameHost.Load() != 1 {
		t.Fatalf("control: an ordinary client reached the targets %d and %d times, want 1 and 1", elsewhere.Load(), sameHost.Load())
	}
	elsewhere.Store(0)
	sameHost.Store(0)

	c, _ := newClient(t, srv)
	ctx := context.Background()
	for name, send := range map[string]func() error{
		"Do, same host": func() error {
			_, err := c.Do(ctx, http.MethodGet, Path("me"), nil, nil)
			return err
		},
		"Do, another host": func() error {
			_, err := c.Do(ctx, http.MethodPost, Path("rulesets", "SIGN_IN", "rules"), nil, map[string]string{})
			return err
		},
		"Stream": func() error { return c.Stream(ctx, Path("trace"), nil, func(Event) error { return nil }) },
		"Download": func() error {
			return c.Download(ctx, Path("replay", "r1", "export"), nil, io.Discard)
		},
	} {
		if err := send(); !errors.Is(err, httpclient.ErrRedirect) {
			t.Errorf("%s: err = %v, want a refused redirect", name, err)
		}
	}
	if elsewhere.Load() != 0 || sameHost.Load() != 0 {
		t.Fatalf("redirected requests arrived: %d at another host, %d on the same host", elsewhere.Load(), sameHost.Load())
	}
}

func TestPath(t *testing.T) {
	if got := Path("protections", "sign in"); got != "/labs/api/protections/sign%20in" {
		t.Fatalf("Path = %q", got)
	}
}
