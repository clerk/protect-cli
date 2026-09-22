package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/httpclient"
)

type testKey struct {
	*ecdsa.PrivateKey
	thumb string
}

func (k testKey) Thumbprint() string { return k.thumb }

func (k testKey) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return k.PrivateKey.Sign(r, d, o)
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := dpop.Thumbprint(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{PrivateKey: priv, thumb: thumb}
}

// fakeServer refuses what the real authorization server refuses: a proof that
// does not verify, a proof for another URL, a key that is not the one the code
// was bound to, a verifier that does not hash to the challenge, a different
// redirect, a spent code.
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	challenge   string
	jkt         string
	redirect    string
	code        string
	spent       bool
	proofThumb  string // the key that signed the last exchange proof
	renewals    atomic.Int32
	tokenErr    string
	tokenStatus int
	tokenTTL    time.Duration
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, code: "code-123", tokenTTL: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /labs/cli/token", f.token)
	mux.HandleFunc("POST /labs/api/cli/renew", f.renew)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) refuse(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func (f *fakeServer) issue(w http.ResponseWriter, token string) {
	now := time.Now()
	_ = json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: token, TokenType: "DPoP",
		ExpiresAt:              now.Add(f.tokenTTL).UTC().Format(time.RFC3339),
		AuthorizationExpiresAt: now.Add(8 * time.Hour).UTC().Format(time.RFC3339),
		InstanceID:             "ins_2abc", Subject: "user_1", Email: "person@example.com",
		Scopes: []string{"protect:rules:read"}, GrantID: "cli_grant",
	})
}

func (f *fakeServer) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenErr != "" {
		status := f.tokenStatus
		if status == 0 {
			status = http.StatusBadRequest
		}
		f.refuse(w, status, f.tokenErr, "refused by the test server")
		return
	}
	v, err := dpop.Verify(r.Header.Get("DPoP"), http.MethodPost, f.srv.URL+"/labs/cli/token", "", time.Minute)
	if err != nil {
		f.refuse(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
		return
	}
	f.proofThumb = v.Thumbprint
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case f.spent || body["code"] != f.code:
		f.refuse(w, http.StatusBadRequest, "invalid_grant", "spent or unknown code")
	case body["grant_type"] != "authorization_code":
		f.refuse(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type")
	case S256(body["code_verifier"]) != f.challenge:
		f.refuse(w, http.StatusBadRequest, "invalid_grant", "pkce")
	case v.Thumbprint != f.jkt:
		f.refuse(w, http.StatusBadRequest, "invalid_grant", "dpop key")
	case body["redirect_uri"] != f.redirect:
		f.refuse(w, http.StatusBadRequest, "invalid_grant", "redirect")
	default:
		f.spent = true
		f.issue(w, "tok-1")
	}
}

func (f *fakeServer) renew(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
	if !ok {
		f.refuse(w, http.StatusUnauthorized, "invalid_token", "a device token is required")
		return
	}
	if _, err := dpop.Verify(r.Header.Get("DPoP"), http.MethodPost, f.srv.URL+"/labs/api/cli/renew", token, time.Minute); err != nil {
		f.refuse(w, http.StatusUnauthorized, "invalid_token", "the device token was not accepted")
		return
	}
	f.renewals.Add(1)
	f.issue(w, "tok-renewed")
}

// browser simulates the approval page: it reads the authorization URL the CLI
// opened, records what the server would store at approval, and redirects to the
// loopback address with the given query.
func (f *fakeServer) browser(t *testing.T, reply func(redirect, state string) []string) func(string) error {
	return func(authorize string) error {
		u, err := url.Parse(authorize)
		if err != nil {
			return err
		}
		q := u.Query()
		if q.Get("cli_authorize") != "1" || q.Get("code_challenge_method") != "S256" || q.Get("client_name") != "clerk-protect" {
			t.Errorf("authorization URL is missing required parameters: %s", authorize)
		}
		f.mu.Lock()
		f.challenge, f.jkt, f.redirect = q.Get("code_challenge"), q.Get("dpop_jkt"), q.Get("redirect_uri")
		f.mu.Unlock()
		go func() {
			for _, query := range reply(q.Get("redirect_uri"), q.Get("state")) {
				resp, err := http.Get(q.Get("redirect_uri") + "?" + query)
				if err == nil {
					_ = resp.Body.Close()
				}
			}
		}()
		return nil
	}
}

func approve(f *fakeServer, t *testing.T) func(string) error {
	return f.browser(t, func(_, state string) []string {
		return []string{"code=code-123&state=" + url.QueryEscape(state)}
	})
}

func TestLogin_completesAgainstAServerThatChecksEveryBinding(t *testing.T) {
	f := newFakeServer(t)
	key := newTestKey(t)
	before := time.Now()
	creds, err := Login(context.Background(), LoginOptions{
		APIBase: f.srv.URL, Key: key, ClientVersion: "1.2.3", DeviceName: "laptop\nevil",
		OpenBrowser: approve(f, t),
		Timeout:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if creds.AccessToken != "tok-1" || creds.InstanceID != "ins_2abc" || creds.KeyThumbprint != key.thumb {
		t.Fatalf("credentials %+v", creds)
	}
	if creds.IssuedAt.Before(before.Add(-time.Second)) || creds.IssuedAt.After(time.Now()) {
		t.Fatalf("issued_at %v was not recorded at receipt", creds.IssuedAt)
	}
	if f.jkt != key.thumb {
		t.Fatalf("the authorization named key %q, want this key %q", f.jkt, key.thumb)
	}
	if !strings.HasPrefix(f.redirect, "http://127.0.0.1:") || !strings.HasSuffix(f.redirect, "/callback") {
		t.Fatalf("redirect %q is not a loopback callback", f.redirect)
	}
}

// Anything on this machine can reach the loopback port. A reply without the
// state must neither complete nor cancel the sign-in.
func TestLogin_ignoresAReplyWithTheWrongState(t *testing.T) {
	f := newFakeServer(t)
	var wrongStatus atomic.Int32
	creds, err := Login(context.Background(), LoginOptions{
		APIBase: f.srv.URL, Key: newTestKey(t),
		OpenBrowser: func(authorize string) error {
			u, _ := url.Parse(authorize)
			q := u.Query()
			f.mu.Lock()
			f.challenge, f.jkt, f.redirect = q.Get("code_challenge"), q.Get("dpop_jkt"), q.Get("redirect_uri")
			f.mu.Unlock()
			go func() {
				for _, query := range []string{
					"code=code-123&state=not-the-state",
					"error=access_denied&state=not-the-state",
				} {
					resp, err := http.Get(q.Get("redirect_uri") + "?" + query)
					if err == nil {
						wrongStatus.Store(int32(resp.StatusCode))
						_ = resp.Body.Close()
					}
				}
				resp, err := http.Get(q.Get("redirect_uri") + "?code=code-123&state=" + url.QueryEscape(q.Get("state")))
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Login: %v — a wrong-state reply ended the wait", err)
	}
	if creds.AccessToken != "tok-1" {
		t.Fatalf("credentials %+v", creds)
	}
	if wrongStatus.Load() != http.StatusBadRequest {
		t.Fatalf("a wrong-state reply got HTTP %d, want 400", wrongStatus.Load())
	}
}

func TestLogin_reportsADenial(t *testing.T) {
	f := newFakeServer(t)
	_, err := Login(context.Background(), LoginOptions{
		APIBase: f.srv.URL, Key: newTestKey(t),
		OpenBrowser: f.browser(t, func(_, state string) []string {
			return []string{"error=access_denied&state=" + url.QueryEscape(state)}
		}),
		Timeout: 10 * time.Second,
	})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied", err)
	}
}

// An exchange refused because the approval itself is no good — a spent or
// expired code, an authorization past its lifetime, a token the server will not
// accept — is fixed by approving again, so it is a sign-in error (the CLI's exit
// 3). A refusal that approving again would not fix is not.
func TestLogin_anExchangeRefusalIsASignInOnlyWhenApprovingAgainFixesIt(t *testing.T) {
	cases := []struct {
		status    int
		code      string
		wantLogin bool
	}{
		{http.StatusBadRequest, "invalid_grant", true},
		{http.StatusUnauthorized, "authorization_expired", true},
		{http.StatusUnauthorized, "invalid_token", true},
		{http.StatusBadRequest, "invalid_request", false},
		{http.StatusServiceUnavailable, "temporarily_unavailable", false},
		{http.StatusServiceUnavailable, "not_enabled", false},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			f := newFakeServer(t)
			f.tokenErr, f.tokenStatus = tc.code, tc.status
			creds, err := Login(context.Background(), LoginOptions{
				APIBase: f.srv.URL, Key: newTestKey(t), OpenBrowser: approve(f, t), Timeout: 10 * time.Second,
			})
			if err == nil || creds != nil {
				t.Fatalf("Login = %+v, %v; want a refusal", creds, err)
			}
			if errors.Is(err, ErrLoginRequired) != tc.wantLogin {
				t.Fatalf("errors.Is(err, ErrLoginRequired) = %v, want %v: %v", !tc.wantLogin, tc.wantLogin, err)
			}
			if !strings.Contains(err.Error(), "refused by the test server") {
				t.Fatalf("err = %v, want the server's message", err)
			}
		})
	}
}

// The CLI signs the exchange with the key it named in the authorization, and a
// refusal leaves it with no credential. The server here remembers a different
// key, as it would for a code approved for another machine.
func TestLogin_signsTheExchangeWithTheKeyItNamedAndKeepsNothingWhenRefused(t *testing.T) {
	f := newFakeServer(t)
	key, other := newTestKey(t), newTestKey(t)
	creds, err := Login(context.Background(), LoginOptions{
		APIBase: f.srv.URL, Key: key,
		OpenBrowser: func(authorize string) error {
			if err := approve(f, t)(authorize); err != nil {
				return err
			}
			f.mu.Lock()
			f.jkt = other.thumb
			f.mu.Unlock()
			return nil
		},
		Timeout: 10 * time.Second,
	})
	if creds != nil || !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Login = %+v, %v; want no credential and a sign-in error", creds, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.proofThumb != key.thumb {
		t.Fatalf("the exchange proof was signed by %q, want the CLI's own key %q", f.proofThumb, key.thumb)
	}
}

func TestLogin_givesUpAfterTheTimeout(t *testing.T) {
	f := newFakeServer(t)
	_, err := Login(context.Background(), LoginOptions{
		APIBase: f.srv.URL, Key: newTestKey(t),
		OpenBrowser: func(string) error { return nil },
		Timeout:     200 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "no approval arrived") {
		t.Fatalf("err = %v", err)
	}
}

// Neither the code exchange nor a renewal follows a redirect: the proof, and on
// renewal the token, would go with it.
func TestTokenRequests_refuseToFollowARedirect(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	// Control: an ordinary client does follow this redirect, so the counts below
	// mean something.
	resp, err := http.Post(redirecting.URL+"/labs/cli/token", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if elsewhere.Load() != 1 {
		t.Fatalf("control: an ordinary client reached the redirect target %d times, want 1", elsewhere.Load())
	}
	elsewhere.Store(0)

	proofs, err := dpop.NewBuilder(newTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := exchangeCode(ctx, nil, redirecting.URL, proofs, "code", "verifier", "http://127.0.0.1:1234/callback"); !errors.Is(err, httpclient.ErrRedirect) {
		t.Fatalf("exchange: err = %v, want a refused redirect", err)
	}
	if _, err := renewToken(ctx, nil, redirecting.URL, proofs, "tok"); !errors.Is(err, httpclient.ErrRedirect) {
		t.Fatalf("renew: err = %v, want a refused redirect", err)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("%d request(s) reached the redirect target", n)
	}
}

func TestPKCE(t *testing.T) {
	v, c, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 43 || S256(v) != c || len(c) != 43 {
		t.Fatalf("verifier %q challenge %q", v, c)
	}
	v2, _, _ := NewPKCE()
	if v == v2 {
		t.Fatal("two verifiers were identical")
	}
}

func TestSanitizeLabel(t *testing.T) {
	for in, want := range map[string]string{
		"laptop":                 "laptop",
		"laptop\nrole: admin":    "laptoprole: admin",
		"  spaced  ":             "spaced",
		"héllo":                  "hllo",
		strings.Repeat("a", 100): strings.Repeat("a", 64),
	} {
		if got := SanitizeLabel(in); got != want {
			t.Errorf("SanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// unknownIssue leaves a credential's issue time unrecorded, as one stored by an
// earlier version is.
const unknownIssue = time.Duration(-1)

// sessionFor builds a session whose token was issued issuedAgo ago and expires
// in expiresIn, under an authorization that ends in authorizationIn.
func sessionFor(t *testing.T, f *fakeServer, issuedAgo, expiresIn, authorizationIn time.Duration) *Session {
	t.Helper()
	key := newTestKey(t)
	proofs, err := dpop.NewBuilder(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := &Credentials{
		APIBase: f.srv.URL, InstanceID: "ins_2abc", AccessToken: "tok-1",
		ExpiresAt: now.Add(expiresIn), AuthorizationExpiresAt: now.Add(authorizationIn),
		KeyThumbprint: key.thumb,
	}
	if issuedAgo != unknownIssue {
		c.IssuedAt = now.Add(-issuedAgo)
	}
	return &Session{Base: f.srv.URL, Store: Store{Dir: t.TempDir()}, Creds: c, Proofs: proofs}
}

func TestSession_renewsOnceHalfTheTokensLifetimeHasPassed(t *testing.T) {
	cases := []struct {
		name                 string
		issuedAgo, expiresIn time.Duration
		wantRenewal          bool
	}{
		{"a fresh hour-long token", 10 * time.Minute, 50 * time.Minute, false},
		{"just before half-way", 29 * time.Minute, 31 * time.Minute, false},
		// A window of the last two minutes left this token alone, and the next
		// command after it expired had to sign in again.
		{"past half-way, with 25 minutes left", 35 * time.Minute, 25 * time.Minute, true},
		{"a short token inside the floor", 10 * time.Second, 110 * time.Second, true},
		{"no recorded issue time, 45 minutes left", unknownIssue, 45 * time.Minute, false},
		{"no recorded issue time, 20 minutes left", unknownIssue, 20 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			s := sessionFor(t, f, tc.issuedAgo, tc.expiresIn, 8*time.Hour)
			tok, err := s.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			renewed := f.renewals.Load() == 1
			if renewed != tc.wantRenewal || (tok == "tok-renewed") != tc.wantRenewal {
				t.Fatalf("renewed=%v token=%q, want renewal %v", renewed, tok, tc.wantRenewal)
			}
			if !tc.wantRenewal {
				return
			}
			stored, err := s.Store.Load(f.srv.URL, "ins_2abc")
			if err != nil || stored.AccessToken != "tok-renewed" || stored.IssuedAt.IsZero() {
				t.Fatalf("the renewed token was not stored with its issue time: %+v, %v", stored, err)
			}
		})
	}
}

// A token that already ends with its authorization cannot be extended, so it
// is used until it expires rather than renewed on every command.
func TestSession_doesNotRenewATokenThatEndsWithItsAuthorization(t *testing.T) {
	f := newFakeServer(t)
	s := sessionFor(t, f, 59*time.Minute, time.Minute, time.Minute)
	s.Creds.AuthorizationExpiresAt = s.Creds.ExpiresAt
	if tok, err := s.Token(context.Background()); err != nil || tok != "tok-1" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
	if f.renewals.Load() != 0 {
		t.Fatal("renewed a token that cannot outlive its authorization")
	}
	if _, ok := s.ReconnectBy(); ok {
		t.Fatal("ReconnectBy offered a reconnect that could not renew")
	}
}

func TestSession_reconnectByIsInsideTheRenewalWindow(t *testing.T) {
	f := newFakeServer(t)
	s := sessionFor(t, f, 10*time.Minute, 50*time.Minute, 8*time.Hour)
	at, ok := s.ReconnectBy()
	if !ok || !at.Equal(s.Creds.ExpiresAt.Add(-RenewFloor)) {
		t.Fatalf("ReconnectBy = %v, %v", at, ok)
	}
	if s.Creds.ExpiresAt.Sub(at) > renewWindow(s.Creds) {
		t.Fatal("a stream reconnected at ReconnectBy would not renew")
	}
}

func TestSession_refusesPastTheAuthorizationLifetime(t *testing.T) {
	f := newFakeServer(t)
	s := sessionFor(t, f, 59*time.Minute, time.Minute, -time.Second)
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
	if f.renewals.Load() != 0 {
		t.Fatal("tried to renew past the authorization's lifetime")
	}
}

func TestSession_anExpiredTokenAsksForASignIn(t *testing.T) {
	f := newFakeServer(t)
	s := sessionFor(t, f, time.Hour, -time.Second, 8*time.Hour)
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
}

// A refused renewal is a sign-in; an unreachable server is not, while the token
// still works.
func TestSession_distinguishesARefusalFromAnOutage(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_token","message":"the device token was not accepted"}`)
	}))
	defer refusing.Close()
	f := newFakeServer(t)
	s := sessionFor(t, f, 55*time.Minute, 5*time.Minute, 8*time.Hour)
	s.Base = refusing.URL
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("refused renewal: err = %v, want ErrLoginRequired", err)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	s = sessionFor(t, f, 55*time.Minute, 5*time.Minute, 8*time.Hour)
	s.Base = down.URL
	if tok, err := s.Token(context.Background()); err != nil || tok != "tok-1" {
		t.Fatalf("outage: Token = %q, %v; want the still-valid token", tok, err)
	}
}

// Signing in to B and then A makes A current. Renewing B — as `--instance B`
// does — saves B's new token and leaves A current, so the next command without
// --instance still acts on A.
func TestSession_renewalDoesNotChangeTheCurrentInstance(t *testing.T) {
	f := newFakeServer(t)
	s := sessionFor(t, f, 55*time.Minute, 5*time.Minute, 8*time.Hour)
	b := s.Creds
	a := &Credentials{APIBase: f.srv.URL, InstanceID: "ins_2other", AccessToken: "tok-a", ExpiresAt: time.Now().Add(time.Hour)}
	for _, c := range []*Credentials{b, a} {
		if err := s.Store.Save(c); err != nil {
			t.Fatal(err)
		}
		if err := s.Store.SetCurrent(f.srv.URL, c.InstanceID); err != nil {
			t.Fatal(err)
		}
	}

	if tok, err := s.Token(context.Background()); err != nil || tok != "tok-renewed" {
		t.Fatalf("Token = %q, %v; want a renewal", tok, err)
	}
	if cur, err := s.Store.Current(f.srv.URL); err != nil || cur != "ins_2other" {
		t.Fatalf("current instance is %q after renewing %s, want ins_2other: %v", cur, b.InstanceID, err)
	}
	if stored, err := s.Store.Load(f.srv.URL, b.InstanceID); err != nil || stored.AccessToken != "tok-renewed" {
		t.Fatalf("renewed credential not saved: %+v, %v", stored, err)
	}
}

func TestStore_roundTripCurrentAndRemove(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	base := "https://api.example.test"
	c := &Credentials{APIBase: base, InstanceID: "ins_2abc", AccessToken: "t"}
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(base, ""); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Save alone made the credential current: %v", err)
	}
	if err := s.SetCurrent(base, c.InstanceID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(base, "")
	if err != nil || got.InstanceID != "ins_2abc" {
		t.Fatalf("Load current = %+v, %v", got, err)
	}
	if _, err := s.Load("https://other.example.test", ""); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("another API host saw this credential: %v", err)
	}
	if removed, err := s.Remove(base, ""); err != nil || removed != "ins_2abc" {
		t.Fatalf("Remove = %q, %v", removed, err)
	}
	if _, err := s.Load(base, ""); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Load after Remove: %v", err)
	}
}

// An instance id that is not one is refused before it becomes part of a path,
// and nothing is written anywhere — inside the store or beside it.
func TestStore_refusesAnInstanceThatIsNotAnID(t *testing.T) {
	parent := t.TempDir()
	s := Store{Dir: filepath.Join(parent, "config")}
	base := "https://api.example.test"
	for _, id := range []string{"../../etc/passwd", "../escaped", "ins_", "user_2abc", "ins_2abc/../x", `ins_2abc\..\x`} {
		if err := s.Save(&Credentials{APIBase: base, InstanceID: id}); err == nil {
			t.Errorf("Save accepted instance %q", id)
		}
		if err := s.SetCurrent(base, id); err == nil {
			t.Errorf("SetCurrent accepted instance %q", id)
		}
		if _, err := s.Load(base, id); err == nil {
			t.Errorf("Load accepted instance %q", id)
		}
	}
	if files := filesUnder(t, parent); len(files) != 0 {
		t.Fatalf("refused saves wrote files: %v", files)
	}

	// Control: the walk does see what a valid save writes, and where.
	if err := s.Save(&Credentials{APIBase: base, InstanceID: "ins_2abc"}); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(parent, "config", "credentials", "api.example.test", "ins_2abc.json")
	if files := filesUnder(t, parent); len(files) != 1 || files[0] != want {
		t.Fatalf("a valid save wrote %v, want exactly %s", files, want)
	}
}

func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
