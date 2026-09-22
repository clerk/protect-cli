package auth

import (
	"context"
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/style"
)

// Key is what sign-in needs from the device key.
type Key interface {
	crypto.Signer
	Thumbprint() string
}

// LoginOptions configures one sign-in.
type LoginOptions struct {
	APIBase       string
	Key           Key
	ClientVersion string
	DeviceName    string
	// OpenBrowser opens the authorization page. Nil prints the URL only.
	OpenBrowser func(string) error
	Out         io.Writer
	// Style colours the prompt written to Out; the zero value colours nothing.
	Style      style.Palette
	HTTPClient *http.Client
	// Timeout bounds the wait for the browser. Zero means five minutes.
	Timeout time.Duration
}

const (
	clientName          = "clerk-protect"
	defaultLoginTimeout = 5 * time.Minute
)

// SanitizeLabel reduces a self-reported label — a hostname, a version — to what
// the server accepts: printable ASCII, at most 64 characters. The approval page
// shows it to a person, so it must not carry a newline or a control character
// that could make it read as something it is not.
func SanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 64 {
		out = strings.TrimSpace(out[:64])
	}
	return out
}

// AuthorizeURL is the browser page that asks a person to approve this machine.
func AuthorizeURL(base, redirect, state, challenge, jkt, version, device string) string {
	v := url.Values{}
	v.Set("cli_authorize", "1")
	v.Set("redirect_uri", redirect)
	v.Set("state", state)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	v.Set("dpop_jkt", jkt)
	v.Set("client_name", clientName)
	v.Set("client_version", SanitizeLabel(version))
	v.Set("device_name", SanitizeLabel(device))
	return base + "/?" + v.Encode()
}

type callbackResult struct {
	code string
	err  error
}

// Login runs the browser authorization and exchanges its code for a token.
//
// The shape is RFC 8252's native-app flow with PKCE, bound to the device key at
// authorization time:
//
//  1. listen on 127.0.0.1, on a port the operating system picks;
//  2. open the approval page, naming that loopback address, a random state, the
//     PKCE challenge and this key's thumbprint;
//  3. receive the code on the loopback listener, and only with the state this
//     process generated;
//  4. redeem it with the verifier and a proof signed by the key.
//
// A code delivered anywhere else, or redeemed by anything else, is worthless:
// the listener is on this machine, and the verifier and key never left this
// process.
func Login(ctx context.Context, o LoginOptions) (*Credentials, error) {
	if o.Key == nil {
		return nil, errors.New("login: no device key")
	}
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultLoginTimeout
	}
	proofs, err := dpop.NewBuilder(o.Key)
	if err != nil {
		return nil, err
	}
	state, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := NewPKCE()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for the browser's reply on this computer: %w", err)
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)

	results := make(chan callbackResult, 1)
	srv := &http.Server{
		Handler:           callbackHandler(state, results),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	authorize := AuthorizeURL(o.APIBase, redirect, state, challenge, o.Key.Thumbprint(), o.ClientVersion, o.DeviceName)
	_, _ = fmt.Fprintf(out, "To approve this computer, open:\n\n  %s\n\n", o.Style.Emphasis(authorize))
	_, _ = fmt.Fprintf(out, "Approve only if the page shows this key fingerprint: %s\n\n", o.Style.Emphasis(dpop.Fingerprint(o.Key.Thumbprint())))
	if o.OpenBrowser != nil {
		if err := o.OpenBrowser(authorize); err != nil {
			_, _ = fmt.Fprintf(out, "(Could not open a browser: %v. Open the address above yourself.)\n\n", err)
		}
	}
	_, _ = fmt.Fprintln(out, o.Style.Muted("Waiting for the browser…"))

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var res callbackResult
	select {
	case res = <-results:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("no approval arrived within %s", timeout)
	}
	if res.err != nil {
		return nil, res.err
	}

	exchangeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	token, err := exchangeCode(exchangeCtx, o.HTTPClient, o.APIBase, proofs, res.code, verifier, redirect)
	if err != nil {
		// A spent or expired code, or an approval past its lifetime, is fixed by
		// approving again — the sign-in exit code — not by retrying the request.
		if needsLogin(err) {
			return nil, LoginRequiredBy("the sign-in could not be completed", err)
		}
		return nil, fmt.Errorf("complete the sign-in: %w", err)
	}
	return token.credentials(o.APIBase, o.Key.Thumbprint(), time.Now())
}

// callbackHandler receives the browser's redirect.
//
// A request without THIS process's state is refused and does not end the wait:
// anything on this machine can reach a loopback port, and a page that guessed
// the port must not be able to cancel a sign-in, let alone complete one.
func callbackHandler(state string, results chan<- callbackResult) http.Handler {
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// The address bar holds the code for a moment; keep it out of any
		// Referer the page might send.
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "This reply does not belong to the sign-in waiting on this computer.", http.StatusBadRequest)
			return
		}

		var res callbackResult
		switch e := q.Get("error"); {
		case e == "access_denied":
			res.err = ErrAccessDenied
		case e != "":
			res.err = fmt.Errorf("the authorization failed: %s", SanitizeLabel(e))
		case q.Get("code") == "":
			http.Error(w, "The reply carried no authorization code.", http.StatusBadRequest)
			return
		default:
			res.code = q.Get("code")
		}

		delivered := false
		once.Do(func() {
			results <- res
			delivered = true
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case !delivered:
			_, _ = io.WriteString(w, page("Already done", "This sign-in has already been completed. You can close this tab."))
		case res.err != nil:
			_, _ = io.WriteString(w, page("Not approved", "The command line was not approved. You can close this tab."))
		default:
			_, _ = io.WriteString(w, page("Approved", "Return to your terminal to finish signing in. You can close this tab."))
		}
	})
	return mux
}

func page(title, message string) string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(title) +
		"</title></head><body style=\"font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem\"><h1>" +
		html.EscapeString(title) + "</h1><p>" + html.EscapeString(message) + "</p></body></html>"
}
