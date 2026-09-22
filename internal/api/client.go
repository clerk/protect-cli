// Package api is the HTTP client for the Protect API: every request signed for
// the URL it is sent to, every refusal surfaced in the server's own words.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/httpclient"
	"github.com/clerk/protect-cli/internal/httperr"
)

// Prefix is where every customer API route lives.
const Prefix = "/labs/api"

// maxBody bounds a buffered response. Exports stream instead.
const maxBody = 64 << 20

// TokenSource supplies the access token for the next request.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Client makes signed requests.
type Client struct {
	// Base is the API origin, with no trailing slash and no path.
	Base   string
	Tokens TokenSource
	Proofs *dpop.Builder
	// HTTP serves ordinary requests; nil means a client with a one-minute
	// timeout. Streams serves long-lived ones; nil means no timeout, bounded by
	// the context.
	HTTP      *http.Client
	Streams   *http.Client
	UserAgent string
}

// Path joins escaped segments under the API prefix:
// Path("rulesets", "SIGN_IN", "rules") is /labs/api/rulesets/SIGN_IN/rules.
// Every segment is escaped, so an id containing a slash stays one segment.
func Path(segments ...string) string {
	var b strings.Builder
	b.WriteString(Prefix)
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// Response is a successful, buffered response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, body []byte, accept string) (*http.Request, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("api: path %q must be absolute", path)
	}
	u, err := url.Parse(c.Base + path)
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	token, err := c.Tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	// htu is the origin plus the ESCAPED path, with no query: exactly what the
	// server rebuilds from its own configured origin and the path it received.
	// Signing u.Path instead would break on the first id containing a character
	// that needs escaping.
	proof, err := c.Proofs.Proof(method, c.Base+u.EscapedPath(), token)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	req.Header.Set("Accept", accept)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	return req, nil
}

func encode(in any) ([]byte, error) {
	switch v := in.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		return v, nil
	case []byte:
		return v, nil
	default:
		return json.Marshal(v)
	}
}

// refusal turns a non-2xx response into an error. A 401 is a sign-in: the
// credential was not accepted, and nothing this command can do will change that.
func refusal(status int, body []byte) error {
	he := httperr.Parse(status, body)
	if status == http.StatusUnauthorized {
		return auth.LoginRequiredBy("the server did not accept this computer's credential", he)
	}
	return he
}

// httpClient and streamClient never follow a redirect: every request carries a
// token and a proof, and a redirect would send both on (see httpclient).
func (c *Client) httpClient() *http.Client {
	return httpclient.NoRedirects(c.HTTP, time.Minute)
}

// Do sends a request and buffers the response.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, in any) (*Response, error) {
	body, err := encode(in)
	if err != nil {
		return nil, err
	}
	req, err := c.request(ctx, method, path, query, body, "application/json")
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, refusal(resp.StatusCode, data)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
}

// JSON sends a request and decodes a JSON response into out (which may be nil).
func (c *Client) JSON(ctx context.Context, method, path string, query url.Values, in, out any) error {
	resp, err := c.Do(ctx, method, path, query, in)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(resp.Body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	return nil
}

// Download streams a response body to w without buffering it.
func (c *Client) Download(ctx context.Context, path string, query url.Values, w io.Writer) error {
	req, err := c.request(ctx, http.MethodGet, path, query, nil, "*/*")
	if err != nil {
		return err
	}
	resp, err := c.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return refusal(resp.StatusCode, data)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (c *Client) streamClient() *http.Client {
	return httpclient.NoRedirects(c.Streams, 0)
}

// Stream opens a Server-Sent Events stream and calls fn for each event until the
// stream ends, the context is cancelled, or fn returns an error. ErrStop from fn
// ends the stream without an error.
func (c *Client) Stream(ctx context.Context, path string, query url.Values, fn func(Event) error) error {
	req, err := c.request(ctx, http.MethodGet, path, query, nil, "text/event-stream")
	if err != nil {
		return err
	}
	resp, err := c.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return refusal(resp.StatusCode, data)
	}
	err = ReadEvents(resp.Body, fn)
	if errors.Is(err, ErrStop) {
		return nil
	}
	return err
}
