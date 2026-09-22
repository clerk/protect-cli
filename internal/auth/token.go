package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/httpclient"
	"github.com/clerk/protect-cli/internal/httperr"
)

const (
	// tokenPath is the code exchange. Outside the API prefix on purpose: it is
	// the one request that arrives before there is a token.
	tokenPath = "/labs/cli/token"
	renewPath = "/labs/api/cli/renew"
)

// UserAgent is sent on every request this package makes. The CLI sets it.
var UserAgent = "clerk-protect"

// TokenResponse is what the exchange and renewal return.
type TokenResponse struct {
	AccessToken            string   `json:"access_token"`
	TokenType              string   `json:"token_type"`
	ExpiresAt              string   `json:"expires_at"`
	AuthorizationExpiresAt string   `json:"authorization_expires_at"`
	InstanceID             string   `json:"instance_id"`
	Subject                string   `json:"subject"`
	Email                  string   `json:"email,omitempty"`
	Scopes                 []string `json:"scopes"`
	GrantID                string   `json:"grant_id"`
}

// credentials turns a token response into a stored credential. receivedAt is
// recorded as the issue time, which renewal measures the token's lifetime from.
func (t *TokenResponse) credentials(base, thumbprint string, receivedAt time.Time) (*Credentials, error) {
	if t.AccessToken == "" || !strings.EqualFold(t.TokenType, "DPoP") {
		return nil, fmt.Errorf("the server returned an unusable token (type %q)", t.TokenType)
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("the server returned an unreadable expiry %q", t.ExpiresAt)
	}
	authExp, err := time.Parse(time.RFC3339, t.AuthorizationExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("the server returned an unreadable authorization expiry %q", t.AuthorizationExpiresAt)
	}
	if !ValidInstanceID(t.InstanceID) {
		return nil, fmt.Errorf("the server returned an unexpected instance id %q", t.InstanceID)
	}
	return &Credentials{
		APIBase:                base,
		InstanceID:             t.InstanceID,
		Subject:                t.Subject,
		Email:                  t.Email,
		Scopes:                 t.Scopes,
		GrantID:                t.GrantID,
		AccessToken:            t.AccessToken,
		IssuedAt:               receivedAt.UTC(),
		ExpiresAt:              exp,
		AuthorizationExpiresAt: authExp,
		KeyThumbprint:          thumbprint,
	}, nil
}

// exchangeCode redeems an authorization code. The proof carries no `ath` —
// there is no token yet — and is signed by the key the code was bound to, which
// is the check the server makes before it mints anything.
func exchangeCode(ctx context.Context, hc *http.Client, base string, proofs *dpop.Builder, code, verifier, redirect string) (*TokenResponse, error) {
	proof, err := proofs.Proof(http.MethodPost, base+tokenPath, "")
	if err != nil {
		return nil, err
	}
	body := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  redirect,
	}
	return postToken(ctx, hc, base+tokenPath, body, map[string]string{"DPoP": proof})
}

// renewToken exchanges a still-valid token for a fresh one with the same
// authorization. It cannot extend the authorization's lifetime; the server caps
// every token at it.
func renewToken(ctx context.Context, hc *http.Client, base string, proofs *dpop.Builder, token string) (*TokenResponse, error) {
	proof, err := proofs.Proof(http.MethodPost, base+renewPath, token)
	if err != nil {
		return nil, err
	}
	return postToken(ctx, hc, base+renewPath, nil, map[string]string{
		"Authorization": "DPoP " + token,
		"DPoP":          proof,
	})
}

func postToken(ctx context.Context, hc *http.Client, u string, body any, headers map[string]string) (*TokenResponse, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Never followed: the proof, and on renewal the token, would go with it.
	resp, err := httpclient.NoRedirects(hc, 30*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, httperr.Parse(resp.StatusCode, data)
	}
	var out TokenResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("the server returned an unreadable token response: %w", err)
	}
	return &out, nil
}
