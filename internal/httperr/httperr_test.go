package httperr

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestParse(t *testing.T) {
	cases := []struct {
		name, body  string
		status      int
		wantMessage string
		wantCode    string
	}{
		{
			name:        "problem detail beats title",
			status:      400,
			body:        `{"type":"https://clerk.com/problems/invalid-rule-expression","title":"invalid rule expression","status":400,"detail":"unknown field ip.nope at 1:1"}`,
			wantMessage: "unknown field ip.nope at 1:1",
		},
		{name: "problem title alone", status: 400, body: `{"title":"ruleset limit exceeded","status":400}`, wantMessage: "ruleset limit exceeded"},
		{name: "message envelope", status: 404, body: `{"message":"rule not found","status":404}`, wantMessage: "rule not found"},
		{
			name: "authorization error", status: 400,
			body:        `{"error":"invalid_grant","message":"this authorization code has expired or already been used"}`,
			wantMessage: "this authorization code has expired or already been used", wantCode: "invalid_grant",
		},
		{name: "plain text middleware refusal", status: 401, body: "labs session required\n", wantMessage: "labs session required"},
		{
			name: "the CDN's page for a refusal", status: 404,
			body:        "<!doctype html><html><head><title>Not found</title></head><body>…</body></html>",
			wantMessage: "not found, or not permitted for this sign-in",
		},
		{name: "a proxy's error page", status: 502, body: "<html>Bad Gateway</html>", wantMessage: "the server answered with a web page, not an API response"},
		{
			name: "a CLI refusal", status: 503,
			body:        `{"error":"not_enabled","message":"the customer CLI is not enabled in this environment"}`,
			wantMessage: "the customer CLI is not enabled in this environment", wantCode: "not_enabled",
		},
		{name: "empty body", status: 503, body: "", wantMessage: "HTTP 503"},
		{
			// OSC 52 (write the clipboard), a carriage return, and cursor-up plus
			// erase-line: a message that would overwrite what came before it.
			name: "a message carrying terminal control sequences", status: 400,
			body: mustJSON(map[string]string{
				"error":   "x\x1b[2J",
				"message": "denied\x1b]52;c;ZXZpbA==\x07\x0d\x1b[1A\x1b[2Kok",
			}),
			wantMessage: "denied]52;c;ZXZpbA==[1A[2Kok", wantCode: "x[2J",
		},
		{name: "a raw body carrying them", status: 502, body: "bad\x1b[31m gateway", wantMessage: "bad[31m gateway"},
		{name: "json without a message", status: 500, body: `{"unexpected":true}`, wantMessage: `{"unexpected":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Parse(tc.status, []byte(tc.body))
			if e.Message != tc.wantMessage || e.Code != tc.wantCode || e.Status != tc.status {
				t.Fatalf("Parse = %+v, want message %q code %q", e, tc.wantMessage, tc.wantCode)
			}
		})
	}
}

func TestParse_boundsARawBody(t *testing.T) {
	e := Parse(502, []byte(strings.Repeat("x", 10_000)))
	if len(e.Message) > maxMessage+len("…") {
		t.Fatalf("message is %d bytes", len(e.Message))
	}
}
