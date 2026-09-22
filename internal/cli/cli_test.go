package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/keystore"
)

func TestPlanReorder(t *testing.T) {
	cur := []string{"a", "b", "c", "d"}
	cases := []struct {
		name    string
		move    moveSpec
		order   []string
		want    []string
		wantErr bool
	}{
		{name: "top", move: moveSpec{id: "c", top: true}, want: []string{"c", "a", "b", "d"}},
		{name: "bottom", move: moveSpec{id: "a", bottom: true}, want: []string{"b", "c", "d", "a"}},
		{name: "to 2", move: moveSpec{id: "d", to: 2}, want: []string{"a", "d", "b", "c"}},
		{name: "before", move: moveSpec{id: "d", before: "b"}, want: []string{"a", "d", "b", "c"}},
		{name: "after", move: moveSpec{id: "a", after: "c"}, want: []string{"b", "c", "a", "d"}},
		{name: "explicit", order: []string{"d", "c", "b", "a"}, want: []string{"d", "c", "b", "a"}},
		{name: "unknown id", move: moveSpec{id: "zz", top: true}, wantErr: true},
		{name: "two destinations", move: moveSpec{id: "a", top: true, bottom: true}, wantErr: true},
		{name: "no destination", move: moveSpec{id: "a"}, wantErr: true},
		{name: "to out of range", move: moveSpec{id: "a", to: 9}, wantErr: true},
		{name: "explicit missing a rule", order: []string{"a", "b", "c"}, wantErr: true},
		{name: "explicit duplicate", order: []string{"a", "a", "b", "c", "d"}, wantErr: true},
		{name: "explicit unknown", order: []string{"a", "b", "c", "x"}, wantErr: true},
		{name: "both forms", move: moveSpec{id: "a", top: true}, order: cur, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := planReorder(cur, tc.move, tc.order)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("planReorder = %v, want an error", got)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("planReorder = %v, %v; want %v", got, err, tc.want)
			}
			if !slices.Equal(cur, []string{"a", "b", "c", "d"}) {
				t.Fatal("planReorder modified the current order in place")
			}
		})
	}
}

func TestMergeBindings(t *testing.T) {
	existing := []binding{{Name: "threshold", Expression: "5"}, {SubRuleID: "r1", Name: "window", Expression: "PT1H"}}

	got, err := mergeBindings(existing, []string{"threshold=10", "r1:extra=ip.address"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []binding{{Name: "threshold", Expression: "10"}, {SubRuleID: "r1", Name: "window", Expression: "PT1H"}, {SubRuleID: "r1", Name: "extra", Expression: "ip.address"}}
	if !slices.Equal(got, want) {
		t.Fatalf("merge = %+v, want %+v — one --bind must not drop the others", got, want)
	}

	got, err = mergeBindings(existing, nil, []string{"r1:window"}, false)
	if err != nil || len(got) != 1 || got[0].Name != "threshold" {
		t.Fatalf("unbind = %+v, %v", got, err)
	}

	got, err = mergeBindings(existing, []string{"only=1"}, nil, true)
	if err != nil || len(got) != 1 {
		t.Fatalf("replace = %+v, %v", got, err)
	}

	for _, bad := range []string{"noequals", "=x", "name=", ":name=x", "sub:=x"} {
		if _, err := mergeBindings(nil, []string{bad}, nil, false); err == nil {
			t.Errorf("--bind %q was accepted", bad)
		}
	}
	if _, err := mergeBindings(existing, nil, []string{"missing"}, false); err == nil {
		t.Error("--unbind of a binding that does not exist was accepted")
	}
}

func TestInsightsBody(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	newCmd := func(args ...string) (*cobra.Command, *insightsQuery) {
		q := &insightsQuery{}
		cmd := &cobra.Command{Use: "x"}
		q.register(cmd)
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		return cmd, q
	}
	noFile := func(string) (json.RawMessage, error) { return nil, errors.New("no file") }

	cmd, q := newCmd("--since", "2h", "--filter", "country=US,CA", "--exclude", "action=allow", "--unit", "flows")
	body, err := q.body(cmd, now, noFile)
	if err != nil {
		t.Fatal(err)
	}
	if body["from"] != "2026-09-14T10:00:00Z" || body["to"] != "2026-09-14T12:00:00Z" || body["unit"] != "flows" {
		t.Fatalf("body %v", body)
	}
	raw, _ := json.Marshal(body["filter"])
	if string(raw) != `[{"dimension":"country","op":"in","values":["US","CA"]},{"dimension":"action","op":"not_in","values":["allow"]}]` {
		t.Fatalf("filter %s", raw)
	}

	// A body given as JSON keeps its window unless a window flag was given.
	cmd, q = newCmd("--query", `{"from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z","filter":[{"dimension":"a","op":"in","values":["b"]}]}`, "--filter", "c=d")
	body, err = q.body(cmd, now, noFile)
	if err != nil {
		t.Fatal(err)
	}
	if body["from"] != "2026-01-01T00:00:00Z" || len(body["filter"].([]any)) != 2 {
		t.Fatalf("body %v", body)
	}

	cmd, q = newCmd("--from", "2026-09-14T12:00:00Z", "--to", "2026-09-14T11:00:00Z")
	if _, err := q.body(cmd, now, noFile); err == nil {
		t.Fatal("an empty window was accepted")
	}
}

func TestSparkline(t *testing.T) {
	if got := sparkline([]int64{0, 1, 8, 4, 0}); got != " ▁█▄ " {
		t.Fatalf("sparkline = %q", got)
	}
	if got := sparkline([]int64{0, 0}); got != "  " {
		t.Fatalf("all-zero sparkline = %q", got)
	}
}

func TestCodeFor(t *testing.T) {
	if codeFor(auth.LoginRequired("x")) != ExitAuth {
		t.Error("a sign-in error is not ExitAuth")
	}
	if codeFor(usageError("x")) != ExitUsage {
		t.Error("a usage error is not ExitUsage")
	}
	if codeFor(errors.New(`unknown command "nope" for "clerk-protect"`)) != ExitUsage {
		t.Error("an unknown command is not ExitUsage")
	}
	if codeFor(errors.New("boom")) != ExitError {
		t.Error("an ordinary error is not ExitError")
	}
}

// A decision field is whatever the client sent — a user agent can carry an
// escape sequence — and a trace line must print it as text.
func TestDecisionLine_escapesControlSequencesInFieldsAndKeys(t *testing.T) {
	line := decisionLine(map[string]any{
		"ip":            "1.2.3.4",
		"ua":            "curl\x1b]52;c;ZXZpbA==\x07",
		"note":          "two\nlines",
		"odd\x1b[2Jkey": "x",
	}, nil)
	if strings.ContainsAny(line, "\x1b\x07\n") {
		t.Fatalf("the decision line carries control characters: %q", line)
	}
	for _, want := range []string{"ip=1.2.3.4", `ua="curl\x1b]52;c;ZXZpbA==\a"`, `note="two\nlines"`, "odd[2Jkey=x"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %s", line, want)
		}
	}
}

// --- against a server that verifies every proof ----------------------------

const instanceA = "ins_2abc"

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

type fakeAPI struct {
	t     *testing.T
	srv   *httptest.Server
	mux   *http.ServeMux
	thumb string
	dir   string

	mu       sync.Mutex
	calls    []string
	posts    map[string]json.RawMessage
	tokens   map[string]string // access token → the instance it was issued for
	renewals int
}

func (f *fakeAPI) json(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

func (f *fakeAPI) token(r *http.Request) string {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
	return tok
}

func (f *fakeAPI) record(r *http.Request) {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	f.mu.Lock()
	f.posts[r.Method+" "+r.URL.Path] = buf.Bytes()
	f.mu.Unlock()
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, mux: http.NewServeMux(), posts: map[string]json.RawMessage{}, tokens: map[string]string{"tok": instanceA}}
	f.mux.HandleFunc("GET /labs/api/me", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		instance := f.tokens[f.token(r)]
		f.mu.Unlock()
		f.json(w, 200, mustJSON(map[string]any{
			"instance_id": instance, "subject": "user_1", "email": "person@example.com",
			"scopes": []string{"protect:rules:read"}, "credential": "device_token",
		}))
	})
	f.mux.HandleFunc("POST /labs/api/cli/renew", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.renewals++
		instance := f.tokens[f.token(r)]
		fresh := fmt.Sprintf("tok-renewed-%d", f.renewals)
		f.tokens[fresh] = instance
		f.mu.Unlock()
		now := time.Now()
		f.json(w, 200, mustJSON(auth.TokenResponse{
			AccessToken: fresh, TokenType: "DPoP", InstanceID: instance, Subject: "user_1", GrantID: "cli_grant",
			ExpiresAt:              now.Add(time.Hour).UTC().Format(time.RFC3339),
			AuthorizationExpiresAt: now.Add(7 * time.Hour).UTC().Format(time.RFC3339),
		}))
	})
	f.mux.HandleFunc("GET /labs/api/rulesets/SIGN_IN/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			f.json(w, 200, `{"rules":[{"id":"r1","expression":"ip.address == \"1.2.3.4\"","action":"BLOCK"}],"nextPageToken":"p2"}`)
			return
		}
		f.json(w, 200, `{"rules":[{"id":"r2","expression":"true","action":"CHALLENGE","disabled":true}],"nextPageToken":null}`)
	})
	f.mux.HandleFunc("POST /labs/api/rulesets/SIGN_IN/rules", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.json(w, 200, `{"id":"r9","expression":"true","action":"BLOCK"}`)
	})
	f.mux.HandleFunc("POST /labs/api/rulesets/SIGN_IN/rules/validate", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.json(w, 200, `{"valid":false,"errors":[{"field":"expression","message":"unknown field nope"}]}`)
	})
	f.mux.HandleFunc("GET /labs/api/protections", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, 200, `{"protections":[{"protection":{"name":"sign_in_captcha","version":3},"activation":{"id":"a1","protectionName":"sign_in_captcha","protectionVersion":3,"bindings":[{"name":"threshold","expression":"5"}],"disabled":true}}]}`)
	})
	f.mux.HandleFunc("POST /labs/api/protections/sign_in_captcha/enable", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.json(w, 200, `{"id":"a1","protectionName":"sign_in_captcha","protectionVersion":3,"disabled":false}`)
	})

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		_, known := f.tokens[f.token(r)]
		f.mu.Unlock()
		// The code exchange is the one request that carries no token yet.
		if r.URL.Path == "/labs/cli/token" {
			f.mux.ServeHTTP(w, r)
			return
		}
		if !known {
			f.json(w, 401, `{"error":"invalid_token","message":"the device token was not accepted"}`)
			return
		}
		v, err := dpop.Verify(r.Header.Get("DPoP"), r.Method, f.srv.URL+r.URL.EscapedPath(), f.token(r), time.Minute)
		if err != nil || v.Thumbprint != f.thumb {
			t.Errorf("%s %s: proof refused: %v", r.Method, r.URL.Path, err)
			f.json(w, 401, `{"error":"invalid_token","message":"the device token was not accepted"}`)
			return
		}
		f.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// signIn gives the test a device key and a current credential for instance A,
// in a temporary configuration directory.
func (f *fakeAPI) signIn(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses the key file backend, which is refused on Windows")
	}
	f.dir = t.TempDir()
	t.Setenv(config.EnvConfigDir, f.dir)
	t.Setenv(config.EnvAPIURL, "")
	clearProfileEnv(t)
	t.Setenv(keystore.EnvKeyBackend, "file")
	dev, _, err := keystore.OpenOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	f.thumb = dev.Thumbprint()
	f.storeCredential(t, instanceA, "tok", 10*time.Minute, 50*time.Minute, true)
}

// storeCredential stores a credential issued issuedAgo ago that expires in
// expiresIn, making it current when current is set — as signing in does.
func (f *fakeAPI) storeCredential(t *testing.T, instance, token string, issuedAgo, expiresIn time.Duration, current bool) {
	t.Helper()
	f.mu.Lock()
	f.tokens[token] = instance
	f.mu.Unlock()
	now := time.Now()
	st := auth.Store{Dir: f.dir}
	if err := st.Save(&auth.Credentials{
		APIBase: f.srv.URL, InstanceID: instance, Subject: "user_1", AccessToken: token,
		IssuedAt: now.Add(-issuedAgo), ExpiresAt: now.Add(expiresIn), AuthorizationExpiresAt: now.Add(8 * time.Hour),
		KeyThumbprint: f.thumb,
	}); err != nil {
		t.Fatal(err)
	}
	if current {
		if err := st.SetCurrent(f.srv.URL, instance); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fakeAPI) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"--api-url", f.srv.URL}, args...), strings.NewReader(""), &out, &errOut, func() bool { return false })
	return code, out.String(), errOut.String()
}

func (f *fakeAPI) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestCommands_whoamiAndPagedRuleList(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)

	code, out, errOut := f.run(t, "whoami", "--json")
	if code != ExitOK || !strings.Contains(out, `"instance_id": "ins_2abc"`) {
		t.Fatalf("whoami: code %d out %s err %s", code, out, errOut)
	}

	code, out, errOut = f.run(t, "rules", "list", "--ruleset", "SIGN_IN", "--json")
	if code != ExitOK {
		t.Fatalf("rules list: code %d err %s", code, errOut)
	}
	var blocks []struct {
		Rules []struct{ ID string } `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &blocks); err != nil || len(blocks) != 1 || len(blocks[0].Rules) != 2 {
		t.Fatalf("rules list did not follow the second page: %s (%v)", out, err)
	}

	code, out, _ = f.run(t, "rules", "list", "--ruleset", "SIGN_IN")
	if code != ExitOK || !strings.Contains(out, "#2  r2  CHALLENGE  [disabled]") {
		t.Fatalf("human rules list: %s", out)
	}
}

// Every mutation requires --yes when stdin is not a terminal. The
// refusal comes before the first request, so a script that forgot --yes sends
// nothing at all, and leaves this computer's state as it was.
func TestCommands_everyMutationRefusesWithoutYesWhenNotInteractive(t *testing.T) {
	replayFile := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(replayFile, []byte(`{"name":"candidate"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		args  []string
		local bool // changes only this computer
	}{
		{"rules create", []string{"rules", "create", "--ruleset", "SIGN_IN", "--expression", "true", "--action", "block"}, false},
		{"rules update", []string{"rules", "update", "r1", "--ruleset", "SIGN_IN", "--description", "changed"}, false},
		{"rules enable", []string{"rules", "enable", "r1", "--ruleset", "SIGN_IN"}, false},
		{"rules disable", []string{"rules", "disable", "r1", "--ruleset", "SIGN_IN"}, false},
		{"rules delete", []string{"rules", "delete", "r1", "--ruleset", "SIGN_IN"}, false},
		{"rules reorder", []string{"rules", "reorder", "--ruleset", "SIGN_IN", "--move", "r2", "--top"}, false},
		{"protections enable", []string{"protections", "enable", "sign_in_captcha"}, false},
		{"protections disable", []string{"protections", "disable", "sign_in_captcha"}, false},
		{"protections bindings", []string{"protections", "bindings", "sign_in_captcha", "--bind", "threshold=6"}, false},
		{"protections reset", []string{"protections", "reset", "sign_in_captcha"}, false},
		{"replay create", []string{"replay", "create", "--file", replayFile}, false},
		{"replay apply", []string{"replay", "apply", "rep_1"}, false},
		{"logout --all", []string{"logout", "--all"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			code, _, errOut := f.run(t, tc.args...)
			if code != ExitUsage || !strings.Contains(errOut, "--yes") {
				t.Fatalf("without --yes: code %d, stderr %q; want exit 2 naming --yes", code, errOut)
			}
			if n := f.callCount(); n != 0 {
				t.Fatalf("without --yes, %d request(s) reached the server: %v", n, f.calls)
			}
			if _, err := os.Stat(filepath.Join(f.dir, "credentials")); err != nil {
				t.Fatalf("without --yes, the stored sign-ins changed: %v", err)
			}

			// Control: with --yes the same command acts, so the refusal above was the
			// consent check and not a command that never worked.
			code, _, errOut = f.run(t, append([]string{"--yes"}, tc.args...)...)
			if tc.local {
				if _, err := os.Stat(filepath.Join(f.dir, "credentials")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("control: with --yes the sign-ins were not removed (code %d, %s)", code, errOut)
				}
				return
			}
			if f.callCount() == 0 {
				t.Fatalf("control: with --yes no request was sent (code %d, %s)", code, errOut)
			}
		})
	}
}

// Signing out of one instance removes local state only, so it needs no --yes.
func TestCommands_singleInstanceLogoutNeedsNoYes(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	if code, _, errOut := f.run(t, "logout"); code != ExitOK {
		t.Fatalf("logout: code %d, %s", code, errOut)
	}
	if _, err := (auth.Store{Dir: f.dir}).Load(f.srv.URL, instanceA); !errors.Is(err, auth.ErrLoginRequired) {
		t.Fatalf("the sign-in is still stored: %v", err)
	}
}

func TestCommands_invalidRuleExitsOne(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	code, out, _ := f.run(t, "rules", "validate", "--ruleset", "SIGN_IN", "nope == 1")
	if code != ExitError || !strings.Contains(out, "unknown field nope") {
		t.Fatalf("code %d out %s", code, out)
	}
}

func TestCommands_enableKeepsTheOtherBindings(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	code, _, errOut := f.run(t, "--yes", "protections", "enable", "sign_in_captcha", "--bind", "window=PT1H")
	if code != ExitOK {
		t.Fatalf("code %d err %s", code, errOut)
	}
	var body struct {
		Version  int       `json:"version"`
		Bindings []binding `json:"bindings"`
	}
	if err := json.Unmarshal(f.posts["POST /labs/api/protections/sign_in_captcha/enable"], &body); err != nil {
		t.Fatal(err)
	}
	if body.Version != 3 || len(body.Bindings) != 2 {
		t.Fatalf("enable body %+v — the existing binding was dropped or the version not read", body)
	}
}

// The server answers 409 for a replay already applied, a replay not finished,
// and a failed one. Only the first applied anything.
func TestCommands_replayApplyExitsZeroOnlyWhenAlreadyApplied(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	conflict := func(message string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			f.json(w, http.StatusConflict, mustJSON(map[string]any{"message": message, "status": 409}))
		}
	}
	f.mux.HandleFunc("POST /labs/api/replay/rep_done/apply", conflict("this replay has already been applied"))
	f.mux.HandleFunc("POST /labs/api/replay/rep_running/apply", conflict("this replay is running; only a replay that finished successfully can be applied"))
	f.mux.HandleFunc("POST /labs/api/replay/rep_failed/apply", conflict("this replay is failed; only a replay that finished successfully can be applied"))

	if code, _, errOut := f.run(t, "--yes", "replay", "apply", "rep_done"); code != ExitOK || !strings.Contains(errOut, "already applied") {
		t.Fatalf("already applied: code %d, %s; want exit 0", code, errOut)
	}
	for _, id := range []string{"rep_running", "rep_failed"} {
		code, _, errOut := f.run(t, "--yes", "replay", "apply", id)
		if code != ExitError || !strings.Contains(errOut, "only a replay that finished successfully can be applied") {
			t.Fatalf("%s: code %d, %s; want exit 1 with the server's message", id, code, errOut)
		}
	}
}

// -o replaces the file only once the export has arrived in full: not before
// signing in, not on a refusal, not on a dropped connection.
func TestCommands_replayExportLeavesTheFileAloneUnlessTheDownloadCompletes(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.mux.HandleFunc("GET /labs/api/replay/rep_denied/export", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusForbidden, `{"message":"not permitted","status":403}`)
	})
	f.mux.HandleFunc("GET /labs/api/replay/rep_cut/export", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = fmt.Fprint(w, "{\"decision\":1}\n")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	f.mux.HandleFunc("GET /labs/api/replay/rep_ok/export", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = fmt.Fprint(w, "{\"decision\":1}\n{\"decision\":2}\n")
	})
	outDir := t.TempDir()
	out := filepath.Join(outDir, "export.ndjson")
	const previous = "the previous export\n"
	if err := os.WriteFile(out, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	unchanged := func(what string) {
		t.Helper()
		got, err := os.ReadFile(out)
		if err != nil || string(got) != previous {
			t.Fatalf("%s: the file became %q (%v)", what, got, err)
		}
		entries, _ := os.ReadDir(outDir)
		if len(entries) != 1 {
			t.Fatalf("%s: left %d files beside it", what, len(entries)-1)
		}
	}

	for _, id := range []string{"rep_denied", "rep_cut"} {
		if code, _, errOut := f.run(t, "replay", "export", id, "-o", out); code != ExitError {
			t.Fatalf("%s: code %d, %s; want exit 1", id, code, errOut)
		}
		unchanged(id)
	}

	signedIn := os.Getenv(config.EnvConfigDir)
	t.Setenv(config.EnvConfigDir, t.TempDir())
	if code, _, _ := f.run(t, "replay", "export", "rep_ok", "-o", out); code != ExitAuth {
		t.Fatalf("not signed in: code %d, want 3", code)
	}
	unchanged("not signed in")
	t.Setenv(config.EnvConfigDir, signedIn)

	if code, _, errOut := f.run(t, "replay", "export", "rep_ok", "-o", out); code != ExitOK {
		t.Fatalf("complete download: code %d, %s", code, errOut)
	}
	if got, _ := os.ReadFile(out); string(got) != "{\"decision\":1}\n{\"decision\":2}\n" {
		t.Fatalf("the completed export wrote %q", got)
	}
}

// Sign in to B, then A: A is current. A command with --instance B renews B's
// token, and A is still current afterwards, so the next command without
// --instance acts on A.
func TestCommands_renewingAnotherInstanceLeavesTheCurrentOneAlone(t *testing.T) {
	const instanceB = "ins_2bbb"
	f := newFakeAPI(t)
	f.signIn(t)
	f.storeCredential(t, instanceB, "tok-b", 55*time.Minute, 5*time.Minute, true)
	if err := (auth.Store{Dir: f.dir}).SetCurrent(f.srv.URL, instanceA); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := f.run(t, "--instance", instanceB, "whoami", "--json")
	if code != ExitOK || !strings.Contains(out, `"instance_id": "ins_2bbb"`) {
		t.Fatalf("whoami --instance B: code %d, %s %s", code, out, errOut)
	}
	if f.renewals != 1 {
		t.Fatalf("B's token was renewed %d times, want 1", f.renewals)
	}
	if cur, err := (auth.Store{Dir: f.dir}).Current(f.srv.URL); err != nil || cur != instanceA {
		t.Fatalf("current instance is %q after renewing B, want %s: %v", cur, instanceA, err)
	}
	if code, out, _ := f.run(t, "whoami", "--json"); code != ExitOK || !strings.Contains(out, `"instance_id": "ins_2abc"`) {
		t.Fatalf("a command without --instance did not act on A: %s", out)
	}
}

// A stream outlives the token it opened with. trace closes it before the token
// expires and reopens it, and the reopening renews — rather than the server
// ending the stream with an expired token that can no longer be renewed.
func TestCommands_traceReopensTheStreamToRenewBeforeTheTokenExpires(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	// Too young to renew now; expires two seconds after the reconnect point.
	f.storeCredential(t, instanceA, "tok", time.Second, auth.RenewFloor+2*time.Second, true)

	var mu sync.Mutex
	var streams []string
	f.mux.HandleFunc("GET /labs/api/trace/columns", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, 200, `{"enabled":true,"columns":[{"key":"ip","label":"IP","group":"Network","default":true}],"defaults":["ip"]}`)
	})
	f.mux.HandleFunc("GET /labs/api/trace", func(w http.ResponseWriter, r *http.Request) {
		tok := f.token(r)
		mu.Lock()
		streams = append(streams, tok)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: status\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		if tok == "tok" {
			<-r.Context().Done() // the stream stays open until the client closes it
			return
		}
		_, _ = fmt.Fprint(w, "event: decision\ndata: {\"ip\":\"1.2.3.4\"}\n\nevent: closed\ndata: {\"reason\":\"closed\"}\n\n")
	})

	code, out, errOut := f.run(t, "trace")
	if code != ExitOK {
		t.Fatalf("trace: code %d, %s", code, errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(streams) != 2 || streams[0] != "tok" || streams[1] != "tok-renewed-1" {
		t.Fatalf("streams opened with %v; want the original token, then the renewed one", streams)
	}
	if !strings.Contains(out, "ip=1.2.3.4") {
		t.Fatalf("the decision from the reopened stream was not printed: %q", out)
	}
}

// Server text reaches a terminal only stripped of control sequences — in an
// error message and in a rendered rule — while --json keeps it, JSON-escaped.
func TestCommands_serverTextCannotControlTheTerminal(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	const evil = "\x1b]52;c;ZXZpbA==\x07\x1b[2J\x1b[1A"
	f.mux.HandleFunc("GET /labs/api/rulesets/EVIL/rules", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, 200, mustJSON(map[string]any{
			"rules":         []map[string]any{{"id": "r1", "expression": "true" + evil, "action": "BLOCK", "description": "looks fine" + evil}},
			"nextPageToken": nil,
		}))
	})
	f.mux.HandleFunc("GET /labs/api/rulesets/DENIED/rules", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusForbidden, mustJSON(map[string]any{"message": "denied" + evil, "status": 403}))
	})

	code, out, _ := f.run(t, "rules", "list", "--ruleset", "EVIL")
	if code != ExitOK || !strings.Contains(out, "looks fine") || strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("human output: code %d, %q", code, out)
	}
	code, _, errOut := f.run(t, "rules", "list", "--ruleset", "DENIED")
	if code != ExitError || !strings.Contains(errOut, "denied") || strings.ContainsAny(errOut, "\x1b\x07") {
		t.Fatalf("error output: code %d, %q", code, errOut)
	}
	code, out, _ = f.run(t, "rules", "list", "--ruleset", "EVIL", "--json")
	escapedESC := string(rune(92)) + "u001b"
	if code != ExitOK || strings.ContainsAny(out, "\x1b\x07") || !strings.Contains(out, escapedESC) {
		t.Fatalf("--json output: code %d, %q; want the value kept, escaped", code, out)
	}
}

func TestCommands_insightsEntityAndFlowSendTheirBodies(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	for _, route := range []string{"POST /labs/api/insights/entity", "POST /labs/api/insights/decisions/flow"} {
		f.mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			f.record(r)
			f.json(w, 200, `{"ok":true}`)
		})
	}

	code, _, errOut := f.run(t, "insights", "entity", "--dimension", "ip", "--value", "1.2.3.4", "--since", "2h")
	if code != ExitOK {
		t.Fatalf("entity: code %d, %s", code, errOut)
	}
	var entity map[string]any
	if err := json.Unmarshal(f.posts["POST /labs/api/insights/entity"], &entity); err != nil {
		t.Fatal(err)
	}
	if entity["dimension"] != "ip" || entity["value"] != "1.2.3.4" || entity["from"] == nil || entity["to"] == nil {
		t.Fatalf("entity body %v", entity)
	}

	code, _, errOut = f.run(t, "insights", "flow", "--decision-id", "dec_1", "--at", "2026-09-14T10:00:00Z")
	if code != ExitOK {
		t.Fatalf("flow: code %d, %s", code, errOut)
	}
	if got := string(f.posts["POST /labs/api/insights/decisions/flow"]); got != `{"at":"2026-09-14T10:00:00Z","decision_id":"dec_1"}` {
		t.Fatalf("flow body %s", got)
	}

	before := f.callCount()
	for _, args := range [][]string{
		{"insights", "entity", "--dimension", "ip"},
		{"insights", "flow", "--decision-id", "dec_1"},
		{"insights", "flow", "--at", "2026-09-14T10:00:00Z"},
	} {
		if code, _, _ := f.run(t, args...); code != ExitUsage {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
	if f.callCount() != before {
		t.Fatal("an incomplete insights request was sent")
	}
}

func TestCommands_signInProblemsExitThree(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)

	// A different device key than the credential was bound to.
	if err := keystore.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keystore.OpenOrCreate(); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := f.run(t, "whoami")
	if code != ExitAuth || !strings.Contains(errOut, "clerk-protect login") {
		t.Fatalf("changed key: code %d err %s", code, errOut)
	}

	// No credential at all.
	t.Setenv(config.EnvConfigDir, t.TempDir())
	code, _, _ = f.run(t, "rules", "list")
	if code != ExitAuth {
		t.Fatalf("not signed in: code %d", code)
	}
}

func TestCommands_usageMistakesExitTwo(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	for _, args := range [][]string{{"no-such-command"}, {"rules", "get"}, {"rules", "list", "--bogus"}, {"rules", "get", "r1"}} {
		if code, _, errOut := f.run(t, args...); code != ExitUsage {
			t.Errorf("%v: code %d err %s", args, code, errOut)
		}
	}
}
