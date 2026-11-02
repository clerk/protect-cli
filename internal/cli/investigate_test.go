package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// serveInvestigation answers the query route with each stream in turn, and
// records each request body.
func (f *fakeAPI) serveInvestigation(streams ...string) *[]map[string]any {
	var mu sync.Mutex
	var bodies []map[string]any
	i := 0
	f.mux.HandleFunc("POST /labs/api/investigation/query", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		bodies = append(bodies, body)
		s := streams[min(i, len(streams)-1)]
		i++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, s)
	})
	return &bodies
}

const investigationAnswered = "event: accepted\ndata: {\"request_id\":\"inv_000000000000000000000001\"}\n\n" +
	"event: query\ndata: {\"attempt\":1,\"sql\":\"SELECT 1\",\"explanation\":\"x\"}\n\n" +
	"event: review\ndata: {\"attempt\":1,\"accepted\":true,\"reason\":\"ok\"}\n\n" +
	"event: columns\ndata: {\"columns\":[{\"name\":\"country\",\"type\":\"String\"},{\"name\":\"n\",\"type\":\"UInt64\"}]}\n\n" +
	"event: rows\ndata: {\"rows\":[[\"US\",\"12\"],[\"=cmd()\",\"3\"]]}\n\n" +
	"event: done\ndata: {\"outcome\":\"answered\",\"row_count\":2}\n\n"

func TestInvestigate_answersToStdoutAndTraceToStderr(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	bodies := f.serveInvestigation(investigationAnswered)

	code, out, errOut := f.run(t, "investigate", "--format", "csv", "--purpose", "why", "Blocked sign-ups by country")
	if code != ExitOK {
		t.Fatalf("code %d err %s", code, errOut)
	}
	if out != "country,n\nUS,12\n'=cmd(),3\n" {
		t.Errorf("stdout = %q (a formula cell must be defused)", out)
	}
	if !strings.Contains(errOut, "SELECT 1") || !strings.Contains(errOut, "answered · 2 rows") {
		t.Errorf("stderr = %q", errOut)
	}
	if got := (*bodies)[0]; got["prompt"] != "Blocked sign-ups by country" || got["purpose"] != "why" || got["instance"] != nil {
		t.Errorf("request body = %v", got)
	}
}

// A stream that ends without `done` is an error, whatever came before it.
func TestInvestigate_aStreamWithoutDoneIsIncomplete(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.serveInvestigation(strings.TrimSuffix(investigationAnswered, "event: done\ndata: {\"outcome\":\"answered\",\"row_count\":2}\n\n"))
	code, _, errOut := f.run(t, "investigate", "q")
	if code != ExitError || !strings.Contains(errOut, "NOT the complete result") {
		t.Fatalf("code %d err %s", code, errOut)
	}
}

// Without a terminal, a request for more information exits 5 with the
// request id; a declined one exits 4.
func TestInvestigate_outcomeExitCodes(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.serveInvestigation(
		"event: accepted\ndata: {\"request_id\":\"inv_000000000000000000000002\"}\n\n"+
			"event: needs_more_information\ndata: {\"questions\":[\"Which flow?\"]}\n\n"+
			"event: done\ndata: {\"outcome\":\"needs_more_information\"}\n\n",
		"event: declined\ndata: {\"reason\":\"not about decisions\"}\n\n"+
			"event: done\ndata: {\"outcome\":\"declined\"}\n\n",
	)
	code, _, errOut := f.run(t, "investigate", "q")
	if code != ExitNeedsMore || !strings.Contains(errOut, "--prior-request inv_000000000000000000000002") || !strings.Contains(errOut, "Which flow?") {
		t.Fatalf("needs more: code %d err %s", code, errOut)
	}
	code, _, errOut = f.run(t, "investigate", "q")
	if code != ExitDeclined || !strings.Contains(errOut, "not about decisions") {
		t.Fatalf("declined: code %d err %s", code, errOut)
	}
}

// --json prints each event as one JSON line, for a program to read.
func TestInvestigate_jsonPrintsEvents(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.serveInvestigation(investigationAnswered)
	code, out, errOut := f.run(t, "investigate", "--json", "q")
	if code != ExitOK {
		t.Fatalf("code %d err %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var last struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || last.Event != "done" {
		t.Fatalf("last line %q", lines[len(lines)-1])
	}
}

func TestInvestigate_needsAQuestion(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	before := f.callCount()
	if code, _, _ := f.run(t, "investigate"); code != ExitUsage || f.callCount() != before {
		t.Fatalf("no question: code %d, %d requests", code, f.callCount()-before)
	}
	if code, _, _ := f.run(t, "investigate", "--format", "xml", "q"); code != ExitUsage {
		t.Fatalf("bad format: code %d", code)
	}
}

func TestInvestigationAgent(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	tests := []struct {
		name, flag, want, session, attended string
		env                                 map[string]string
	}{
		{name: "a person", env: map[string]string{}},
		{name: "flag wins", flag: "my-bot", env: map[string]string{"AI_AGENT": "x"}, want: "my-bot"},
		{name: "AI_AGENT", env: map[string]string{"AI_AGENT": "claude-code_2_agent", "CLAUDE_CODE_SESSION_ID": "s1", "CLAUDE_CODE_SESSION_ATTENDED": "0"}, want: "claude-code_2_agent", session: "s1", attended: "false"},
		{name: "CLERK_PROTECT_AGENT", env: map[string]string{"CLERK_PROTECT_AGENT": "codex"}, want: "codex"},
		{name: "CLAUDECODE", env: map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ATTENDED": "1"}, want: "claude-code", attended: "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, session, att := investigationAgent(tt.flag, env(tt.env))
			got := ""
			if att != nil {
				got = fmt.Sprint(*att)
			}
			if name != tt.want || session != tt.session || got != tt.attended {
				t.Fatalf("got (%q, %q, %q)", name, session, got)
			}
		})
	}
}
