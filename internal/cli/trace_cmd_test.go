package cli

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const traceColumnsJSON = `{"enabled":true,"columns":[` +
	`{"key":"decision","label":"Decision","group":"Decision","default":true},` +
	`{"key":"ip","label":"IP","group":"Network","default":true}],"defaults":["decision","ip"]}`

func (f *fakeAPI) serveTrace(events string) {
	f.mux.HandleFunc("GET /labs/api/trace/columns", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, 200, traceColumnsJSON)
	})
	f.mux.HandleFunc("GET /labs/api/trace", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, events)
	})
}

// --filter keeps the decisions that match, ignoring case. A filter that is not
// one exits 2 before anything is sent; one naming a field the server does not
// describe exits 2 once the server has described its fields.
func TestCommands_traceFiltersLines(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.serveTrace("event: status\ndata: {}\n\n" +
		"event: decision\ndata: {\"decision\":\"DENY\",\"ip\":\"10.0.0.1\"}\n\n" +
		"event: decision\ndata: {\"decision\":\"ALLOW\",\"ip\":\"10.0.0.2\"}\n\n" +
		"event: closed\ndata: {\"reason\":\"closed\"}\n\n")

	code, out, errOut := f.run(t, "trace", "--filter", "decision=deny")
	if code != ExitOK || !strings.Contains(out, "ip=10.0.0.1") || strings.Contains(out, "10.0.0.2") {
		t.Fatalf("code %d out %q err %s", code, out, errOut)
	}
	code, out, _ = f.run(t, "trace", "--filter", "ip~10.0.0.", "--filter", "decision!=deny")
	if code != ExitOK || strings.Contains(out, "10.0.0.1") || !strings.Contains(out, "ip=10.0.0.2") {
		t.Fatalf("two filters: code %d out %q", code, out)
	}

	before := f.callCount()
	if code, _, errOut := f.run(t, "trace", "--filter", "decision"); code != ExitUsage || f.callCount() != before {
		t.Fatalf("a filter that is not one: code %d, %d requests, err %s", code, f.callCount()-before, errOut)
	}
	if code, _, errOut := f.run(t, "trace", "--filter", "nope=1"); code != ExitUsage || !strings.Contains(errOut, "no field named") {
		t.Fatalf("an unknown field: code %d err %s", code, errOut)
	}
}

// Without a terminal, trace prints lines even when not asked to: the
// interactive view is only for a person at a terminal.
func TestCommands_traceWithoutATerminalPrintsLines(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.serveTrace("event: status\ndata: {}\n\nevent: decision\ndata: {\"decision\":\"DENY\",\"ip\":\"10.0.0.1\"}\n\n")
	code, out, errOut := f.run(t, "trace")
	if code != ExitOK || !strings.Contains(out, "decision=DENY ip=10.0.0.1") || strings.Contains(out, "\x1b") {
		t.Fatalf("code %d out %q err %s", code, out, errOut)
	}
}

// --field is exact in the interactive view, as in line output: it becomes
// key==value, which does not match a value that differs only in case.
func TestFieldFilters_areExact(t *testing.T) {
	got := fieldFilters(map[string]string{"ip": "10.0.0.1", "decision": "DENY"})
	if len(got) != 2 || got[0].String() != "decision==DENY" || got[1].String() != "ip==10.0.0.1" {
		t.Fatalf("fieldFilters = %v", got)
	}
	if got[0].Match(map[string]string{"decision": "deny"}) {
		t.Fatal("--field matched a value that differs in case")
	}
}
