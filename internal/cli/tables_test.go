package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeTableStore serves the Labs tables routes from memory, closely enough to
// hold the CLI to the wire contract: a row write is a replacement, rows page
// by next_page_token, and a query matches a CIDR entry by prefix.
type fakeTableStore struct {
	mu     sync.Mutex
	tables map[string]*tableInfo
	rows   map[string][]tableRow
	extra  map[string]map[string]json.RawMessage // per row id: fields the server records
	bodies []string                              // every write body, in order
}

func (s *fakeTableStore) mount(t *testing.T, f *fakeAPI) {
	t.Helper()
	s.tables = map[string]*tableInfo{}
	s.rows = map[string][]tableRow{}
	s.extra = map[string]map[string]json.RawMessage{}
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	read := func(r *http.Request, v any) string {
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_ = json.Unmarshal(raw, v)
		s.bodies = append(s.bodies, string(raw))
		return string(raw)
	}
	f.mux.HandleFunc("GET /labs/api/tables", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var list []tableInfo
		for _, tb := range s.tables {
			tb.RowCount = int32(len(s.rows[tb.Name]))
			list = append(list, *tb)
		}
		reply(w, map[string]any{"tables": list})
	})
	f.mux.HandleFunc("POST /labs/api/tables", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var tb tableInfo
		read(r, &tb)
		s.tables[tb.Name] = &tb
		w.WriteHeader(http.StatusCreated)
		reply(w, tb)
	})
	f.mux.HandleFunc("GET /labs/api/tables/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		tb, ok := s.tables[r.PathValue("name")]
		if !ok {
			http.Error(w, `{"message":"table not found"}`, http.StatusNotFound)
			return
		}
		reply(w, tb)
	})
	f.mux.HandleFunc("PATCH /labs/api/tables/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var body map[string]any
		read(r, &body)
		reply(w, s.tables[r.PathValue("name")])
	})
	f.mux.HandleFunc("DELETE /labs/api/tables/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.tables, r.PathValue("name"))
		s.bodies = append(s.bodies, "DELETE "+r.PathValue("name"))
		reply(w, map[string]any{})
	})
	f.mux.HandleFunc("GET /labs/api/tables/{name}/rows", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		rows := s.rows[r.PathValue("name")]
		// Pages of two, so the CLI must follow the token.
		start := 0
		if after := r.URL.Query().Get("after"); after != "" {
			for i, row := range rows {
				if row.ID == after {
					start = i + 1
				}
			}
		}
		end := min(start+2, len(rows))
		next := ""
		if end < len(rows) {
			next = rows[end-1].ID
		}
		reply(w, map[string]any{"rows": rows[start:end], "next_page_token": next})
	})
	f.mux.HandleFunc("GET /labs/api/tables/{name}/rows/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, row := range s.rows[r.PathValue("name")] {
			if row.ID == r.PathValue("id") {
				raw, _ := json.Marshal(row)
				var m map[string]json.RawMessage
				_ = json.Unmarshal(raw, &m)
				for k, v := range s.extra[row.ID] {
					m[k] = v
				}
				reply(w, m)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"row not found"}`))
	})
	upsert := func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var row tableRow
		raw := read(r, &row)
		if id := r.PathValue("id"); id != "" {
			row.ID = id
		}
		// A replacement: what the write carries is what is kept, provenance included.
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &m)
		kept := map[string]json.RawMessage{}
		for _, k := range []string{"added_by", "source"} {
			if v, ok := m[k]; ok {
				kept[k] = v
			}
		}
		s.extra[row.ID] = kept
		if row.ID == "" {
			// As the real server: an id is required, and none is assigned.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"row.id is required"}`))
			return
		}
		name := r.PathValue("name")
		for i, existing := range s.rows[name] {
			if existing.ID == row.ID {
				s.rows[name][i] = row // a replacement, as the server's is
				reply(w, row)
				return
			}
		}
		s.rows[name] = append(s.rows[name], row)
		reply(w, row)
	}
	f.mux.HandleFunc("POST /labs/api/tables/{name}/rows", upsert)
	f.mux.HandleFunc("PUT /labs/api/tables/{name}/rows/{id}", upsert)
	f.mux.HandleFunc("DELETE /labs/api/tables/{name}/rows/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		name := r.PathValue("name")
		kept := s.rows[name][:0]
		for _, row := range s.rows[name] {
			if row.ID != r.PathValue("id") {
				kept = append(kept, row)
			}
		}
		s.rows[name] = kept
		reply(w, map[string]any{})
	})
	f.mux.HandleFunc("POST /labs/api/tables/{name}/query", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var body struct {
			Inputs map[string]string `json:"inputs"`
		}
		read(r, &body)
		var hit []tableRow
		for _, row := range s.rows[r.PathValue("name")] {
			ok := true
			for col, val := range body.Inputs {
				matched := false
				for _, e := range row.Fields[col] {
					if e.Value == val || (e.Kind == "CIDR" && strings.HasPrefix(val, strings.TrimSuffix(e.Value, "0/24"))) {
						matched = true
					}
				}
				ok = ok && matched
			}
			if ok {
				hit = append(hit, row)
			}
		}
		reply(w, map[string]any{"rows": hit, "total_matches": len(hit)})
	})
}

func tablesFixture(t *testing.T) (*fakeAPI, *fakeTableStore) {
	t.Helper()
	f := newFakeAPI(t)
	f.signIn(t)
	s := &fakeTableStore{}
	s.mount(t, f)
	return f, s
}

func TestTables_createListAndGet(t *testing.T) {
	f, s := tablesFixture(t)
	code, out, errOut := f.run(t, "tables", "create", "blocked", "--yes",
		"--column", "network:ip:matchable:required", "--column", "reason:STRING", "--description", "Networks we block")
	if code != ExitOK || !strings.Contains(out, "Created table") {
		t.Fatalf("create: code %d out %q err %q", code, out, errOut)
	}
	var sent tableInfo
	_ = json.Unmarshal([]byte(s.bodies[0]), &sent)
	if len(sent.Columns) != 2 || sent.Columns[0] != (tableColumn{Name: "network", Type: "IP", Matchable: true, Required: true}) {
		t.Fatalf("create sent %s", s.bodies[0])
	}

	code, out, _ = f.run(t, "tables", "list")
	if code != ExitOK || !strings.Contains(out, "blocked") || !strings.Contains(out, "network:ip*") {
		t.Fatalf("list: %q", out)
	}
	code, out, _ = f.run(t, "tables", "get", "blocked")
	if code != ExitOK || !strings.Contains(out, "network") || !strings.Contains(out, "Networks we block") {
		t.Fatalf("get: %q", out)
	}
}

func TestTables_createRefusesABadColumn(t *testing.T) {
	f, s := tablesFixture(t)
	for _, spec := range []string{"network", "network:FLOAT", "network:IP:unique"} {
		if code, _, _ := f.run(t, "tables", "create", "x", "--yes", "--column", spec); code != ExitUsage {
			t.Errorf("--column %q: code %d, want a usage error", spec, code)
		}
	}
	if len(s.bodies) != 0 {
		t.Fatalf("a refused create reached the server: %v", s.bodies)
	}
}

func TestTables_rowsAddListPagesAndDelete(t *testing.T) {
	f, s := tablesFixture(t)
	for _, args := range [][]string{
		{"--id", "a", "--matcher", "network=cidr:203.0.113.0/24", "--value", "reason=abuse"},
		{"--id", "b", "--value", "network=198.51.100.7", "--note", "from a ticket"},
		{"--id", "c", "--value", "network=192.0.2.1", "--expires", "2027-01-01T00:00:00Z"},
	} {
		if code, _, errOut := f.run(t, append([]string{"tables", "rows", "add", "blocked", "--yes"}, args...)...); code != ExitOK {
			t.Fatalf("add %v: %s", args, errOut)
		}
	}
	var first tableRow
	_ = json.Unmarshal([]byte(s.bodies[0]), &first)
	if e := first.Fields["network"]; len(e) != 1 || e[0] != (tableEntry{Kind: "CIDR", Value: "203.0.113.0/24"}) {
		t.Fatalf("matcher sent as %s", s.bodies[0])
	}

	// Three rows over pages of two: the CLI follows the token.
	code, out, _ := f.run(t, "tables", "rows", "list", "blocked")
	if code != ExitOK || strings.Count(out, "\n") != 4 || !strings.Contains(out, "cidr:203.0.113.0/24") ||
		!strings.Contains(out, "2027-01-01T00:00:00Z") {
		t.Fatalf("list:\n%s", out)
	}

	if code, _, errOut := f.run(t, "tables", "rows", "delete", "blocked", "b", "--yes"); code != ExitOK {
		t.Fatalf("delete: %s", errOut)
	}
	if _, out, _ := f.run(t, "tables", "rows", "list", "blocked", "--json"); strings.Contains(out, `"b"`) {
		t.Fatalf("deleted row still listed: %s", out)
	}
}

func TestTables_rowsUpdateKeepsWhatItDoesNotName(t *testing.T) {
	f, s := tablesFixture(t)
	f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "a",
		"--value", "network=198.51.100.7", "--value", "reason=abuse", "--note", "keep me")

	if code, _, errOut := f.run(t, "tables", "rows", "update", "blocked", "a", "--yes", "--value", "reason=spam"); code != ExitOK {
		t.Fatalf("update: %s", errOut)
	}
	row := s.rows["blocked"][0]
	if row.Fields["network"][0].Value != "198.51.100.7" || row.Fields["reason"][0].Value != "spam" || row.Note != "keep me" {
		t.Fatalf("update lost what it did not name: %+v", row)
	}

	// set replaces: what is not given is gone.
	if code, _, errOut := f.run(t, "tables", "rows", "set", "blocked", "a", "--yes", "--value", "network=192.0.2.9"); code != ExitOK {
		t.Fatalf("set: %s", errOut)
	}
	row = s.rows["blocked"][0]
	if _, kept := row.Fields["reason"]; kept || row.Note != "" || row.Fields["network"][0].Value != "192.0.2.9" {
		t.Fatalf("set kept what it was not given: %+v", row)
	}

	// --clear empties one column.
	f.run(t, "tables", "rows", "update", "blocked", "a", "--yes", "--value", "reason=x")
	f.run(t, "tables", "rows", "update", "blocked", "a", "--yes", "--clear", "reason")
	if _, kept := s.rows["blocked"][0].Fields["reason"]; kept {
		t.Fatalf("--clear left the column: %+v", s.rows["blocked"][0])
	}
}

func TestTables_rowsSearch(t *testing.T) {
	f, s := tablesFixture(t)
	f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "net", "--matcher", "network=cidr:203.0.113.0/24")
	f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "one", "--value", "network=198.51.100.7", "--note", "Reported by Acme")

	code, out, errOut := f.run(t, "tables", "rows", "search", "blocked", "--match", "network=203.0.113.7")
	if code != ExitOK || !strings.Contains(out, "net") || strings.Contains(out, "one") || !strings.Contains(errOut, "1 live row(s) match") {
		t.Fatalf("--match: out %q err %q", out, errOut)
	}
	var q struct {
		Inputs map[string]string `json:"inputs"`
	}
	_ = json.Unmarshal([]byte(s.bodies[len(s.bodies)-1]), &q)
	if q.Inputs["network"] != "203.0.113.7" {
		t.Fatalf("query sent %s", s.bodies[len(s.bodies)-1])
	}

	code, out, errOut = f.run(t, "tables", "rows", "search", "blocked", "--contains", "acme")
	if code != ExitOK || !strings.Contains(out, "one") || strings.Contains(out, "net ") || !strings.Contains(errOut, "1 of 2 rows") {
		t.Fatalf("--contains: out %q err %q", out, errOut)
	}

	if code, _, _ := f.run(t, "tables", "rows", "search", "blocked"); code != ExitUsage {
		t.Fatalf("search with neither: code %d", code)
	}
}

func TestTables_writesNeedConsentWhenNotInteractive(t *testing.T) {
	f, s := tablesFixture(t)
	for _, args := range [][]string{
		{"tables", "create", "x", "--column", "a:STRING"},
		{"tables", "delete", "x"},
		{"tables", "rows", "add", "x", "--value", "a=b"},
		{"tables", "rows", "delete", "x", "r"},
	} {
		if code, _, _ := f.run(t, args...); code != ExitUsage {
			t.Errorf("%v without --yes: code %d, want a usage error", args, code)
		}
	}
	if len(s.bodies) != 0 {
		t.Fatalf("an unconfirmed write reached the server: %v", s.bodies)
	}
}

// A row write is a replacement, so update and set must send back what the
// server recorded about a row — who added it, from where — or erase it.
func TestTables_updateAndSetKeepProvenance(t *testing.T) {
	f, s := tablesFixture(t)
	f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "a", "--value", "network=198.51.100.7")
	s.extra["a"] = map[string]json.RawMessage{"added_by": json.RawMessage(`"user_curator"`), "source": json.RawMessage(`"case 7"`)}

	if code, _, errOut := f.run(t, "tables", "rows", "update", "blocked", "a", "--yes", "--value", "network=192.0.2.1"); code != ExitOK {
		t.Fatalf("update: %s", errOut)
	}
	if string(s.extra["a"]["added_by"]) != `"user_curator"` || string(s.extra["a"]["source"]) != `"case 7"` {
		t.Fatalf("update dropped provenance: %v", s.extra["a"])
	}
	if code, _, errOut := f.run(t, "tables", "rows", "set", "blocked", "a", "--yes", "--value", "network=192.0.2.2"); code != ExitOK {
		t.Fatalf("set: %s", errOut)
	}
	if string(s.extra["a"]["added_by"]) != `"user_curator"` {
		t.Fatalf("set dropped provenance: %v", s.extra["a"])
	}
}

func TestTables_addRefusesATakenIDAndSetRefusesAMissingOne(t *testing.T) {
	f, s := tablesFixture(t)
	f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "a", "--value", "network=198.51.100.7")
	writes := len(s.bodies)
	if code, _, errOut := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "a", "--value", "network=192.0.2.1"); code != ExitUsage || !strings.Contains(errOut, "already has a row a") {
		t.Fatalf("add over a taken id: code %d err %q", code, errOut)
	}
	if code, _, _ := f.run(t, "tables", "rows", "set", "blocked", "nope", "--yes", "--value", "network=192.0.2.1"); code == ExitOK {
		t.Fatal("set created a row that did not exist")
	}
	if len(s.bodies) != writes || s.rows["blocked"][0].Fields["network"][0].Value != "198.51.100.7" {
		t.Fatalf("a refused write reached the server: %v", s.bodies[writes:])
	}
}

// The server requires a row id and assigns none, so a row added without --id
// gets a generated one the server's pattern accepts.
func TestTables_addWithoutAnIDGeneratesOne(t *testing.T) {
	f, s := tablesFixture(t)
	code, out, errOut := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--value", "network=198.51.100.7")
	if code != ExitOK {
		t.Fatalf("add without --id: code %d err %q", code, errOut)
	}
	id := s.rows["blocked"][0].ID
	if !rowIDPattern.MatchString(id) || !strings.Contains(out, id) {
		t.Fatalf("generated id %q (printed %q)", id, out)
	}
	if code, _, _ := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "9bad", "--value", "network=x"); code != ExitUsage {
		t.Fatalf("an id the server would refuse: code %d, want a usage error", code)
	}
}

// --from-json takes a whole row: its expiry, note and reference are kept, the
// flags win over them, and a key it does not know is refused, not dropped.
func TestTables_fromJSONHonoursTheWholeRow(t *testing.T) {
	f, s := tablesFixture(t)
	dir := t.TempDir()
	path := dir + "/row.json"
	row := `{"id":"imp","fields":{"network":[{"kind":"CIDR","value":"203.0.113.0/24"}]},` +
		`"expires_at":"2027-01-01T00:00:00Z","note":"from export","reference":"https://example.com/why","added_by":"user_x"}`
	if err := os.WriteFile(path, []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--from-json", path, "--note", "flag wins"); code != ExitOK {
		t.Fatalf("add --from-json: %s", errOut)
	}
	got := s.rows["blocked"][0]
	if got.ID != "imp" || got.ExpiresAt != "2027-01-01T00:00:00Z" || got.Reference != "https://example.com/why" ||
		got.Note != "flag wins" || got.Fields["network"][0].Kind != "CIDR" {
		t.Fatalf("imported row = %+v", got)
	}

	if err := os.WriteFile(path, []byte(`{"fields":{},"expiry":"2027-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--from-json", path); code != ExitUsage || !strings.Contains(errOut, `"expiry"`) {
		t.Fatalf("an unknown key: code %d err %q, want a usage error naming it", code, errOut)
	}
}

// A bare fields map whose column is named "fields" is still a fields map, and a
// null fields value is refused rather than crashing the flags applied after it.
func TestTables_fromJSONShapes(t *testing.T) {
	f, s := tablesFixture(t)
	path := t.TempDir() + "/row.json"
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"fields":[{"value":"x"}],"other":[{"value":"y"}]}`)
	if code, _, errOut := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "a", "--from-json", path); code != ExitOK {
		t.Fatalf("a column named fields: %s", errOut)
	}
	if got := s.rows["blocked"][0].Fields; got["fields"][0].Value != "x" || got["other"][0].Value != "y" {
		t.Fatalf("stored %+v", got)
	}

	write(`{"fields":null}`)
	if code, _, errOut := f.run(t, "tables", "rows", "add", "blocked", "--yes", "--id", "b", "--from-json", path, "--value", "network=x"); code != ExitUsage {
		t.Fatalf("null fields: code %d err %q, want a usage error", code, errOut)
	}
}
