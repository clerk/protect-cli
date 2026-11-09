package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestInsightsTraceID(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		decisions  []map[string]any
		wantBody   map[string]any
		wantNote   string
		wantNoNote bool
	}{
		{
			name:       "a block is found",
			args:       []string{"7Q8ikxgt"},
			decisions:  []map[string]any{{"decision_id": "d1", "decision": "DENY"}},
			wantBody:   map[string]any{"trace_id": "7Q8ikxgt"},
			wantNoNote: true,
		},
		{
			name:      "nothing matches",
			args:      []string{"7Q8ikxgt", "--window-hours", "48", "--limit", "5"},
			decisions: []map[string]any{},
			wantBody:  map[string]any{"trace_id": "7Q8ikxgt", "window_hours": float64(48), "limit": float64(5)},
			wantNote:  "No decision on this instance matches 7Q8ikxgt",
		},
		{
			name:      "a shadow deny is not a block",
			args:      []string{"7Q8ikxgt"},
			decisions: []map[string]any{{"decision_id": "d3", "decision": "DENY", "traffic_class": "TRAFFIC_CLASS_SHADOW"}},
			wantBody:  map[string]any{"trace_id": "7Q8ikxgt"},
			wantNote:  "None of the matching decisions was an enforced block",
		},
		{
			name:      "a match that was not a block",
			args:      []string{"7Q8ikxgt"},
			decisions: []map[string]any{{"decision_id": "d2", "decision": "ALLOW"}},
			wantBody:  map[string]any{"trace_id": "7Q8ikxgt"},
			wantNote:  "None of the matching decisions was an enforced block",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			var got map[string]any
			f.mux.HandleFunc("POST /labs/api/insights/decisions/trace-id", func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Error(err)
				}
				f.json(w, 200, mustJSON(map[string]any{
					"ident":     map[string]any{"value": "7Q8ikxgt", "kind": "trace-id"},
					"decisions": tc.decisions,
					"truncated": false,
					"from":      "2026-10-26T00:00:00Z",
					"to":        "2026-11-09T00:00:00Z",
				}))
			})
			code, out, errOut := f.run(t, append([]string{"insights", "trace-id"}, tc.args...)...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			if len(got) != len(tc.wantBody) {
				t.Errorf("request body = %v, want %v", got, tc.wantBody)
			}
			for k, v := range tc.wantBody {
				if got[k] != v {
					t.Errorf("request %s = %v, want %v", k, got[k], v)
				}
			}
			var printed map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &printed); err != nil {
				t.Fatalf("stdout is not the JSON response: %v\n%s", err, out)
			}
			if tc.wantNoNote && strings.TrimSpace(errOut) != "" {
				t.Errorf("unexpected note: %q", errOut)
			}
			if tc.wantNote != "" && !strings.Contains(errOut, tc.wantNote) {
				t.Errorf("stderr = %q, want it to contain %q", errOut, tc.wantNote)
			}
		})
	}
}

func TestInsightsTraceID_requiresOneReference(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	if code, _, _ := f.run(t, "insights", "trace-id"); code == 0 {
		t.Fatal("no reference was accepted")
	}
}
