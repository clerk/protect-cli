package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestInsightsSearch_followsPages(t *testing.T) {
	for _, tc := range []struct {
		name, unit, rowKey string
		pageCap, available int
		args               []string
	}{
		{"decisions", "decisions", "decisions", 500, 800, []string{"--limit", "620"}},
		{"smaller server pages", "decisions", "decisions", 100, 800, []string{"--query", `{"limit":620}`}},
		{"flows", "flows", "flows", 500, 800, []string{"--limit", "620"}},
		{"exhausted", "decisions", "decisions", 500, 517, []string{"--limit", "620"}},
		{"flag overrides body", "decisions", "decisions", 500, 800, []string{"--query", `{"limit":1}`, "--limit", "620"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			var first map[string]any
			calls, returned := 0, 0
			f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				calls++
				limit := int(body["limit"].(float64))
				if limit != min(500, 620-returned) {
					t.Errorf("page limit = %d after %d rows", limit, returned)
				}
				if first == nil {
					first = body
				} else {
					for _, key := range []string{"from", "to", "unit", "filter", "traffic_classes"} {
						if !reflect.DeepEqual(body[key], first[key]) {
							t.Errorf("%s changed between pages", key)
						}
					}
				}
				start, _ := strconv.Atoi(body["cursor"].(string))
				if start != 7+returned {
					t.Errorf("cursor = %d after %d rows", start, returned)
				}
				n := min(limit, tc.pageCap, tc.available-start)
				rows := make([]map[string]int, n)
				for i := range rows {
					rows[i] = map[string]int{"index": start + i}
				}
				returned += n
				cursor := ""
				if start+n < tc.available {
					cursor = strconv.Itoa(start + n)
				}
				f.json(w, 200, mustJSON(map[string]any{tc.rowKey: rows, "unit": tc.unit, "next_cursor": cursor}))
			})
			args := []string{"insights", "search", "--unit", tc.unit, "--cursor", "7", "--since", "2h", "--filter", "country_code=CA", "--traffic-class", "TRAFFIC_CLASS_PRODUCTION"}
			code, out, errOut := f.run(t, append(args, tc.args...)...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			var result map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatal(err)
			}
			var rows []struct{ Index int }
			if err := json.Unmarshal(result[tc.rowKey], &rows); err != nil {
				t.Fatal(err)
			}
			want := min(620, tc.available-7)
			if len(rows) != want || calls < 2 {
				t.Fatalf("%d rows from %d calls, want %d", len(rows), calls, want)
			}
			for i, row := range rows {
				if row.Index != 7+i {
					t.Fatalf("row %d = %d; skipped or duplicated a row", i, row.Index)
				}
			}
			var cursor string
			_ = json.Unmarshal(result["next_cursor"], &cursor)
			if (cursor == "") != (want == tc.available-7) || (cursor != "" && cursor != strconv.Itoa(7+want)) {
				t.Fatalf("next_cursor = %q after %d rows", cursor, want)
			}
		})
	}
}

func TestInsightsSearch_preservesSinglePageShape(t *testing.T) {
	for _, tc := range []struct{ unit, response string }{
		{"decisions", `{"decisions":[],"columns":["decision_id"]}`},
		{"decisions", `{"decisions":null}`},
		{"flows", `{"unit":"flows","flows":[],"next_cursor":""}`},
	} {
		t.Run(tc.response, func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, r *http.Request) {
				var body struct{ Limit int }
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Limit != 100 {
					t.Errorf("default request limit = %d: %v", body.Limit, err)
				}
				f.json(w, 200, tc.response)
			})
			code, out, errOut := f.run(t, "insights", "search", "--unit", tc.unit)
			var got, want any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal([]byte(tc.response), &want)
			// The CLI adds only the window it searched; TestInsightsSearch_printsWindowToContinue covers it.
			if m, ok := got.(map[string]any); ok {
				delete(m, "window")
			}
			if code != 0 || !reflect.DeepEqual(got, want) {
				t.Fatalf("exit %d, response %s: %s", code, out, errOut)
			}
		})
	}
}

// A cursor marks a row, not a window, so a --since search must print the
// absolute window it used; rerunning --since later would start later and skip
// the oldest rows without an error.
func TestInsightsSearch_printsWindowToContinue(t *testing.T) {
	for _, tc := range []struct {
		name, from, cursor string
		args               []string
	}{
		{"since", "", "1793300000000000000|abc", []string{"--since", "2h"}},
		{"null JSON start uses the server default", "2026-10-27T12:00:00Z", "1793300000000000000|abc", []string{"--query", `{"from":null,"to":"2026-10-28T12:00:00Z"}`}},
		{"null start keeps sub-second precision", "2026-10-27T12:00:00.5Z", "1793300000000000000|abc", []string{"--query", `{"from":null,"to":"2026-10-28T12:00:00.5Z"}`}},
		{"exhausted", "", "", []string{"--since", "2h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			var sent struct{ From, To string }
			f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
					t.Error(err)
				}
				f.json(w, 200, mustJSON(map[string]any{"decisions": []map[string]int{{"index": 0}}, "next_cursor": tc.cursor}))
			})
			code, out, errOut := f.run(t, append([]string{"insights", "search", "--limit", "1"}, tc.args...)...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			var result struct{ Window struct{ From, To string } }
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatal(err)
			}
			if sent.From == "" || sent.To == "" || result.Window.From != sent.From || result.Window.To != sent.To {
				t.Fatalf("window %+v, sent %+v", result.Window, sent)
			}
			if tc.from != "" && sent.From != tc.from {
				t.Fatalf("from = %q, want %q", sent.From, tc.from)
			}
			hint := fmt.Sprintf("--from %s --to %s --cursor '%s'", sent.From, sent.To, tc.cursor)
			if got := strings.Contains(errOut, hint); got != (tc.cursor != "") {
				t.Fatalf("stderr %q; want continuation hint %v", errOut, tc.cursor != "")
			}
		})
	}
}

// The printed window must survive being passed back as flags, or a
// continuation would cut sub-second rows from the window's ends.
func TestInsightsQuery_windowFlagsKeepPrecision(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	var sent struct{ From, To string }
	f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		f.json(w, 200, `{"decisions":[]}`)
	})
	from, to := "2026-10-27T12:00:00.5Z", "2026-10-28T12:00:00.123456789Z"
	if code, _, errOut := f.run(t, "insights", "search", "--from", from, "--to", to, "--cursor", "1|a"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if sent.From != from || sent.To != to {
		t.Fatalf("sent %+v, want %s .. %s", sent, from, to)
	}
}

func TestInsightsSearch_refusesIncompleteResults(t *testing.T) {
	for _, tc := range []struct {
		name, second string
		status       int
	}{
		{"failed page", `{"message":"unavailable"}`, 503},
		{"repeated cursor", `{"decisions":[{}],"next_cursor":"c2","columns":["decision_id"]}`, 200},
		{"empty page with cursor", `{"decisions":[],"next_cursor":"c3","columns":["decision_id"]}`, 200},
		{"changed columns", `{"decisions":[{}],"columns":["source_ip"]}`, 200},
		{"missing rows", `{"flows":[{}],"columns":["decision_id"]}`, 200},
		{"invalid cursor", `{"decisions":[{}],"next_cursor":123,"columns":["decision_id"]}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			calls := 0
			f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if calls == 1 {
					f.json(w, 200, `{"decisions":[{}],"next_cursor":"c2","columns":["decision_id"]}`)
					return
				}
				f.json(w, tc.status, tc.second)
			})
			code, out, errOut := f.run(t, "insights", "search", "--limit", "2")
			if code == 0 || out != "" || errOut == "" || calls != 2 {
				t.Fatalf("exit %d, output %q, error %q, calls %d", code, out, errOut, calls)
			}
		})
	}
}

func TestInsightsSearch_validatesLimitBeforeSending(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	for _, limit := range []string{"0", "-1", "1.5", "null", `"500"`} {
		code, _, errOut := f.run(t, "insights", "search", "--query", fmt.Sprintf(`{"limit":%s}`, limit))
		if code != ExitUsage || !strings.Contains(errOut, "positive whole number") {
			t.Errorf("limit %s: exit %d: %s", limit, code, errOut)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("sent an invalid search")
	}
}

func TestInsightsFlowID_composesWithExistingExpression(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	var body map[string]any
	f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.json(w, 200, `{"decisions":[]}`)
	})
	flowID := `sua_example`
	code, _, errOut := f.run(t, "insights", "search", "--flow-id", flowID, "--expression", `ip.asn.type == "hosting" || asn == 123`, "--filter", "request_type=signup")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := `(ip.asn.type == "hosting" || asn == 123) && (flow_id == ` + strconv.Quote(flowID) + `)`
	if body["expression"] != want || len(body["filter"].([]any)) != 1 {
		t.Fatalf("request = %v", body)
	}
	code, _, errOut = f.run(t, "insights", "search", "--query", `{"unit":"flows","expression":"decision == \"ALLOW\""}`, "--unit", "decisions", "--flow-id", "sua_test")
	if code != 0 || body["unit"] != nil || body["expression"] != `(decision == "ALLOW") && (flow_id == "sua_test")` {
		t.Fatalf("body override: exit %d, body %v: %s", code, body, errOut)
	}
	code, _, errOut = f.run(t, "insights", "search", "--query", `{"unit":"decisions"}`, "--flow-id", "sua_test")
	if code != 0 || body["unit"] != nil || body["expression"] != `flow_id == "sua_test"` {
		t.Fatalf("JSON decisions unit: exit %d, body %v: %s", code, body, errOut)
	}
	for _, args := range [][]string{{"--flow-id", ""}, {"--flow-id", `sua_" || true`}, {"--flow-id", `sua_\test`}, {"--unit", "flows", "--flow-id", "sua_test"}} {
		code, _, errOut := f.run(t, append([]string{"insights", "search"}, args...)...)
		if code != ExitUsage {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
	}
}

func TestInsightsFlowID_requiresSelfContainedExpression(t *testing.T) {
	f := newFakeAPI(t)
	for _, expression := range []string{`asn == 1) || (asn == 2`, `(asn == 1`, `user_agent == "unterminated`} {
		code, out, errOut := f.run(t, "insights", "search", "--flow-id", "sua_example", "--expression", expression)
		if code != ExitUsage || out != "" || !strings.Contains(errOut, "balanced parentheses") {
			t.Errorf("%s: exit %d, output %q, error %q", expression, code, out, errOut)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("sent a malformed combined expression")
	}
	for _, expression := range []string{`(asn == 1 || asn == 2)`, `user_agent.contains(")(")`, `user_agent == "a\"(b"`} {
		if !selfContainedExpression(expression) {
			t.Errorf("rejected complete expression %s", expression)
		}
	}
}

func TestInsightsSearch_boundsCombinedResponse(t *testing.T) {
	for _, tc := range []struct{ padding, limit, calls int }{{32 << 20, 2, 2}, {64 << 20, 1, 1}} {
		t.Run(strconv.Itoa(tc.padding), func(t *testing.T) {
			f := newFakeAPI(t)
			f.signIn(t)
			padding := strings.Repeat("x", tc.padding)
			calls := 0
			f.mux.HandleFunc("POST /labs/api/insights/decisions/search", func(w http.ResponseWriter, _ *http.Request) {
				calls++
				f.json(w, 200, fmt.Sprintf(`{"decisions":[{}],"next_cursor":"c%d","padding":"%s"}`, calls, padding))
			})
			code, out, errOut := f.run(t, "insights", "search", "--limit", strconv.Itoa(tc.limit))
			if code == 0 || out != "" || !strings.Contains(errOut, "reached 64 MiB") || calls != tc.calls {
				t.Fatalf("exit %d, stdout length %d, error %s, calls %d", code, len(out), errOut, calls)
			}
		})
	}
}

func TestInsightsFields_includesAliasesAndNonDimensions(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.mux.HandleFunc("GET /labs/api/insights/dimensions", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, 200, `{"dimensions":[{"key":"asn_type"}],"fields":[{"name":"asn_type","aliases":["ip.asn.type"]},{"name":"flow_id"}]}`)
	})
	code, out, errOut := f.run(t, "insights", "fields")
	if code != 0 || !strings.Contains(out, `"ip.asn.type"`) || !strings.Contains(out, `"flow_id"`) || strings.Contains(out, `"dimensions"`) {
		t.Fatalf("exit %d, output %s: %s", code, out, errOut)
	}
}
