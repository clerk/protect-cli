package traceview

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var testColumns = []Column{
	{Key: "timestamp", Label: "Time", Group: "Decision", Default: true},
	{Key: "decision", Label: "Decision", Group: "Decision", Default: true},
	{Key: "sourceIp", Label: "IP", Group: "Network", Default: true},
	{Key: "userAgent", Label: "User agent", Group: "Client"},
}

func newTestModel(buffer int) (*Model, *time.Time) {
	clock := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	m := New(Options{Instance: "ins_2abc", Columns: testColumns, Buffer: buffer, Now: func() time.Time { return clock }})
	return m, &clock
}

func press(m *Model, keys ...Key) Action {
	var last Action
	for _, k := range keys {
		last = m.Key(k)
	}
	return last
}

func r(c rune) Key { return Key{Name: "rune", Rune: c} }

func named(n string) Key { return Key{Name: n} }

func typeText(m *Model, s string) {
	for _, c := range s {
		m.Key(r(c))
	}
}

func TestDecode(t *testing.T) {
	got, err := Decode([]byte(`{"decisionId":"d1","durationMs":"12","botScore":0.5,"ok":true,"anonymizerTypes":["vpn","tor"],"nested":{"a":1},"none":null}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"decisionId": "d1", "durationMs": "12", "botScore": "0.5", "ok": "true",
		"anonymizerTypes": "vpn, tor", "nested": `{"a":1}`, "none": "",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, err := Decode([]byte(`[1]`)); err == nil {
		t.Error("a decision that is not an object was accepted")
	}
}

func TestParseFilter(t *testing.T) {
	known := func(k string) bool { return k == "decision" || k == "sourceIp" }
	fields := map[string]string{"decision": "DENY", "sourceIp": "10.1.2.3"}
	for _, tc := range []struct {
		in    string
		match bool
	}{
		{"decision=deny", true},
		{"decision = DENY ", true},
		{"decision==DENY", true},
		{"decision==deny", false},
		{"decision!=deny", false},
		{"decision!=allow", true},
		{"sourceIp~10.1", true},
		{"sourceIp~192.", false},
	} {
		f, err := ParseFilter(tc.in, known)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if f.Match(fields) != tc.match {
			t.Errorf("%q matched %v, want %v", tc.in, !tc.match, tc.match)
		}
	}
	for _, bad := range []string{"decision", "=deny", "nope=1", "decision!deny"} {
		if _, err := ParseFilter(bad, known); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestParseKeys(t *testing.T) {
	got := ParseKeys([]byte("\x1b[A\x1b[B\x1b[5~\x1b[6~\x1b[H\x1b[F\x1bOA\x1bq\r\x7f\x03é"))
	want := []Key{
		named("up"), named("down"), named("pgup"), named("pgdn"), named("home"), named("end"), named("up"),
		named("esc"), r('q'), named("enter"), named("backspace"), named("ctrl-c"), r('é'),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d = %v, want %v", i, got[i], want[i])
		}
	}
	if keys := ParseKeys([]byte("\x1b[")); len(keys) != 0 {
		t.Errorf("a cut-off sequence became keys: %v", keys)
	}
	if keys := ParseKeys([]byte("\x1b")); len(keys) != 1 || keys[0].Name != "esc" {
		t.Errorf("a lone escape: %v", keys)
	}
}

// Selecting pauses the view: decisions arriving while paused move neither the
// selection nor the rows on screen — the view does not scroll to them — and are
// counted in the header until G resumes following.
func TestModel_aPausedViewHoldsStillWhileDecisionsArrive(t *testing.T) {
	m, _ := newTestModel(100)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		m.Add(map[string]string{"decision": "ALLOW", "sourceIp": ip})
	}
	// Seven lines leave three rows for decisions.
	const width, height = 80, 7
	press(m, named("up")) // pauses on the second of three
	vis := m.visible()
	if m.following || vis[m.cursor(vis)].fields["sourceIp"] != "10.0.0.2" {
		t.Fatalf("up did not pause on the previous decision")
	}
	rows := func() string { return strings.Join(m.Render(width, height)[3:6], "\n") }
	before := rows()
	m.Add(map[string]string{"decision": "DENY", "sourceIp": "10.0.0.4"})
	m.Add(map[string]string{"decision": "DENY", "sourceIp": "10.0.0.5"})
	vis = m.visible()
	if vis[m.cursor(vis)].fields["sourceIp"] != "10.0.0.2" {
		t.Fatal("the selection moved while paused")
	}
	if after := rows(); after != before || strings.Contains(after, "10.0.0.5") {
		t.Fatalf("the rows moved while paused:\nbefore\n%s\nafter\n%s", before, after)
	}
	if head := m.Render(width, height)[0]; !strings.Contains(head, "PAUSED (+2 new)") {
		t.Fatalf("header %q does not count the new decisions", head)
	}
	press(m, r('G'))
	if !m.following || !strings.Contains(rows(), "10.0.0.5") {
		t.Fatalf("G did not resume on the newest decision:\n%s", rows())
	}
}

func TestModel_theBufferKeepsTheNewest(t *testing.T) {
	m, _ := newTestModel(5)
	for range 8 {
		m.Add(map[string]string{"decision": "ALLOW"})
	}
	if len(m.buf) != 5 || m.buf[0].seq != 4 || m.total != 8 {
		t.Fatalf("kept %d from seq %d of %d", len(m.buf), m.buf[0].seq, m.total)
	}
}

// The detail view lists every field, and f or e there becomes a filter on that
// field's value.
func TestModel_filtersFromADecisionsFields(t *testing.T) {
	m, _ := newTestModel(100)
	m.Add(map[string]string{"decision": "ALLOW", "sourceIp": "10.0.0.1"})
	m.Add(map[string]string{"decision": "DENY", "sourceIp": "10.0.0.2", "extra": "x"})
	press(m, named("enter"))
	if m.mode != modeDetail {
		t.Fatal("enter did not open the decision")
	}
	fs := m.fields(m.detail)
	if len(fs) != 3 || fs[0].key != "decision" || fs[2].key != "extra" {
		t.Fatalf("fields %v: want the described ones in order, then the rest", fs)
	}
	press(m, r('f'))
	if m.mode != modeTable || len(m.filters) != 1 || m.filters[0].String() != "decision=DENY" {
		t.Fatalf("f did not add decision=DENY: %v", m.filters)
	}
	if vis := m.visible(); len(vis) != 1 || vis[0].fields["sourceIp"] != "10.0.0.2" {
		t.Fatalf("the filter did not narrow the rows: %v", vis)
	}
	press(m, r('x'), named("enter"), r('e'))
	if len(m.filters) != 1 || m.filters[0].String() != "decision!=DENY" {
		t.Fatalf("e did not exclude the value: %v", m.filters)
	}
}

func TestModel_theFilterPrompt(t *testing.T) {
	m, _ := newTestModel(100)
	press(m, r('f'))
	typeText(m, "nope=1")
	press(m, named("enter"))
	if m.mode != modeFilter || !strings.Contains(m.message, "no field named") {
		t.Fatalf("an unknown field: mode %v message %q", m.mode, m.message)
	}
	press(m, named("ctrl-u"))
	typeText(m, "sourceIp~10.")
	press(m, named("enter"))
	if m.mode != modeTable || len(m.filters) != 1 || m.filters[0].String() != "sourceIp~10." {
		t.Fatalf("filters %v mode %v", m.filters, m.mode)
	}
	press(m, r('/'), named("enter"))
	if len(m.filters) != 0 {
		t.Fatalf("enter on an empty prompt did not remove the last filter: %v", m.filters)
	}
	press(m, r('f'), r('x'), named("esc"))
	if m.mode != modeTable || len(m.filters) != 0 {
		t.Fatal("esc did not leave the prompt without a filter")
	}
}

func TestModel_choosingColumns(t *testing.T) {
	m, _ := newTestModel(100)
	if strings.Join(m.show, ",") != "timestamp,decision,sourceIp" {
		t.Fatalf("defaults %v", m.show)
	}
	press(m, r('c'), r('j'), r('j'), r('j'), r(' '), named("esc"))
	if strings.Join(m.show, ",") != "timestamp,decision,sourceIp,userAgent" {
		t.Fatalf("show %v after toggling userAgent on", m.show)
	}
	m.show = []string{"decision"}
	press(m, r('c'), r('j'), r(' '))
	if len(m.show) != 1 || !strings.Contains(m.message, "At least one column") {
		t.Fatalf("the last visible column was hidden: %v", m.show)
	}
}

func TestModel_rateStatsAndReconnect(t *testing.T) {
	m, clock := newTestModel(100)
	for range 10 {
		m.Add(map[string]string{"decision": "ALLOW"})
	}
	m.SetStatus(Live, "")
	m.SetStats(Stats{Engines: 3, Connected: 2, Dropped: 1234})
	head := m.Render(120, 10)[0]
	for _, want := range []string{"LIVE", "10 decisions", "2.0/s", "engines 2/3", "dropped 1,234"} {
		if !strings.Contains(head, want) {
			t.Errorf("header %q lacks %q", head, want)
		}
	}
	*clock = clock.Add(6 * time.Second)
	if head := m.Render(120, 10)[0]; !strings.Contains(head, "0.0/s") {
		t.Errorf("the rate did not fall: %q", head)
	}
	if press(m, r('r')) != None {
		t.Error("r reconnected a live stream")
	}
	m.SetStatus(Closed, "the server closed the stream")
	if press(m, r('r')) != Reconnect || !strings.Contains(m.Render(120, 10)[0], "CLOSED") {
		t.Error("r did not ask to reconnect a closed stream")
	}
	if press(m, named("ctrl-c")) != Quit || press(m, r('q')) != Quit {
		t.Error("ctrl-c and q do not quit")
	}
}

// The key help fits a small 80×18 window whole. The view cuts a wider line and
// drops the lines past the window's bottom, and whatever is cut is a key nobody
// then learns about.
func TestHelp_fitsASmallWindow(t *testing.T) {
	for i, line := range helpLines {
		if n := utf8.RuneCountInString(line); n > 80 {
			t.Errorf("help line %d is %d wide: %q", i, n, line)
		}
	}
	m, _ := newTestModel(100)
	press(m, r('?'))
	if drawn := strings.Join(m.Render(80, 18), "\n"); !strings.Contains(drawn, "Esc back") {
		t.Errorf("the help's last line does not fit an 18-row window:\n%s", drawn)
	}
}

var ownEscapes = regexp.MustCompile(`\x1b\[(0|1|2|7|31|32|33)m`)

// What the view draws is never wider than the window, and carries no escape
// sequence but its own colours — whatever the server put in a decision field, a
// column label or an instance name.
func TestRender_staysInsideTheWindowAndWritesOnlyItsOwnEscapes(t *testing.T) {
	// OSC 52 (write the clipboard), BEL, clear screen, the one-byte C1 form of
	// ESC [, a right-to-left override, and a line break.
	evil := "\x1b]52;c;ZXZpbA==\x07\x1b[2J" + string(rune(0x9b)) + "1A" + string(rune(0x202e)) + "evil\r\nnext"
	columns := append([]Column(nil), testColumns...)
	columns[3].Label = "User agent" + evil
	m := New(Options{Instance: "ins_2abc" + evil, Columns: columns, Show: []string{"timestamp", "decision", "sourceIp", "userAgent"}})
	for range 30 {
		m.Add(map[string]string{
			"timestamp": "2026-09-14T12:00:00.123Z", "decision": "DENY" + evil,
			"sourceIp": "10.0.0.1", "userAgent": strings.Repeat("Mozilla/5.0 界 ", 20) + evil, "decisionId": "d" + evil,
		})
	}
	m.filters = []Filter{{Key: "userAgent", Op: "~", Value: "mozilla" + evil}}
	m.SetStatus(Closed, "reason"+evil)

	check := func(label string, lines []string, width int) {
		t.Helper()
		for i, line := range lines {
			plain := ownEscapes.ReplaceAllString(line, "")
			if n := utf8.RuneCountInString(plain); n > width {
				t.Errorf("%s line %d is %d wide, over %d: %q", label, i, n, width, line)
			}
			for _, c := range plain {
				if c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) || (c >= 0x202a && c <= 0x202e) {
					t.Errorf("%s line %d carries control %U: %q", label, i, c, line)
					break
				}
			}
		}
	}
	for _, width := range []int{20, 60, 200} {
		check("table", m.Render(width, 14), width)
		press(m, named("up"), named("enter"))
		check("detail", m.Render(width, 14), width)
		press(m, named("esc"), r('c'), r('j'), r('j'), r('j'))
		check("columns", m.Render(width, 14), width)
		press(m, named("esc"), r('?'))
		check("help", m.Render(width, 14), width)
		press(m, r(' '), r('f'))
		typeText(m, "userAgent~"+evil)
		check("prompt", m.Render(width, 14), width)
		// A mistyped filter leaves its error beside the prompt, which must still
		// fit on the one footer line.
		press(m, named("ctrl-u"))
		typeText(m, "nope=1"+evil)
		press(m, named("enter"))
		if m.message == "" {
			t.Fatal("an unknown field left no error in the prompt")
		}
		check("prompt error", m.Render(width, 14), width)
		press(m, named("esc"))
	}
}
