package style

import (
	"strings"
	"testing"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		mode Mode
		tty  bool
		env  map[string]string
		want bool
	}{
		{"auto on a terminal", Auto, true, nil, true},
		{"auto into a pipe", Auto, false, nil, false},
		{"auto with NO_COLOR", Auto, true, map[string]string{"NO_COLOR": "1"}, false},
		{"auto with an empty NO_COLOR", Auto, true, map[string]string{"NO_COLOR": ""}, true},
		{"auto on a dumb terminal", Auto, true, map[string]string{"TERM": "dumb"}, false},
		{"always into a pipe", Always, false, map[string]string{"NO_COLOR": "1"}, true},
		{"never on a terminal", Never, true, nil, false},
	}
	for _, c := range cases {
		if got := Decide(c.mode, c.tty, env(c.env)); got != c.want {
			t.Errorf("%s: Decide = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"auto", "ALWAYS", " never "} {
		if _, err := ParseMode(s); err != nil {
			t.Errorf("ParseMode(%q): %v", s, err)
		}
	}
	if _, err := ParseMode("sometimes"); err == nil {
		t.Error("ParseMode accepted \"sometimes\"")
	}
}

// Server text is stripped BEFORE colour is added, so the only escape
// sequences in a Text are this package's own.
func TestPalette_stripsBeforeColouring(t *testing.T) {
	hostile := "rule\x1b]52;c;ZXZpbA==\x07" + string(rune(0x9b)) + "2J"
	got := string(New(true).Bad(hostile))
	if !strings.HasPrefix(got, "\x1b[31m") || !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("Bad did not colour: %q", got)
	}
	// Without the palette's own two sequences, nothing a terminal acts on is left.
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "\x1b[31m"), "\x1b[0m")
	for _, bad := range []string{"\x1b", "\x07", string(rune(0x9b))} {
		if strings.Contains(inner, bad) {
			t.Fatalf("%q from the server text reached the output: %q", bad, got)
		}
	}
}

func TestPalette_offAddsNothing(t *testing.T) {
	p := New(false)
	for _, got := range []Text{p.Header("NAME"), p.Bad("x"), p.Word("deny"), p.ID("ins_1")} {
		if strings.Contains(string(got), "\x1b") {
			t.Errorf("an uncoloured palette added a sequence: %q", got)
		}
	}
	if got := p.Plain("a\x1b[31mb"); got != "a[31mb" {
		t.Errorf("Plain did not strip: %q", got)
	}
}

func TestWord_coloursByMeaning(t *testing.T) {
	p := New(true)
	for word, code := range map[string]string{"DENY": red, "challenge": yellow, "Allow": green, "off": dim, "succeeded": green, "not set up": yellow} {
		if got := string(p.Word(word)); !strings.HasPrefix(got, "\x1b["+code+"m") {
			t.Errorf("Word(%q) = %q, want colour %s", word, got, code)
		}
	}
	if got := p.Word("something-else"); strings.Contains(string(got), "\x1b") {
		t.Errorf("an unlisted word was coloured: %q", got)
	}
}

func TestVisible(t *testing.T) {
	if got := Visible("\x1b[1mNAME\x1b[0m  x"); got != "NAME  x" {
		t.Errorf("Visible = %q", got)
	}
}

// NEGATIVE CONTROL for the backstop: colour survives, every other sequence —
// an OSC clipboard write, a cursor move, a C1 CSI — does not.
func TestSanitize_keepsColourAndNothingElse(t *testing.T) {
	in := "\x1b[32mok\x1b[0m \x1b]52;c;ZXZpbA==\x07 \x1b[2J " + string(rune(0x9b)) + "H done"
	got := Sanitize(in)
	if !strings.Contains(got, "\x1b[32mok\x1b[0m") {
		t.Errorf("colour was lost: %q", got)
	}
	for _, bad := range []string{"\x1b]", "\x07", string(rune(0x9b))} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived: %q", bad, got)
		}
	}
	// \x1b[2J is not colour (it clears the screen) and must lose its ESC.
	if strings.Contains(got, "\x1b[2J") {
		t.Errorf("a screen clear survived: %q", got)
	}
}
