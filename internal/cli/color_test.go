package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/clerk/protect-cli/internal/style"
)

// runTTY runs a command as if stdout and stderr were terminals, with env as
// the only environment colour is decided from.
func (f *fakeAPI) runTTY(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(""), &out, &errOut, func() bool { return true })
	a.streamIsTerminal = func(io.Writer) bool { return true }
	a.getenv = func(k string) string { return env[k] }
	code := a.execute(args)
	return code, out.String(), errOut.String()
}

const esc = "\x1b["

func TestColor_onATerminalTablesAreColouredAndStillAligned(t *testing.T) {
	f := newFakeAPI(t)
	clearProfileEnv(t)
	if code, _, errOut := f.runBare(t, "profile", "set", "work", "--instance", "ins_2bbb"); code != ExitOK {
		t.Fatalf("profile set: %s", errOut)
	}
	if code, _, errOut := f.runBare(t, "profile", "set", "a-much-longer-name", "--instance", "ins_3ccc"); code != ExitOK {
		t.Fatalf("profile set: %s", errOut)
	}
	code, out, errOut := f.runTTY(t, map[string]string{"TERM": "xterm-256color"}, "profile", "list")
	if code != ExitOK {
		t.Fatalf("profile list: %s", errOut)
	}
	if !strings.Contains(out, esc+"1mNAME"+esc+"0m") {
		t.Errorf("the header is not bold:\n%q", out)
	}
	if !strings.Contains(out, esc+"36mwork"+esc+"0m") {
		t.Errorf("the profile name is not coloured as an id:\n%q", out)
	}
	// Colour takes no columns: once it is removed, the instance column lines up.
	var cols []int
	for _, line := range strings.Split(strings.TrimRight(style.Visible(out), "\n"), "\n") {
		cols = append(cols, strings.Index(line, "ins_"))
	}
	if len(cols) != 3 || cols[1] < 0 || cols[1] != cols[2] {
		t.Errorf("the instance column is not aligned (%v):\n%s", cols, style.Visible(out))
	}
}

func TestColor_offWhenNotATerminal(t *testing.T) {
	f := newFakeAPI(t)
	clearProfileEnv(t)
	_, _, _ = f.runBare(t, "profile", "set", "work", "--instance", "ins_2bbb")
	if _, out, _ := f.runBare(t, "profile", "list", "--color", "auto"); strings.Contains(out, "\x1b") {
		t.Fatalf("piped output carries colour: %q", out)
	}
}

func TestColor_neverOrNoColorOrJSONColoursNothing(t *testing.T) {
	f := newFakeAPI(t)
	clearProfileEnv(t)
	_, _, _ = f.runBare(t, "profile", "set", "work", "--instance", "ins_2bbb")
	for name, tc := range map[string]struct {
		env  map[string]string
		args []string
	}{
		"--color=never": {map[string]string{"TERM": "xterm"}, []string{"profile", "list", "--color", "never"}},
		"NO_COLOR":      {map[string]string{"TERM": "xterm", "NO_COLOR": "1"}, []string{"profile", "list"}},
		"TERM=dumb":     {map[string]string{"TERM": "dumb"}, []string{"profile", "list"}},
		"--json":        {map[string]string{"TERM": "xterm"}, []string{"profile", "list", "--json", "--color", "always"}},
	} {
		code, out, errOut := f.runTTY(t, tc.env, tc.args...)
		if code != ExitOK {
			t.Fatalf("%s: code %d: %s", name, code, errOut)
		}
		if strings.Contains(out, "\x1b") {
			t.Errorf("%s: output carries colour: %q", name, out)
		}
	}
}

func TestColor_alwaysColoursAPipe(t *testing.T) {
	f := newFakeAPI(t)
	clearProfileEnv(t)
	_, _, _ = f.runBare(t, "profile", "set", "work", "--instance", "ins_2bbb")
	if _, out, _ := f.runBare(t, "profile", "list", "--color", "always"); !strings.Contains(out, esc) {
		t.Fatalf("--color=always did not colour: %q", out)
	}
}

func TestColor_badValueIsAUsageError(t *testing.T) {
	f := newFakeAPI(t)
	if code, _, errOut := f.runBare(t, "profile", "list", "--color", "sometimes"); code != ExitUsage {
		t.Fatalf("code %d, want %d: %s", code, ExitUsage, errOut)
	}
}

// A flag mistake is reported before cobra has parsed --color, and still as it asks.
func TestColor_neverHoldsForAFlagMistake(t *testing.T) {
	f := newFakeAPI(t)
	env := map[string]string{"TERM": "xterm"}
	code, _, errOut := f.runTTY(t, env, "--color", "never", "profile", "list", "--no-such-flag")
	if code != ExitUsage || strings.Contains(errOut, "\x1b") {
		t.Fatalf("code %d, stderr %q", code, errOut)
	}
	if _, _, errOut := f.runTTY(t, env, "profile", "list", "--no-such-flag"); !strings.Contains(errOut, esc+"1;31mError:") {
		t.Fatalf("a terminal's flag mistake is not in colour: %q", errOut)
	}
}

// Server text reaches a coloured line only through safef, which strips it;
// the palette's own sequences are the only ones that survive.
func TestSafef_stripsServerTextButKeepsStyle(t *testing.T) {
	p := style.New(true)
	got := safef("%s %s %d %v\n", p.Good("ok"), "evil\x1b]52;c;ZXZpbA==\x07\x1b[2J", 3, true)
	// Strip removes the control bytes; what printable text they carried stays.
	if v := style.Visible(got); strings.ContainsAny(v, "\x1b\x07") {
		t.Fatalf("server text kept a control sequence: %q", got)
	}
	if !strings.Contains(got, esc+"32mok"+esc+"0m") || !strings.Contains(style.Visible(got), "ok evil") ||
		!strings.HasSuffix(got, " 3 true\n") {
		t.Fatalf("safef lost the styled or plain text: %q", got)
	}
}
