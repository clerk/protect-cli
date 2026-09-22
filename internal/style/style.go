// Package style colours the CLI's human output when it is going to a person.
//
// Colour is decided once per stream. It is on when --color=always, off when
// --color=never, and otherwise (auto) on only when the stream is a terminal,
// NO_COLOR is unset or empty (https://no-color.org), and TERM is not "dumb".
// JSON output is never coloured: a program is reading it.
//
// THE SAFETY RULE this package exists to keep: server text reaches the
// terminal in rule expressions, error messages and decision fields, and every
// piece of it is stripped of control sequences (package textsafe) before it is
// shown. Colour is made of control sequences. So colour is only ever added by
// this package, around text it has stripped itself, and a Text value is
// terminal-safe by construction. Sanitize is the last line: it keeps this
// package's own SGR sequences and strips everything else.
package style

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/clerk/protect-cli/internal/textsafe"
)

// Mode is the --color setting.
type Mode string

const (
	Auto   Mode = "auto"
	Always Mode = "always"
	Never  Mode = "never"
)

// ParseMode reads a --color value.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case Auto, Always, Never:
		return m, nil
	}
	return "", fmt.Errorf("--color must be auto, always or never, not %q", s)
}

// Decide reports whether to colour a stream. getenv is os.Getenv, or a
// stand-in in tests.
func Decide(m Mode, isTerminal bool, getenv func(string) string) bool {
	switch m {
	case Never:
		return false
	case Always:
		return true
	}
	return isTerminal && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}

// Text is a string this package produced: its content was stripped of control
// sequences before any colour was added, so it is safe to write as it is.
type Text string

// Palette colours text for one stream, or passes it through when that stream
// is not coloured.
type Palette struct{ on bool }

// New returns a palette that colours when on is true.
func New(on bool) Palette { return Palette{on: on} }

// On reports whether this palette adds colour.
func (p Palette) On() bool { return p.on }

// SGR parameters. Only these are ever written.
const (
	bold    = "1"
	dim     = "2"
	red     = "31"
	green   = "32"
	yellow  = "33"
	cyan    = "36"
	boldRed = "1;31"
)

func (p Palette) wrap(code, s string) Text {
	s = textsafe.Strip(s)
	if !p.on || s == "" {
		return Text(s)
	}
	return Text("\x1b[" + code + "m" + s + "\x1b[0m")
}

// Plain strips s and adds nothing: for text shown as it is, beside styled text.
func (p Palette) Plain(s string) Text { return Text(textsafe.Strip(s)) }

// Header is a table's column heading.
func (p Palette) Header(s string) Text { return p.wrap(bold, s) }

// Label is the name half of a name–value line.
func (p Palette) Label(s string) Text { return p.wrap(dim, s) }

// ID is an identifier a person may copy: an instance, rule, replay or profile.
func (p Palette) ID(s string) Text { return p.wrap(cyan, s) }

// Emphasis is text that should stand out without meaning good or bad.
func (p Palette) Emphasis(s string) Text { return p.wrap(bold, s) }

// Muted is secondary text.
func (p Palette) Muted(s string) Text { return p.wrap(dim, s) }

// Good is success.
func (p Palette) Good(s string) Text { return p.wrap(green, s) }

// Warn is something to notice.
func (p Palette) Warn(s string) Text { return p.wrap(yellow, s) }

// Bad is failure.
func (p Palette) Bad(s string) Text { return p.wrap(red, s) }

// ErrorPrefix is the "Error:" that starts a failure message.
func (p Palette) ErrorPrefix(s string) Text { return p.wrap(boldRed, s) }

// words colours a value by what it means: a decision, a rule action, a
// protection's state, a replay's status. Matched whole and case-insensitively;
// a word not listed is shown plain.
var words = map[string]string{
	// Stopped, refused, broken.
	"deny": red, "denied": red, "block": red, "blocked": red,
	"failed": red, "error": red, "invalid": red,
	// Asked to prove something, or still in flight.
	"challenge": yellow, "challenged": yellow, "captcha": yellow,
	"queued": yellow, "running": yellow, "pending": yellow, "not set up": yellow,
	// Let through, working, done.
	"allow": green, "allowed": green, "on": green, "enabled": green,
	"succeeded": green, "applied": green, "valid": green, "ok": green,
	// Present but doing nothing.
	"off": dim, "disabled": dim, "shadow": dim, "log": dim, "none": dim,
}

// Word colours s by its meaning when it is one of the words above.
func (p Palette) Word(s string) Text {
	if code, ok := words[strings.ToLower(strings.TrimSpace(s))]; ok {
		return p.wrap(code, s)
	}
	return p.Plain(s)
}

// sgr matches exactly the sequences this package writes.
var sgr = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Visible is s as a terminal shows it: without colour. Its length is what a
// column must be measured by.
func Visible(s string) string { return sgr.ReplaceAllString(s, "") }

// Sanitize keeps colour (SGR) sequences and strips every other control
// sequence and character. Arguments are made safe one by one before they are
// formatted; this pass is the backstop for text that reached a line some other
// way, and it can let through at most a colour change — never a cursor move, a
// title, or a clipboard write.
func Sanitize(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range sgr.FindAllStringIndex(s, -1) {
		b.WriteString(textsafe.Strip(s[last:m[0]]))
		b.WriteString(s[m[0]:m[1]])
		last = m[1]
	}
	b.WriteString(textsafe.Strip(s[last:]))
	return b.String()
}

// JSON colours indented JSON for a terminal: keys cyan, strings green, and
// numbers, booleans and null yellow. It strips s first, as every method does,
// and returns it unchanged apart from that when the palette is off or s is
// not JSON-shaped — a token it does not recognise is written as it stands.
func (p Palette) JSON(s string) Text {
	s = textsafe.Strip(s)
	if !p.on {
		return Text(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, len(s))
			code := "32"
			if k := strings.TrimLeft(s[j:], " "); strings.HasPrefix(k, ":") {
				code = "36"
			}
			b.WriteString("\x1b[" + code + "m" + s[i:j] + "\x1b[0m")
			i = j
		case c == '-' || (c >= '0' && c <= '9') || c == 't' || c == 'f' || c == 'n':
			j := i
			for j < len(s) && !strings.ContainsRune(",]} \n\t:", rune(s[j])) {
				j++
			}
			b.WriteString("\x1b[33m" + s[i:j] + "\x1b[0m")
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return Text(b.String())
}
