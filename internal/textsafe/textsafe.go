// Package textsafe makes text that came from the server safe to put on a
// terminal.
package textsafe

import (
	"strings"
	"unicode/utf8"
)

// Strip removes what a terminal would act on rather than show: every C0
// control except newline and tab (so ESC, BEL, carriage return, backspace),
// DEL, and every C1 control. A byte that is not valid UTF-8 becomes U+FFFD,
// because a lone 0x9B is the one-byte form of the ESC [ that starts a control
// sequence.
//
// Server text reaches a person's terminal in error messages, rule expressions,
// decision fields and replay reports. An escape sequence in any of them could
// rewrite what is on screen, retitle the window, or — through OSC 52 — write to
// the clipboard of whoever ran the command. JSON output is not passed through
// here: JSON escapes its control characters, and a program reading it wants the
// value unchanged.
func Strip(s string) string {
	if plain(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteRune(utf8.RuneError)
		case isControl(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isControl(r rune) bool {
	return (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// plain reports whether s is printable ASCII, newlines and tabs — the common
// case, which needs no copy.
func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x7f || (c < 0x20 && c != '\n' && c != '\t') {
			return false
		}
	}
	return true
}
