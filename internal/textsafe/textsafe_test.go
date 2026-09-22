package textsafe

import (
	"strings"
	"testing"
)

func TestStrip(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain text is untouched", "rule not found", "rule not found"},
		{"newlines and tabs survive", "line one\n\tline two", "line one\n\tline two"},
		{"OSC 52 clipboard write", "copy \x1b]52;c;ZXZpbA==\x07this", "copy ]52;c;ZXZpbA==this"},
		{"screen clear and cursor home", "\x1b[2J\x1b[Hlooks clean", "[2J[Hlooks clean"},
		{"cursor up over the previous line", "ok\x1b[1A\x1b[2Kforged", "ok[1A[2Kforged"},
		{"carriage return overwrite", "Error: denied\x0dSuccess     ", "Error: deniedSuccess     "},
		// U+009B, the C1 control sequence introducer, encoded as UTF-8.
		{"C1 CSI as a code point", "a\xc2\x9b31mb", "a31mb"},
		{"C1 CSI as a lone byte", "a\x9b31mb", "a\xef\xbf\xbd31mb"},
		{"DEL and backspace", "ab\x7f\x08c", "abc"},
		{"non-ASCII text survives", "h\xc3\xa9llo \xe2\x9c\x93", "h\xc3\xa9llo \xe2\x9c\x93"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Strip(tc.in)
			if got != tc.want {
				t.Fatalf("Strip(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for _, c := range []byte(got) {
				if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
					t.Fatalf("Strip(%q) left control byte 0x%02x", tc.in, c)
				}
			}
			if strings.ContainsRune(got, rune(0x9b)) {
				t.Fatalf("Strip(%q) left a C1 control", tc.in)
			}
		})
	}
}
