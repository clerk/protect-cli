package traceview

import "unicode/utf8"

// Key is one key press. Name is "rune" for a character, in Rune; otherwise one
// of up, down, left, right, pgup, pgdn, home, end, delete, enter, esc,
// backspace, tab, ctrl-c, ctrl-d, ctrl-u, or unknown.
type Key struct {
	Name string
	Rune rune
}

func (k Key) is(r rune) bool { return k.Name == "rune" && k.Rune == r }

// ParseKeys splits what a terminal sent into key presses: characters, control
// bytes, and the escape sequences arrow and page keys send (as a VT-style
// terminal, or a Windows console with virtual-terminal input, sends them). An
// escape sequence cut off at the end of the read is dropped rather than read as
// the keys it would spell.
func ParseKeys(b []byte) []Key {
	var keys []Key
	for len(b) > 0 {
		c := b[0]
		switch {
		case c == 0x1b:
			if len(b) >= 2 && (b[1] == '[' || b[1] == 'O') {
				j := 2
				for j < len(b) && b[j] >= 0x20 && b[j] <= 0x3f {
					j++
				}
				if j >= len(b) {
					return keys
				}
				keys = append(keys, sequenceKey(string(b[2:j]), b[j]))
				b = b[j+1:]
				continue
			}
			keys = append(keys, Key{Name: "esc"})
			b = b[1:]
		case c == '\r' || c == '\n':
			keys = append(keys, Key{Name: "enter"})
			b = b[1:]
		case c == 0x7f || c == 0x08:
			keys = append(keys, Key{Name: "backspace"})
			b = b[1:]
		case c == '\t':
			keys = append(keys, Key{Name: "tab"})
			b = b[1:]
		case c == 0x03:
			keys = append(keys, Key{Name: "ctrl-c"})
			b = b[1:]
		case c == 0x04:
			keys = append(keys, Key{Name: "ctrl-d"})
			b = b[1:]
		case c == 0x15:
			keys = append(keys, Key{Name: "ctrl-u"})
			b = b[1:]
		case c < 0x20:
			b = b[1:]
		default:
			r, size := utf8.DecodeRune(b)
			b = b[size:]
			if r != utf8.RuneError {
				keys = append(keys, Key{Name: "rune", Rune: r})
			}
		}
	}
	return keys
}

func sequenceKey(params string, final byte) Key {
	switch final {
	case 'A':
		return Key{Name: "up"}
	case 'B':
		return Key{Name: "down"}
	case 'C':
		return Key{Name: "right"}
	case 'D':
		return Key{Name: "left"}
	case 'H':
		return Key{Name: "home"}
	case 'F':
		return Key{Name: "end"}
	case '~':
		switch params {
		case "1", "7":
			return Key{Name: "home"}
		case "4", "8":
			return Key{Name: "end"}
		case "3":
			return Key{Name: "delete"}
		case "5":
			return Key{Name: "pgup"}
		case "6":
			return Key{Name: "pgdn"}
		}
	}
	return Key{Name: "unknown"}
}
