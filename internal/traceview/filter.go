package traceview

import (
	"fmt"
	"strings"
)

// Filter keeps the decisions whose field matches. key=value and key!=value
// compare the whole value and key~text looks for text anywhere in it, all three
// ignoring case, as the console's trace filter does; key==value compares the
// whole value exactly, as --field does.
type Filter struct {
	Key, Op, Value string
}

func (f Filter) String() string { return f.Key + f.Op + f.Value }

// ParseFilter reads one filter. known reports whether a key names a field; nil
// accepts any key.
func ParseFilter(s string, known func(string) bool) (Filter, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, "=!~")
	if i <= 0 {
		return Filter{}, fmt.Errorf("%q: expected field=value, field==value, field!=value or field~text", s)
	}
	f := Filter{Key: strings.TrimSpace(s[:i])}
	switch {
	case strings.HasPrefix(s[i:], "!="):
		f.Op, f.Value = "!=", s[i+2:]
	case strings.HasPrefix(s[i:], "=="):
		f.Op, f.Value = "==", s[i+2:]
	case s[i] == '=':
		f.Op, f.Value = "=", s[i+1:]
	case s[i] == '~':
		f.Op, f.Value = "~", s[i+1:]
	default:
		return Filter{}, fmt.Errorf("%q: expected field=value, field==value, field!=value or field~text", s)
	}
	f.Value = strings.TrimSpace(f.Value)
	if known != nil && !known(f.Key) {
		return Filter{}, fmt.Errorf("%q: there is no field named %q", s, f.Key)
	}
	return f, nil
}

// Match reports whether a decision's fields satisfy the filter. A field the
// decision does not carry is empty.
func (f Filter) Match(fields map[string]string) bool {
	v := fields[f.Key]
	switch f.Op {
	case "==":
		return v == f.Value
	case "=":
		return strings.EqualFold(v, f.Value)
	case "!=":
		return !strings.EqualFold(v, f.Value)
	default:
		return strings.Contains(strings.ToLower(v), strings.ToLower(f.Value))
	}
}

// MatchAll reports whether a decision satisfies every filter.
func MatchAll(filters []Filter, fields map[string]string) bool {
	for _, f := range filters {
		if !f.Match(fields) {
			return false
		}
	}
	return true
}
