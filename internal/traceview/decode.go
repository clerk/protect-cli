// Package traceview is the interactive view of the live decision stream: the
// decisions received, the columns and filters a person chooses, what is
// selected, and how all of it is drawn — with no terminal in it, so every part
// is tested as plain text.
//
// EVERYTHING DRAWN THAT CAME FROM THE SERVER IS CLEANED, CELL BY CELL: a
// decision's values, a column's label, a filter built from a value. This view
// is where a decision field reaches a person's screen most directly, and a
// field such as a user agent is whatever the client sent.
package traceview

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Column is one field the server describes: the key it has in a decision, and
// how the view names and groups it.
type Column struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Group   string `json:"group"`
	Default bool   `json:"default"`
}

// Stats is what a status event reports about the stream.
type Stats struct {
	Engines   int    `json:"engines"`
	Connected int    `json:"connected"`
	Dropped   uint64 `json:"dropped"`
	Foreign   uint64 `json:"foreign"`
}

// Decode reads one decision into the text the view shows and filters on.
// Strings are kept as sent — 64-bit integers arrive as strings — numbers and
// booleans as written, lists of plain values joined with ", ", and anything
// else as compact JSON.
func Decode(data []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = text(v)
	}
	return out, nil
}

func text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			switch e.(type) {
			case map[string]any, []any:
				return compact(x)
			}
			parts = append(parts, text(e))
		}
		return strings.Join(parts, ", ")
	default:
		return compact(x)
	}
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
