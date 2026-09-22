package api

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// Event is one Server-Sent Events frame.
type Event struct {
	Name string
	Data string
}

// ErrStop, returned from a stream handler, ends the stream cleanly.
var ErrStop = errors.New("stop")

// maxEventLine bounds one line of a stream. A decision frame is a few kilobytes;
// a megabyte is a stream that has stopped making sense.
const maxEventLine = 1 << 20

// ReadEvents parses an event stream (the WHATWG format): `event:` names the
// frame, `data:` lines accumulate, a blank line dispatches, a line starting with
// a colon is a comment. A frame with no `event:` is named "message". A partial
// frame at end of stream is dropped, as a browser drops it.
func ReadEvents(r io.Reader, fn func(Event) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxEventLine)
	var name string
	var data []string
	var hasData bool
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			if hasData {
				ev := Event{Name: name, Data: strings.Join(data, "\n")}
				if ev.Name == "" {
					ev.Name = "message"
				}
				if err := fn(ev); err != nil {
					return err
				}
			}
			name, data, hasData = "", nil, false
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			name = value
		case "data":
			data = append(data, value)
			hasData = true
		}
	}
	return sc.Err()
}
