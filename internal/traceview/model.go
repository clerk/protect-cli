package traceview

import (
	"sort"
	"strings"
	"time"
)

// Status is the stream's state, as the header shows it.
type Status int

// The stream's states.
const (
	Connecting Status = iota
	Live
	Renewing
	Closed
)

// Action is what a key press asks of whatever runs the view.
type Action int

// The actions a key can ask for.
const (
	None Action = iota
	Quit
	Reconnect
)

const (
	defaultBuffer = 2000
	rateWindow    = 5 * time.Second
	maxArrivals   = 10000
)

// Options configure a view.
type Options struct {
	// Instance is shown in the header.
	Instance string
	// Columns are the fields the server describes, in its order.
	Columns []Column
	// Show is the columns visible at first: the server's defaults when empty.
	Show []string
	// Filters apply from the start.
	Filters []Filter
	// Buffer is how many decisions are kept; older ones are let go.
	Buffer int
	// Now is the clock the rate is measured by.
	Now func() time.Time
}

type event struct {
	seq    uint64
	fields map[string]string
}

type mode int

const (
	modeTable mode = iota
	modeDetail
	modeColumns
	modeFilter
	modeHelp
)

// Model is the view's state. It is not safe for concurrent use: whatever runs
// the view feeds it decisions, stream states and keys from one goroutine.
type Model struct {
	instance string
	columns  []Column
	known    map[string]int
	show     []string
	filters  []Filter

	buf      []event
	capacity int
	nextSeq  uint64
	total    uint64
	arrivals []time.Time
	now      func() time.Time

	// following is true while the view tails the newest decision. Otherwise
	// selected (and topSeq, the first row drawn) anchor it by sequence number,
	// so decisions arriving while paused do not move what is on screen.
	following bool
	selected  uint64
	topSeq    uint64
	newSince  int
	page      int

	status       Status
	statusDetail string
	stats        Stats
	haveStats    bool

	mode      mode
	input     []rune
	message   string
	detail    event
	detailRow int
	colRow    int
}

// New builds a view.
func New(o Options) *Model {
	m := &Model{
		instance:  o.Instance,
		columns:   o.Columns,
		known:     make(map[string]int, len(o.Columns)),
		filters:   append([]Filter(nil), o.Filters...),
		capacity:  o.Buffer,
		now:       o.Now,
		following: true,
		page:      10,
	}
	if m.capacity <= 0 {
		m.capacity = defaultBuffer
	}
	if m.now == nil {
		m.now = time.Now
	}
	for i, c := range o.Columns {
		m.known[c.Key] = i
	}
	m.show = append([]string(nil), o.Show...)
	if len(m.show) == 0 {
		for _, c := range o.Columns {
			if c.Default {
				m.show = append(m.show, c.Key)
			}
		}
	}
	return m
}

// Known reports whether a key names a field the server describes. With no
// description at all, any key is accepted.
func (m *Model) Known(key string) bool {
	if len(m.columns) == 0 {
		return true
	}
	_, ok := m.known[key]
	return ok
}

// Add takes one decision.
func (m *Model) Add(fields map[string]string) {
	m.nextSeq++
	m.total++
	m.buf = append(m.buf, event{seq: m.nextSeq, fields: fields})
	if len(m.buf) > m.capacity {
		m.buf = m.buf[len(m.buf)-m.capacity:]
	}
	if !m.following && MatchAll(m.filters, fields) {
		m.newSince++
	}
	now := m.now()
	m.arrivals = append(m.arrivals, now)
	cut := 0
	for cut < len(m.arrivals) && (!m.arrivals[cut].After(now.Add(-rateWindow)) || len(m.arrivals)-cut > maxArrivals) {
		cut++
	}
	m.arrivals = m.arrivals[cut:]
}

// SetStatus records the stream's state, with a detail such as why it closed.
func (m *Model) SetStatus(s Status, detail string) {
	m.status, m.statusDetail = s, detail
}

// SetStats records what the latest status event reported.
func (m *Model) SetStats(s Stats) {
	m.stats, m.haveStats = s, true
}

func (m *Model) visible() []event {
	if len(m.filters) == 0 {
		return m.buf
	}
	out := make([]event, 0, len(m.buf))
	for _, ev := range m.buf {
		if MatchAll(m.filters, ev.fields) {
			out = append(out, ev)
		}
	}
	return out
}

// cursor is the index of the selected decision among the visible ones, or -1.
func (m *Model) cursor(vis []event) int {
	if len(vis) == 0 {
		return -1
	}
	if m.following {
		return len(vis) - 1
	}
	i := sort.Search(len(vis), func(i int) bool { return vis[i].seq >= m.selected })
	return min(i, len(vis)-1)
}

// pauseAt stops following and selects the visible decision at i.
func (m *Model) pauseAt(vis []event, i int) {
	if m.following {
		m.newSince = 0
	}
	m.following = false
	if len(vis) == 0 {
		m.selected = m.nextSeq + 1
		return
	}
	m.selected = vis[max(0, min(i, len(vis)-1))].seq
}

func (m *Model) follow() {
	m.following, m.newSince = true, 0
}

// Key handles one key press.
func (m *Model) Key(k Key) Action {
	if k.Name == "ctrl-c" {
		return Quit
	}
	switch m.mode {
	case modeFilter:
		m.filterKey(k)
		return None
	case modeHelp:
		m.mode = modeTable
		return None
	case modeDetail:
		m.detailKey(k)
		return None
	case modeColumns:
		m.columnsKey(k)
		return None
	}
	m.message = ""
	vis := m.visible()
	i := m.cursor(vis)
	switch {
	case k.is('q'):
		return Quit
	case k.is(' ') || k.is('p'):
		if m.following {
			m.pauseAt(vis, i)
		} else {
			m.follow()
		}
	case k.Name == "down" || k.is('j'):
		m.pauseAt(vis, i+1)
	case k.Name == "up" || k.is('k'):
		m.pauseAt(vis, i-1)
	case k.Name == "pgdn" || k.Name == "ctrl-d":
		m.pauseAt(vis, i+m.page)
	case k.Name == "pgup" || k.Name == "ctrl-u":
		m.pauseAt(vis, i-m.page)
	case k.Name == "home" || k.is('g'):
		m.pauseAt(vis, 0)
	case k.Name == "end" || k.is('G'):
		m.follow()
	case k.Name == "enter":
		if i >= 0 {
			m.detail, m.detailRow, m.mode = vis[i], 0, modeDetail
		}
	case k.is('f') || k.is('/'):
		m.mode, m.input = modeFilter, nil
	case k.is('x'):
		if len(m.filters) > 0 {
			m.filters, m.message = nil, "Filters cleared."
		}
	case k.is('c'):
		m.mode, m.colRow = modeColumns, 0
	case k.is('?'):
		m.mode = modeHelp
	case k.is('r'):
		if m.status == Closed {
			return Reconnect
		}
	}
	return None
}

func (m *Model) filterKey(k Key) {
	switch k.Name {
	case "esc":
		m.mode, m.input, m.message = modeTable, nil, ""
	case "enter":
		text := strings.TrimSpace(string(m.input))
		if text == "" {
			if n := len(m.filters); n > 0 {
				m.message = "Removed filter " + m.filters[n-1].String() + "."
				m.filters = m.filters[:n-1]
			}
			m.mode, m.input = modeTable, nil
			return
		}
		f, err := ParseFilter(text, m.Known)
		if err != nil {
			m.message = err.Error()
			return
		}
		m.filters = append(m.filters, f)
		m.mode, m.input, m.message = modeTable, nil, ""
	case "backspace":
		if n := len(m.input); n > 0 {
			m.input = m.input[:n-1]
		}
		m.message = ""
	case "ctrl-u":
		m.input, m.message = nil, ""
	case "rune":
		if len(m.input) < 200 {
			m.input = append(m.input, k.Rune)
		}
		m.message = ""
	}
}

type field struct{ key, value string }

// fields lists a decision's fields: the described ones in the server's order,
// then any others by name.
func (m *Model) fields(ev event) []field {
	out := make([]field, 0, len(ev.fields))
	seen := make(map[string]bool, len(ev.fields))
	for _, c := range m.columns {
		if v, ok := ev.fields[c.Key]; ok {
			out = append(out, field{c.Key, v})
			seen[c.Key] = true
		}
	}
	var rest []string
	for k := range ev.fields {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, field{k, ev.fields[k]})
	}
	return out
}

func (m *Model) detailKey(k Key) {
	fs := m.fields(m.detail)
	last := max(len(fs)-1, 0)
	switch {
	case k.Name == "esc" || k.Name == "backspace" || k.is('q'):
		m.mode = modeTable
	case k.Name == "down" || k.is('j'):
		m.detailRow = min(m.detailRow+1, last)
	case k.Name == "up" || k.is('k'):
		m.detailRow = max(m.detailRow-1, 0)
	case k.Name == "pgdn" || k.Name == "ctrl-d":
		m.detailRow = min(m.detailRow+m.page, last)
	case k.Name == "pgup" || k.Name == "ctrl-u":
		m.detailRow = max(m.detailRow-m.page, 0)
	case (k.is('f') || k.is('e')) && m.detailRow < len(fs):
		f := Filter{Key: fs[m.detailRow].key, Op: "=", Value: fs[m.detailRow].value}
		if k.is('e') {
			f.Op = "!="
		}
		m.filters = append(m.filters, f)
		m.mode, m.message = modeTable, "Added filter "+f.String()+"."
	}
}

func (m *Model) columnsKey(k Key) {
	switch {
	case k.Name == "esc" || k.is('q') || k.is('c'):
		m.mode = modeTable
	case k.Name == "down" || k.is('j'):
		m.colRow = min(m.colRow+1, max(len(m.columns)-1, 0))
	case k.Name == "up" || k.is('k'):
		m.colRow = max(m.colRow-1, 0)
	case (k.is(' ') || k.Name == "enter") && m.colRow < len(m.columns):
		m.toggle(m.columns[m.colRow].Key)
	}
}

func (m *Model) showing(key string) bool {
	for _, s := range m.show {
		if s == key {
			return true
		}
	}
	return false
}

func (m *Model) toggle(key string) {
	for i, s := range m.show {
		if s == key {
			if len(m.show) == 1 {
				m.message = "At least one column stays visible."
				return
			}
			m.show = append(m.show[:i:i], m.show[i+1:]...)
			return
		}
	}
	m.show = append(m.show, key)
}
