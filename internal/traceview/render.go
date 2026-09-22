package traceview

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/clerk/protect-cli/internal/textsafe"
)

// The only escape sequences the view writes: colour and emphasis.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrDim    = "\x1b[2m"
	sgrInvert = "\x1b[7m"
	sgrRed    = "\x1b[31m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
)

const maxCellWidth = 36

// Render draws the view as height lines, none wider than width cells. The lines
// carry no escape sequence but the colour and emphasis above: every character
// that came from the server is cleaned before it is placed.
func (m *Model) Render(width, height int) []string {
	if width < 20 || height < 6 {
		return []string{fit("Make the window larger.", max(width, 1))}
	}
	lines := []string{m.header(width)}
	body := height - 2
	switch m.mode {
	case modeDetail:
		lines = append(lines, m.renderDetail(width, body)...)
	case modeColumns:
		lines = append(lines, m.renderColumns(width, body)...)
	case modeHelp:
		lines = append(lines, m.renderHelp(width, body)...)
	default:
		lines = append(lines, m.renderTable(width, body)...)
	}
	for len(lines) < height-1 {
		lines = append(lines, "")
	}
	return append(lines, m.footer(width))
}

func (m *Model) stateText() (string, string) {
	switch {
	case m.status == Closed:
		s := "CLOSED"
		if m.statusDetail != "" {
			s += ": " + clean(m.statusDetail)
		}
		return s + " (r reconnects)", sgrRed
	case !m.following:
		if m.newSince > 0 {
			return fmt.Sprintf("PAUSED (+%d new)", m.newSince), sgrYellow
		}
		return "PAUSED", sgrYellow
	case m.status == Renewing:
		return "RENEWING", sgrYellow
	case m.status == Connecting:
		return "CONNECTING", sgrYellow
	}
	return "LIVE", sgrGreen
}

func (m *Model) rate() float64 {
	cutoff := m.now().Add(-rateWindow)
	n := 0
	for i := len(m.arrivals) - 1; i >= 0 && m.arrivals[i].After(cutoff); i-- {
		n++
	}
	return float64(n) / rateWindow.Seconds()
}

func (m *Model) header(width int) string {
	left := " clerk-protect trace  " + clean(m.instance) + "  "
	state, colour := m.stateText()
	right := fmt.Sprintf("  %s decisions  %.1f/s", commas(m.total), m.rate())
	if m.haveStats {
		right += fmt.Sprintf("  engines %d/%d  dropped %s", m.stats.Connected, m.stats.Engines, commas(m.stats.Dropped))
	}
	right += " "
	if runeLen(left)+runeLen(state)+runeLen(right) > width {
		right = ""
	}
	if runeLen(left) >= width {
		return sgrBold + fit(left, width) + sgrReset
	}
	state = fit(state, width-runeLen(left)-runeLen(right))
	return sgrBold + left + sgrReset + colour + state + sgrReset + sgrDim + right + sgrReset
}

func (m *Model) filterLine(width int) string {
	if len(m.filters) == 0 {
		return sgrDim + fit(" no filters · f adds one · ? keys", width) + sgrReset
	}
	parts := make([]string, len(m.filters))
	for i, f := range m.filters {
		parts[i] = clean(f.String())
	}
	return fit(" filters: "+strings.Join(parts, "  "), width)
}

func (m *Model) renderTable(width, n int) []string {
	lines := []string{m.filterLine(width)}
	rows := n - 2
	if rows < 1 {
		return lines
	}
	m.page = max(rows-1, 1)
	vis := m.visible()
	cur := m.cursor(vis)

	start := max(len(vis)-rows, 0)
	if !m.following && cur >= 0 {
		start = sort.Search(len(vis), func(i int) bool { return vis[i].seq >= m.topSeq })
		if cur < start {
			start = cur
		}
		if cur >= start+rows {
			start = cur - rows + 1
		}
		if start+rows > len(vis) {
			start = max(len(vis)-rows, 0)
		}
	}
	window := vis[start:min(start+rows, len(vis))]
	if len(window) > 0 {
		m.topSeq = window[0].seq
	}

	keys, widths := m.layout(window, width)
	labels := make([]string, len(keys))
	for i, key := range keys {
		labels[i] = fit(m.label(key), widths[i])
	}
	lines = append(lines, sgrBold+" "+strings.Join(labels, "  ")+sgrReset)

	if len(vis) == 0 {
		msg := " Waiting for decisions…"
		if len(m.buf) > 0 {
			msg = fmt.Sprintf(" No decisions match the filters (%d received). x clears them.", len(m.buf))
		}
		return append(lines, sgrDim+fit(msg, width)+sgrReset)
	}
	for _, ev := range window {
		selected := !m.following && ev.seq == vis[cur].seq
		plain := make([]string, len(keys))
		coloured := make([]string, len(keys))
		for i, key := range keys {
			v := cell(ev, key)
			plain[i] = fit(v, widths[i])
			coloured[i] = plain[i]
			if key == "decision" {
				if c := decisionColour(v); c != "" {
					coloured[i] = c + plain[i] + sgrReset
				}
			}
		}
		if selected {
			lines = append(lines, sgrInvert+" "+strings.Join(plain, "  ")+sgrReset)
			continue
		}
		lines = append(lines, " "+strings.Join(coloured, "  "))
	}
	return lines
}

// layout picks the columns that fit, and each one's width: its widest value on
// screen, within bounds, with the last one that fits cut to the space left.
func (m *Model) layout(window []event, width int) ([]string, []int) {
	var keys []string
	var widths []int
	used := 1 // the leading space
	for _, key := range m.show {
		w := runeLen(m.label(key))
		for _, ev := range window {
			w = max(w, runeLen(cell(ev, key)))
		}
		w = min(max(w, 3), maxCellWidth)
		sep := 0
		if len(keys) > 0 {
			sep = 2
		}
		if used+sep+w > width {
			if rest := width - used - sep; rest >= 3 {
				keys, widths = append(keys, key), append(widths, rest)
			}
			break
		}
		keys, widths = append(keys, key), append(widths, w)
		used += sep + w
	}
	return keys, widths
}

func (m *Model) renderDetail(width, n int) []string {
	fs := m.fields(m.detail)
	title := " decision"
	if id := m.detail.fields["decisionId"]; id != "" {
		title += " " + clean(id)
	}
	lines := []string{sgrBold + fit(title, width) + sgrReset}
	rows := n - 1
	if rows < 1 {
		return lines
	}
	m.page = max(rows-1, 1)
	keyWidth := 0
	for _, f := range fs {
		keyWidth = max(keyWidth, runeLen(m.label(f.key)))
	}
	keyWidth = min(keyWidth, 28)
	start := max(m.detailRow-rows+1, 0)
	for i := start; i < len(fs) && i < start+rows; i++ {
		line := fit(" "+fit(m.label(fs[i].key), keyWidth)+"  "+clean(fs[i].value), width)
		if i == m.detailRow {
			line = sgrInvert + line + sgrReset
		}
		lines = append(lines, line)
	}
	return lines
}

func (m *Model) renderColumns(width, n int) []string {
	lines := []string{sgrBold + fit(" columns", width) + sgrReset}
	if len(m.columns) == 0 {
		return append(lines, fit(" The server did not describe its columns.", width))
	}
	rows := n - 1
	start := max(m.colRow-rows+1, 0)
	for i := start; i < len(m.columns) && i < start+rows; i++ {
		c := m.columns[i]
		mark := "[ ]"
		if m.showing(c.Key) {
			mark = "[x]"
		}
		line := fit(" "+mark+" "+clean(c.Label)+"  "+clean(c.Group)+"  ("+clean(c.Key)+")", width)
		if i == m.colRow {
			line = sgrInvert + line + sgrReset
		}
		lines = append(lines, line)
	}
	return lines
}

var helpLines = []string{
	" keys",
	"",
	"   q, Ctrl-C       quit",
	"   space, p        pause or resume the stream",
	"   ↑ ↓, j k        select a decision (pauses)",
	"   PgUp PgDn       a page at a time",
	"   g, Home         the oldest decision kept;  G, End  the newest, resuming",
	"   Enter           every field of the selected decision",
	"   f, /            filter: field=value, field!=value, field~text (any case)",
	"                   or field==value (exact case)",
	"   Enter on empty  remove the last filter;  x  clear every filter",
	"   c               choose columns;  r  reconnect a closed stream",
	"",
	" in a decision: ↑ ↓ select a field · f keep its value · e exclude it · Esc back",
}

func (m *Model) renderHelp(width, n int) []string {
	lines := make([]string, 0, n)
	for _, l := range helpLines {
		if len(lines) == n {
			break
		}
		lines = append(lines, fit(l, width))
	}
	return lines
}

func (m *Model) footer(width int) string {
	switch {
	case m.mode == modeFilter:
		prompt := " filter> " + clean(string(m.input)) + "▏"
		if m.message != "" {
			// The error takes only what the prompt leaves, so the footer stays
			// one line: a wrapped footer scrolls the whole view.
			msg := "  " + clean(m.message)
			promptWidth := max(width-runeLen(msg), min(12, width))
			return fit(prompt, promptWidth) + sgrRed + fit(msg, width-promptWidth) + sgrReset
		}
		return fit(prompt, width)
	case m.message != "":
		return sgrYellow + fit(" "+clean(m.message), width) + sgrReset
	case m.mode == modeDetail:
		return sgrDim + fit(" Esc back · ↑↓ select · f keep this value · e exclude it", width) + sgrReset
	case m.mode == modeColumns:
		return sgrDim + fit(" Esc done · ↑↓ select · space shows or hides", width) + sgrReset
	case m.mode == modeHelp:
		return sgrDim + fit(" any key closes", width) + sgrReset
	}
	return sgrDim + fit(" q quit · space pause · ↑↓ select · Enter details · f filter · x clear · c columns · ? keys", width) + sgrReset
}

func (m *Model) label(key string) string {
	if i, ok := m.known[key]; ok && m.columns[i].Label != "" {
		return clean(m.columns[i].Label)
	}
	return clean(key)
}

func cell(ev event, key string) string {
	v := ev.fields[key]
	if key == "timestamp" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			v = t.Local().Format("15:04:05.000")
		}
	}
	return clean(v)
}

func decisionColour(v string) string {
	switch u := strings.ToUpper(v); {
	case strings.Contains(u, "ALLOW"):
		return sgrGreen
	case strings.Contains(u, "DENY") || strings.Contains(u, "BLOCK"):
		return sgrRed
	case strings.Contains(u, "CHALLENGE"):
		return sgrYellow
	}
	return ""
}

// clean makes server text fit to place in one cell: terminal controls removed,
// line breaks and tabs made spaces, and the characters that reorder text on
// screen dropped.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e || r == 0x200f:
			return -1
		}
		return r
	}, textsafe.Strip(s))
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

// fit pads or cuts s to exactly w characters, marking a cut with an ellipsis.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	n := runeLen(s)
	switch {
	case n == w:
		return s
	case n < w:
		return s + strings.Repeat(" ", w-n)
	case w == 1:
		return string([]rune(s)[:1])
	}
	return string([]rune(s)[:w-1]) + "…"
}

func commas(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
