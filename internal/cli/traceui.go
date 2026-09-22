package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/term"
	"github.com/clerk/protect-cli/internal/traceview"
)

// errNoTraceView means the interactive view cannot run on this terminal, and
// trace prints lines instead.
var errNoTraceView = errors.New("the interactive view is not available")

// traceMsg is one thing a stream tells the view. gen names the stream it came
// from, so a stream already replaced by a reconnect cannot speak for the new one.
type traceMsg struct {
	gen      int
	decision map[string]string
	stats    *traceview.Stats
	state    *traceview.Status
	done     bool
	reason   string
	err      error
}

// runTraceView runs the interactive view on a terminal until q, Ctrl-C, or the
// context ends.
//
// THE TERMINAL IS PUT BACK ON EVERY WAY OUT — a return, a panic unwinding
// through here, or a signal that ends the context — because a terminal left in
// raw mode, on the alternate screen with no cursor, is unusable until it is
// reset by hand.
func (a *app) runTraceView(ctx context.Context, in, out *os.File, c *api.Client, session *auth.Session, opts traceview.Options) error {
	if w, h, err := term.Size(out.Fd()); err != nil || w <= 0 || h <= 0 {
		return errNoTraceView
	}
	saved, err := term.MakeRaw(in.Fd(), out.Fd())
	if err != nil {
		a.notef("The interactive view is not available here (%v); printing decisions instead.\n", err)
		return errNoTraceView
	}
	_, _ = io.WriteString(out, "\x1b[?1049h\x1b[?25l")
	defer func() {
		_, _ = io.WriteString(out, "\x1b[0m\x1b[?25h\x1b[?1049l")
		_ = term.Restore(in.Fd(), out.Fd(), saved)
	}()
	// Raw mode turns Ctrl-C into a key, which the view handles. These are the
	// signals that can still end the process from outside.
	ctx, stopSignals := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()

	view := traceview.New(opts)
	msgs := make(chan traceMsg, 1024)
	keys := make(chan []byte, 64)
	go readKeys(in, keys)

	gen := 0
	stop := func() {}
	defer func() { stop() }()
	start := func() {
		stop()
		gen++
		var streamCtx context.Context
		streamCtx, stop = context.WithCancel(ctx)
		view.SetStatus(traceview.Connecting, "")
		go a.feedTraceView(streamCtx, gen, c, session, msgs)
	}
	start()

	var lastW, lastH int
	draw := func() {
		w, h, err := term.Size(out.Fd())
		if err != nil || w <= 0 || h <= 0 {
			w, h = max(lastW, 80), max(lastH, 24)
		}
		lastW, lastH = w, h
		lines := view.Render(w, h)
		var b strings.Builder
		for i, line := range lines {
			fmt.Fprintf(&b, "\x1b[%d;1H\x1b[2K%s\x1b[0m", i+1, line)
		}
		if len(lines) < h {
			fmt.Fprintf(&b, "\x1b[%d;1H\x1b[J", len(lines)+1)
		}
		_, _ = io.WriteString(out, b.String())
	}
	draw()

	var streamErr error
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	dirty, ticks := false, 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case b, ok := <-keys:
			if !ok {
				return streamErr
			}
			for _, k := range traceview.ParseKeys(b) {
				switch view.Key(k) {
				case traceview.Quit:
					return streamErr
				case traceview.Reconnect:
					streamErr = nil
					start()
				}
			}
			draw()
		case m := <-msgs:
			if m.gen != gen {
				continue
			}
			switch {
			case m.decision != nil:
				view.Add(m.decision)
			case m.stats != nil:
				view.SetStats(*m.stats)
			case m.state != nil:
				view.SetStatus(*m.state, "")
			case m.done:
				detail := m.reason
				if m.err != nil {
					detail, streamErr = m.err.Error(), m.err
				}
				if detail == "" {
					detail = "the stream ended"
				}
				view.SetStatus(traceview.Closed, detail)
			}
			dirty = true
		case <-ticker.C:
			ticks++
			if w, h, err := term.Size(out.Fd()); err == nil && (w != lastW || h != lastH) {
				dirty = true
			}
			// At most ten frames a second however fast decisions arrive, and one a
			// second regardless, so the rate falls when they stop.
			if dirty || ticks%10 == 0 {
				draw()
				dirty = false
			}
		}
	}
}

// feedTraceView runs one stream and tells the view what it carries.
func (a *app) feedTraceView(ctx context.Context, gen int, c *api.Client, session *auth.Session, msgs chan<- traceMsg) {
	send := func(m traceMsg) {
		m.gen = gen
		select {
		case msgs <- m:
		case <-ctx.Done():
		}
	}
	reason, err := a.streamTrace(ctx, c, session, traceSink{
		decision: func(data string) {
			if fields, err := traceview.Decode([]byte(data)); err == nil {
				send(traceMsg{decision: fields})
			}
		},
		status: func(data string) {
			var s traceview.Stats
			if json.Unmarshal([]byte(data), &s) == nil {
				send(traceMsg{stats: &s})
			}
			live := traceview.Live
			send(traceMsg{state: &live})
		},
		renewing: func() {
			renewing := traceview.Renewing
			send(traceMsg{state: &renewing})
		},
	})
	if ctx.Err() == nil {
		send(traceMsg{done: true, reason: reason, err: err})
	}
}

// readKeys reads what the terminal sends until it can read no more.
func readKeys(in io.Reader, keys chan<- []byte) {
	defer close(keys)
	buf := make([]byte, 256)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			keys <- append([]byte(nil), buf[:n]...)
		}
		if err != nil {
			return
		}
	}
}
