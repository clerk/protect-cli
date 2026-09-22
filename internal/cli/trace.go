package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/style"
	"github.com/clerk/protect-cli/internal/term"
	"github.com/clerk/protect-cli/internal/textsafe"
	"github.com/clerk/protect-cli/internal/traceview"
)

// traceMaxReconnects bounds how many times in a row `trace` reconnects to a
// stream that closed within a minute of opening. A stream that closes
// immediately every time is not going to start working.
const traceMaxReconnects = 20

// traceRenewRetry is how soon a stream reopens when the renewal that was due
// before it opened did not happen: a server briefly unavailable keeps the old
// token rather than failing the command, and the next reopening tries again.
const traceRenewRetry = 30 * time.Second

// traceRenewMargin is how far before the token's expiry the last renewal retry
// happens. A retry AT expiry is no retry: the server renews only a live token.
const traceRenewMargin = 5 * time.Second

// traceRetryFloor is the soonest a failed renewal is retried, so a renewal that
// keeps failing in a token's last seconds cannot spin.
const traceRetryFloor = time.Second

// traceDeadline is when a stream opened at now is closed from this side, so the
// request reopening it renews the token.
//
// Normally that is the reconnect time. If the reconnect time has ALREADY passed,
// the renewal due at it failed — and riding this stream to the token's expiry
// would leave nothing valid to renew, since the server renews only a live token.
// So the stream reopens soon to try again: within traceRenewRetry, and no later
// than traceRenewMargin before the expiry. The one exception is a token with a
// second or less left, where the retry floor wins and the retry can land at or
// after expiry: no deadline is both a second away and before an expiry that
// close.
func traceDeadline(now, reconnectBy time.Time) time.Time {
	if now.Before(reconnectBy) {
		return reconnectBy
	}
	retry := now.Add(traceRenewRetry)
	if lastChance := reconnectBy.Add(auth.RenewFloor - traceRenewMargin); lastChance.Before(retry) {
		retry = lastChance
	}
	if floor := now.Add(traceRetryFloor); retry.Before(floor) {
		retry = floor
	}
	return retry
}

// traceColumns is the server's description of the fields a decision carries.
type traceColumns struct {
	Enabled  bool               `json:"enabled"`
	Columns  []traceview.Column `json:"columns"`
	Defaults []string           `json:"defaults"`
}

// traceSink receives what the stream carries.
type traceSink struct {
	decision func(data string)
	status   func(data string)
	// renewing is called when a stream is closed from this side to renew.
	renewing func()
}

// streamTrace runs the decision stream until the context ends (nil), the server
// ends it for a reason other than an expired session (that reason), or a
// request fails (the error).
//
// The server verifies a token when a stream opens and ends the stream when that
// token expires, and a token that has expired can no longer be renewed. So the
// stream is closed from this side a little before expiry, and the request
// reopening it renews — see traceDeadline. Both the line output and the
// interactive view run this one loop.
func (a *app) streamTrace(ctx context.Context, c *api.Client, session *auth.Session, sink traceSink) (string, error) {
	quickCloses := 0
	for {
		// Renew now if the token is due, so the deadline below belongs to the
		// token the stream will actually carry.
		if _, err := c.Tokens.Token(ctx); err != nil {
			return "", err
		}
		streamCtx, cancel := context.WithCancel(ctx)
		if session != nil {
			if at, ok := session.ReconnectBy(); ok {
				cancel()
				streamCtx, cancel = context.WithDeadline(ctx, traceDeadline(time.Now(), at))
			}
		}
		opened := time.Now()
		sessionExpired := false
		reason := ""
		err := c.Stream(streamCtx, api.Path("trace"), nil, func(ev api.Event) error {
			switch ev.Name {
			case "decision":
				sink.decision(ev.Data)
			case "status":
				sink.status(ev.Data)
			case "closed":
				var closed struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal([]byte(ev.Data), &closed)
				if closed.Reason == "session_expired" {
					sessionExpired = true
				} else {
					reason = closed.Reason
				}
				return api.ErrStop
			}
			return nil
		})
		renewDue := errors.Is(streamCtx.Err(), context.DeadlineExceeded)
		cancel()
		switch {
		case ctx.Err() != nil:
			return "", nil
		case renewDue:
			sink.renewing()
			continue
		case err != nil:
			return "", err
		case !sessionExpired:
			return reason, nil
		}
		if time.Since(opened) < time.Minute {
			quickCloses++
		} else {
			quickCloses = 0
		}
		if quickCloses > traceMaxReconnects {
			return "", errors.New("the stream kept closing; giving up")
		}
		sink.renewing()
		select {
		case <-ctx.Done():
			return "", nil
		case <-time.After(time.Second):
		}
	}
}

func matchesFields(event map[string]any, want map[string]string) bool {
	for k, v := range want {
		got, ok := event[k]
		if !ok || fmt.Sprint(got) != v {
			return false
		}
	}
	return true
}

// formatValue renders one decision field for a line of human output. Anything
// that would break the line apart, or that is not plain printable text, is
// quoted — and quoting escapes it, so a control sequence in a decision field
// (a user agent is whatever the client sent) prints as text instead of acting.
func formatValue(v any) string {
	s := fmt.Sprint(v)
	if s == "" || strings.ContainsAny(s, " \t\"\n") || textsafe.Strip(s) != s {
		return strconv.Quote(s)
	}
	return s
}

func (a *app) traceCmd() *cobra.Command {
	var fields, filterSpecs, columns []string
	var noTUI bool
	var buffer int
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Stream this instance's decisions live",
		Long: "Streams decisions as they are made, from now.\n\n" +
			"In a terminal, trace opens an interactive view: pause and scroll back, open a decision to see every " +
			"field, add filters, and choose columns. Press ? in it for the keys, q to quit. With --json or " +
			"--no-tui, or when input or output is not a terminal, each decision is printed as one line instead " +
			"(with --json, as the server's JSON).\n\n" +
			"--filter keeps decisions whose field matches: field=value, field!=value or field~text ignoring case, " +
			"or field==value exactly. --field key=value is the same as --filter key==value. The stream is reopened " +
			"before the sign-in token expires, so it runs for as long as your access renews.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			want := map[string]string{}
			for _, f := range fields {
				k, v, ok := strings.Cut(f, "=")
				if !ok || k == "" {
					return usageError("--field %q: expected key=value", f)
				}
				want[k] = v
			}
			// A filter's shape is checked before anything is sent; its field,
			// once the server has said which fields there are.
			for _, spec := range filterSpecs {
				if _, err := traceview.ParseFilter(spec, nil); err != nil {
					return usageError("--filter %v", err)
				}
			}
			if buffer < 1 {
				return usageError("--buffer must be at least 1")
			}
			c, creds, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)

			var info traceColumns
			if err := c.JSON(ctx, http.MethodGet, api.Path("trace", "columns"), nil, nil, &info); err != nil {
				return err
			}
			if !info.Enabled {
				return errors.New("live trace is not available in this environment")
			}
			known := func(key string) bool {
				if len(info.Columns) == 0 {
					return true
				}
				for _, col := range info.Columns {
					if col.Key == key {
						return true
					}
				}
				return false
			}
			filters := make([]traceview.Filter, 0, len(filterSpecs))
			for _, spec := range filterSpecs {
				f, err := traceview.ParseFilter(spec, known)
				if err != nil {
					return usageError("--filter %v", err)
				}
				filters = append(filters, f)
			}
			show := columns
			if len(show) == 0 {
				show = info.Defaults
			}
			session, _ := c.Tokens.(*auth.Session)

			if in, out := a.traceTTY(); !noTUI && !a.jsonOut && a.isTerminal() && term.IsTerminal(out.Fd()) {
				err := a.runTraceView(ctx, in, out, c, session, traceview.Options{
					Instance: creds.InstanceID, Columns: info.Columns, Show: show, Buffer: buffer,
					Filters: append(append([]traceview.Filter(nil), filters...), fieldFilters(want)...),
				})
				if !errors.Is(err, errNoTraceView) {
					return err
				}
			}
			return a.traceLines(ctx, c, session, show, want, filters)
		},
	}
	cmd.Flags().StringArrayVar(&filterSpecs, "filter", nil, "Only decisions whose field matches: field=value, field!=value or field~text ignoring case, or field==value exactly (repeatable)")
	cmd.Flags().StringArrayVar(&fields, "field", nil, "Only decisions where this field has exactly this value: key=value, the same as --filter key==value (repeatable)")
	cmd.Flags().StringSliceVar(&columns, "columns", nil, "Fields to show, comma-separated (default: the server's default columns)")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Print one line per decision, even in a terminal")
	cmd.Flags().IntVar(&buffer, "buffer", 2000, "How many decisions the interactive view keeps to scroll back through")
	return cmd
}

// fieldFilters turns --field key=value into the view's filters: exact, as
// --field is in line output — key==value, never the case-ignoring key=value.
func fieldFilters(want map[string]string) []traceview.Filter {
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]traceview.Filter, 0, len(keys))
	for _, k := range keys {
		out = append(out, traceview.Filter{Key: k, Op: "==", Value: want[k]})
	}
	return out
}

// traceLines prints the stream as lines: one per decision.
func (a *app) traceLines(ctx context.Context, c *api.Client, session *auth.Session, show []string, want map[string]string, filters []traceview.Filter) error {
	announced := false
	reason, err := a.streamTrace(ctx, c, session, traceSink{
		decision: func(data string) {
			var event map[string]any
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				return
			}
			if !matchesFields(event, want) {
				return
			}
			if len(filters) > 0 {
				decoded, err := traceview.Decode([]byte(data))
				if err != nil || !traceview.MatchAll(filters, decoded) {
					return
				}
			}
			if a.jsonOut {
				// The server's JSON as sent: its control characters are escaped.
				_, _ = fmt.Fprintln(a.stdout, data)
				return
			}
			a.printf("%s\n", decisionLine(a.out, event, show))
		},
		status: func(string) {
			if !announced {
				announced = true
				a.notef("Streaming decisions. Interrupt to stop.\n")
			}
		},
		renewing: func() {},
	})
	if reason != "" {
		a.notef("The stream closed (%s).\n", reason)
	}
	return err
}

// decisionLine renders one decision as key=value pairs: keys dimmed, the
// decision itself coloured by what it means. Keys are stripped and values
// quoted when they carry a control character, before any colour is added.
func decisionLine(p style.Palette, event map[string]any, show []string) style.Text {
	var parts []string
	keys := show
	if len(keys) == 0 {
		for k := range event {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	for _, k := range keys {
		if v, ok := event[k]; ok {
			key := strings.Map(func(r rune) rune {
				if r == '\n' || r == '\t' || r == ' ' {
					return '_'
				}
				return r
			}, textsafe.Strip(k))
			value := p.Plain(formatValue(v))
			if k == "decision" {
				value = p.Word(formatValue(v))
			}
			parts = append(parts, string(p.Label(key+"="))+string(value))
		}
	}
	return style.Text(strings.Join(parts, " "))
}
