package cli

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

// insightsTraceIDCmd resolves the reference a blocked person is shown to the
// decision behind it.
//
// The reference is sent as given and validated by the server: its format is
// the server's to change, and a client that parsed it would need a release
// every time it did.
func (a *app) insightsTraceIDCmd() *cobra.Command {
	var windowHours, limit int
	cmd := &cobra.Command{
		Use:   "trace-id <reference>",
		Short: "Find the decision behind the reference shown on a blocked screen",
		Long: `When a sign-in or sign-up is blocked, the person sees a short reference
(e.g. 7Q8ikxgt). Paste it here to find the decision that blocked them: when it
happened, which rule matched, and the network and request it came from.

The reference is case-sensitive. It is resolved only within this instance; a
reference from another instance or environment finds nothing. Decisions are
kept for 14 days, and the whole period is searched unless --window-hours
narrows it.

Prints JSON. A note on stderr says when nothing matched, or when the decision
found was not a block.`,
		Example: `  clerk-protect insights trace-id 7Q8ikxgt
  clerk-protect insights trace-id 7Q8ikxgt --instance ins_abc`,
		Args: exactArgs(1, "the reference from the blocked screen"),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := strings.TrimSpace(args[0])
			if ref == "" {
				return usageError("the reference is empty")
			}
			if windowHours < 0 {
				return usageError("--window-hours must not be negative")
			}
			body := map[string]any{"trace_id": ref}
			if windowHours > 0 {
				body["window_hours"] = windowHours
			}
			if limit > 0 {
				body["limit"] = limit
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("insights", "decisions", "trace-id"), nil, body)
			if err != nil {
				return err
			}
			if err := a.printRaw(resp.Body); err != nil {
				return err
			}
			a.noteTraceIDResult(ref, resp.Body)
			return nil
		},
	}
	cmd.Flags().IntVar(&windowHours, "window-hours", 0, "Search only the last N hours (default: all 14 days kept)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Most decisions to return (default 100)")
	return cmd
}

// noteTraceIDResult explains the two answers that are easy to misread: no
// decision at all, and a decision that was not a block.
func (a *app) noteTraceIDResult(ref string, raw []byte) {
	var res struct {
		Decisions []struct {
			Decision     string `json:"decision"`
			TrafficClass string `json:"traffic_class"`
		} `json:"decisions"`
		From string `json:"from"`
		To   string `json:"to"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return
	}
	if len(res.Decisions) == 0 {
		a.notef("No decision on this instance matches %s between %s and %s. "+
			"Check the reference against the screenshot (it is case-sensitive), and that it "+
			"came from this instance and environment.\n", ref, res.From, res.To)
		return
	}
	// A shadow deny was recorded and never enforced, so it never showed anyone
	// a reference: it does not count as the block the reference came from.
	for _, d := range res.Decisions {
		if d.Decision == "DENY" && d.TrafficClass != "TRAFFIC_CLASS_SHADOW" {
			return
		}
	}
	a.notef("None of the matching decisions was an enforced block. A reference is shown only "+
		"when a request is blocked, so %s was probably mistyped.\n", ref)
}
