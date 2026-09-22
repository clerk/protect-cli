package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

type matchSeries struct {
	Key          string  `json:"key"`
	Matched      []int64 `json:"matched"`
	Acted        []int64 `json:"acted"`
	TotalMatched int64   `json:"total_matched"`
	TotalActed   int64   `json:"total_acted"`
}

type matchResult struct {
	Start           string        `json:"start"`
	End             string        `json:"end"`
	IntervalSeconds int64         `json:"interval_seconds"`
	Buckets         int           `json:"buckets"`
	Unit            string        `json:"unit"`
	GroupBy         string        `json:"group_by"`
	Series          []matchSeries `json:"series"`
}

// sparkline draws counts as blocks. A bucket with NO matches is a space, never
// the lowest block, so a rule that stopped matching is visible as a gap.
func sparkline(counts []int64) string {
	const blocks = "▁▂▃▄▅▆▇█"
	levels := []rune(blocks)
	var peak int64
	for _, c := range counts {
		peak = max(peak, c)
	}
	var b strings.Builder
	for _, c := range counts {
		if c <= 0 || peak == 0 {
			b.WriteRune(' ')
			continue
		}
		i := int((c*int64(len(levels)) - 1) / peak)
		b.WriteRune(levels[min(i, len(levels)-1)])
	}
	return b.String()
}

func (a *app) matchesCmd() *cobra.Command {
	var protections, rules, traffic []string
	var since, from, to, interval, unit string
	cmd := &cobra.Command{
		Use:   "matches",
		Short: "How often protections or rules matched, over time",
		Long:  "Without --protection or --rule-id, shows the protections set up on this instance.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(protections) > 0 && len(rules) > 0 {
				return usageError("give --protection or --rule-id, not both")
			}
			q := url.Values{}
			switch {
			case from != "" || to != "":
				if from == "" || to == "" || interval == "" {
					return usageError("--from and --to need each other and --interval")
				}
				q.Set("from", from)
				q.Set("to", to)
				q.Set("interval", interval)
			default:
				q.Set("since", since)
				if interval != "" {
					q.Set("interval", interval)
				}
			}
			for _, p := range protections {
				q.Add("protection", p)
			}
			// Repeated, never comma-joined: a rule id may itself contain a comma.
			for _, r := range rules {
				q.Add("rule_id", r)
			}
			for _, t := range traffic {
				q.Add("traffic_class", t)
			}
			if unit != "" {
				q.Set("unit", unit)
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodGet, api.Path("matches", "timeseries"), q, nil)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			var res matchResult
			if err := json.Unmarshal(resp.Body, &res); err != nil {
				return err
			}
			a.printf("%s → %s  ·  %d × %ds  ·  %s by %s\n\n", res.Start, res.End, res.Buckets, res.IntervalSeconds, res.Unit, res.GroupBy)
			tw := a.table()
			_, _ = fmt.Fprintln(tw, "KEY\tMATCHED\tACTED\tSPARKLINE")
			for _, s := range res.Series {
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", s.Key, s.TotalMatched, s.TotalActed, sparkline(s.Matched))
			}
			return tw.Flush()
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&protections, "protection", nil, "Protection name (repeatable)")
	f.StringArrayVar(&rules, "rule-id", nil, "Rule id (repeatable)")
	f.StringVar(&since, "since", "24h", "Look back this far (e.g. 24h, 7d)")
	f.StringVar(&from, "from", "", "Window start, RFC 3339")
	f.StringVar(&to, "to", "", "Window end, RFC 3339")
	f.StringVar(&interval, "interval", "", "Bucket width (e.g. 30m, 1h)")
	f.StringVar(&unit, "unit", "", "decisions (default) or flows")
	f.StringArrayVar(&traffic, "traffic-class", nil, "Only this traffic class (repeatable)")
	return cmd
}
