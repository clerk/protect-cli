package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

// insightsQuery is the common half of every insights request. The API takes
// these as POST bodies even for reads, because filter values are addresses and
// identifiers that have no business in a URL.
type insightsQuery struct {
	query      string
	file       string
	since      time.Duration
	from       string
	to         string
	filters    []string
	excludes   []string
	expression string
	flowID     string
	unit       string
	traffic    []string
	requests   []string
}

func (q *insightsQuery) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&q.query, "query", "", "The request body as JSON; flags below are applied on top")
	f.StringVar(&q.file, "file", "", "Read the request body as JSON from this file (- for stdin)")
	f.DurationVar(&q.since, "since", 24*time.Hour, "Look back this far from now (up to 336h / 14 days of retained decisions)")
	f.StringVar(&q.from, "from", "", "Window start, RFC 3339 (overrides --since)")
	f.StringVar(&q.to, "to", "", "Window end, RFC 3339 (default now)")
	f.StringArrayVar(&q.filters, "filter", nil, "Keep rows where a dimension has one of these values: dimension=value1,value2 (repeatable)")
	f.StringArrayVar(&q.excludes, "exclude", nil, "Drop rows where a dimension has one of these values: dimension=value1,value2 (repeatable)")
	f.StringVar(&q.expression, "expression", "", "A filter expression; rule paths such as ip.asn.type are also accepted (see insights fields)")
	f.StringVar(&q.unit, "unit", "", "What to count: decisions (default) or flows")
	f.StringArrayVar(&q.traffic, "traffic-class", nil, "Only this traffic class (repeatable)")
	f.StringArrayVar(&q.requests, "request-type", nil, "Only this request type: signin, signup, email, sms (repeatable)")
}

func (q *insightsQuery) registerFlowID(cmd *cobra.Command) {
	cmd.Flags().StringVar(&q.flowID, "flow-id", "", "Keep decisions from this sign-in or sign-up ID (decisions unit only)")
}

func parseFilter(s, op string) (map[string]any, error) {
	dim, values, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(dim) == "" || strings.TrimSpace(values) == "" {
		return nil, usageError("filter %q: expected dimension=value[,value...]", s)
	}
	var vals []string
	for _, v := range strings.Split(values, ",") {
		if v = strings.TrimSpace(v); v != "" {
			vals = append(vals, v)
		}
	}
	return map[string]any{"dimension": strings.TrimSpace(dim), "op": op, "values": vals}, nil
}

// body builds the request. A JSON body from --query or --file is the starting
// point; flags the person actually gave are layered on it.
func (q *insightsQuery) body(cmd *cobra.Command, now time.Time, readFile func(string) (json.RawMessage, error)) (map[string]any, error) {
	body := map[string]any{}
	switch {
	case q.query != "" && q.file != "":
		return nil, usageError("give --query or --file, not both")
	case q.query != "":
		if err := json.Unmarshal([]byte(q.query), &body); err != nil {
			return nil, usageError("--query is not a JSON object: %v", err)
		}
	case q.file != "":
		raw, err := readFile(q.file)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, usageError("%s is not a JSON object: %v", q.file, err)
		}
	}
	if body == nil {
		body = map[string]any{}
	}

	// Supplied times keep their precision so a printed window round-trips
	// through --from/--to exactly; "now" is whole seconds to stay readable.
	now = now.Truncate(time.Second)
	f := cmd.Flags()
	_, hasWindow := body["from"]
	if !hasWindow || f.Changed("since") || f.Changed("from") || f.Changed("to") {
		end := now
		if q.to != "" {
			t, err := time.Parse(time.RFC3339, q.to)
			if err != nil {
				return nil, usageError("--to must be RFC 3339")
			}
			end = t
		}
		start := end.Add(-q.since)
		if q.from != "" {
			t, err := time.Parse(time.RFC3339, q.from)
			if err != nil {
				return nil, usageError("--from must be RFC 3339")
			}
			start = t
		}
		if !start.Before(end) {
			return nil, usageError("the window is empty: its start is not before its end")
		}
		body["from"] = start.UTC().Format(time.RFC3339Nano)
		body["to"] = end.UTC().Format(time.RFC3339Nano)
	}
	// A partial JSON window must use one end time across every search page,
	// rather than asking the server to choose a fresh "now" on each request.
	if body["to"] == nil {
		body["to"] = now.UTC().Format(time.RFC3339Nano)
	}
	// A null start gets the server's own default, 24 hours before the end, so
	// search can print the exact window a later --cursor continuation must reuse.
	if end, ok := body["to"].(string); ok && body["from"] == nil {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			body["from"] = t.Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
		}
	}

	filters, _ := body["filter"].([]any)
	for _, s := range q.filters {
		clause, err := parseFilter(s, "in")
		if err != nil {
			return nil, err
		}
		filters = append(filters, clause)
	}
	for _, s := range q.excludes {
		clause, err := parseFilter(s, "not_in")
		if err != nil {
			return nil, err
		}
		filters = append(filters, clause)
	}
	if filters == nil {
		filters = []any{}
	}
	body["filter"] = filters

	if f.Changed("expression") {
		body["expression"] = q.expression
	}
	if f.Changed("unit") {
		body["unit"] = q.unit
	}
	if body["unit"] == "decisions" {
		delete(body, "unit")
	}
	if f.Changed("flow-id") {
		if strings.TrimSpace(q.flowID) == "" {
			return nil, usageError("--flow-id must not be empty")
		}
		for _, r := range q.flowID {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			default:
				return nil, usageError("--flow-id must contain only letters, digits, underscores or hyphens")
			}
		}
		if unit, _ := body["unit"].(string); unit != "" && unit != "decisions" {
			return nil, usageError("--flow-id filters decisions; use --unit decisions")
		}
		expression, ok := body["expression"].(string)
		if body["expression"] != nil && !ok {
			return nil, usageError("expression must be a string")
		}
		flow := "flow_id == " + strconv.Quote(q.flowID)
		if strings.TrimSpace(expression) != "" {
			if !selfContainedExpression(expression) {
				return nil, usageError("expression must have balanced parentheses and closed strings when combined with --flow-id")
			}
			flow = "(" + expression + ") && (" + flow + ")"
		}
		body["expression"] = flow
	}
	if len(q.traffic) > 0 {
		body["traffic_classes"] = q.traffic
	}
	if len(q.requests) > 0 {
		body["request_types"] = q.requests
	}
	return body, nil
}

// The expression must not close the group we wrap around it. This only checks
// the grouping boundary; the server still validates the expression itself.
func selfContainedExpression(expression string) bool {
	depth := 0
	quoted := false
	for i := 0; i < len(expression); i++ {
		ch := expression[i]
		if quoted {
			switch ch {
			case '\\':
				i++
			case '"':
				quoted = false
			}
			continue
		}
		switch ch {
		case '"':
			quoted = true
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !quoted
}

func (a *app) insightsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "insights",
		Short: "Investigate decisions on this instance",
		Long: `Insights commands print JSON. Windows default to the last 24 hours; decisions
are retained for 14 days. Search follows pages to satisfy --limit.

Use --filter for dimension names from 'insights dimensions'. Expressions accept
column names and compatible rule paths, e.g. ip.asn.type == "hosting".
'insights fields' lists expression fields and their available aliases.
Use --flow-id to find decisions belonging to one sign-in or sign-up.
Use 'insights trace-id' to find the decision behind a blocked screen's reference.`,
	}
	cmd.AddCommand(
		a.insightsDimensionsCmd(),
		a.insightsFieldsCmd(),
		a.insightsPostCmd("facets", "facets", "Count the values of each dimension in a window", func(cmd *cobra.Command, body map[string]any) error {
			if n, _ := cmd.Flags().GetInt("top-n"); cmd.Flags().Changed("top-n") {
				body["top_n"] = n
			}
			if dims, _ := cmd.Flags().GetStringArray("dimension"); len(dims) > 0 {
				body["dimensions"] = dims
			}
			return nil
		}, func(cmd *cobra.Command) {
			cmd.Flags().Int("top-n", 0, "Values per dimension")
			cmd.Flags().StringArray("dimension", nil, "Count only this dimension (repeatable)")
		}),
		a.insightsPostCmd("timeseries", "timeseries", "Decisions over time", func(cmd *cobra.Command, body map[string]any) error {
			if n, _ := cmd.Flags().GetInt("interval-seconds"); cmd.Flags().Changed("interval-seconds") {
				body["interval_seconds"] = n
			}
			if g, _ := cmd.Flags().GetString("group-by"); g != "" {
				body["group_by"] = g
			}
			return nil
		}, func(cmd *cobra.Command) {
			cmd.Flags().Int("interval-seconds", 0, "Bucket width")
			cmd.Flags().String("group-by", "", "Split the series by this dimension")
		}),
		a.insightsSearchCmd(),
		a.insightsPostCmd("entity", "entity", "Profile one value of one dimension over the window", func(cmd *cobra.Command, body map[string]any) error {
			if d, _ := cmd.Flags().GetString("dimension"); d != "" {
				body["dimension"] = d
			}
			if v, _ := cmd.Flags().GetString("value"); v != "" {
				body["value"] = v
			}
			if s, _ := body["dimension"].(string); s == "" {
				return usageError("--dimension is required (see `clerk-protect insights dimensions`)")
			}
			if s, _ := body["value"].(string); s == "" {
				return usageError("--value is required")
			}
			return nil
		}, func(cmd *cobra.Command) {
			cmd.Flags().String("dimension", "", "The dimension, e.g. ip")
			cmd.Flags().String("value", "", "The value of that dimension to profile")
		}),
		a.insightsPostCmd("events", "events", "Configuration changes in a window", nil, nil),
		a.insightsFlowCmd(),
		a.insightsTraceIDCmd(),
		a.insightsValidateFilterCmd(),
	)
	return cmd
}

func (a *app) insightsFieldsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fields",
		Short: "Expression fields and compatible rule-path aliases for decisions",
		Long: `List expression fields, including fields such as flow_id that are not facet
dimensions. Aliases use the same values as their column name; other rule fields
may use different values or may not be available in historical decisions.

Aliases are included when the server publishes them. Use 'schema' to discover
which fields a rule can use for its event type.`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodGet, api.Path("insights", "dimensions"), nil, nil)
			if err != nil {
				return err
			}
			var catalog struct {
				Fields json.RawMessage `json:"fields"`
			}
			if err := json.Unmarshal(resp.Body, &catalog); err != nil || len(catalog.Fields) == 0 {
				return errors.New("the server did not return expression fields")
			}
			return a.printRaw(catalog.Fields)
		},
	}
}

func (a *app) insightsDimensionsCmd() *cobra.Command {
	var unit string
	cmd := &cobra.Command{
		Use:   "dimensions",
		Short: "The dimensions insights can count and filter on",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			q := url.Values{}
			if unit != "" && unit != "decisions" {
				q.Set("unit", unit)
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodGet, api.Path("insights", "dimensions"), q, nil)
			if err != nil {
				return err
			}
			return a.printRaw(resp.Body)
		},
	}
	cmd.Flags().StringVar(&unit, "unit", "", "decisions (default) or flows")
	return cmd
}

// insightsPostCmd builds an insights read. extra adds the command's own fields
// to the body and checks it; it runs before anything is sent.
func (a *app) insightsPostCmd(use, route, short string, extra func(*cobra.Command, map[string]any) error, flags func(*cobra.Command)) *cobra.Command {
	var q insightsQuery
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := q.body(cmd, a.now(), a.readJSONFile)
			if err != nil {
				return err
			}
			if extra != nil {
				if err := extra(cmd, body); err != nil {
					return err
				}
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			segments := append([]string{"insights"}, strings.Split(route, "/")...)
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path(segments...), nil, body)
			if err != nil {
				return err
			}
			return a.printRaw(resp.Body)
		},
	}
	q.register(cmd)
	if use == "facets" || use == "timeseries" {
		q.registerFlowID(cmd)
	}
	if flags != nil {
		flags(cmd)
	}
	return cmd
}

// insightsFlowCmd reads the flow one decision belonged to. It takes a decision
// reference, not a window: the server finds the flow's own time range from it.
func (a *app) insightsFlowCmd() *cobra.Command {
	var query, file, decisionID, at string
	cmd := &cobra.Command{
		Use:   "flow",
		Short: "Every decision in the flow one decision belonged to",
		Long: "--at is the decision's created_at, as insights search prints it. It is required: the server " +
			"uses it to find the decision without scanning every day it keeps.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := a.jsonBody(query, file)
			if err != nil {
				return err
			}
			if decisionID != "" {
				body["decision_id"] = decisionID
			}
			if at != "" {
				t, err := time.Parse(time.RFC3339, at)
				if err != nil {
					return usageError("--at must be RFC 3339: the decision's created_at")
				}
				body["at"] = t.UTC().Format(time.RFC3339Nano)
			}
			if s, _ := body["decision_id"].(string); s == "" {
				return usageError("--decision-id is required")
			}
			if s, _ := body["at"].(string); s == "" {
				return usageError("--at is required: the decision's created_at")
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("insights", "decisions", "flow"), nil, body)
			if err != nil {
				return err
			}
			return a.printRaw(resp.Body)
		},
	}
	f := cmd.Flags()
	f.StringVar(&query, "query", "", "The request body as JSON; flags below are applied on top")
	f.StringVar(&file, "file", "", "Read the request body as JSON from this file (- for stdin)")
	f.StringVar(&decisionID, "decision-id", "", "The decision")
	f.StringVar(&at, "at", "", "When the decision was made (its created_at), RFC 3339")
	return cmd
}

func (a *app) insightsValidateFilterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate-filter <expression>",
		Short: "Check a filter expression; exits 1 when it does not compile",
		Args:  exactArgs(1, "a filter expression"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("insights", "filter", "validate"), nil, map[string]string{"expression": args[0]})
			if err != nil {
				return err
			}
			var verdict struct {
				Valid  bool `json:"valid"`
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(resp.Body, &verdict); err != nil {
				return err
			}
			if a.jsonOut {
				if err := a.printRaw(resp.Body); err != nil {
					return err
				}
			} else if verdict.Valid {
				a.printf("%s\n", a.out.Good("Valid."))
			} else {
				a.printf("%s\n", a.out.Bad("Invalid:"))
				for _, e := range verdict.Errors {
					a.printf("  %s\n", e.Message)
				}
			}
			if !verdict.Valid {
				return &exitError{code: ExitError, err: errors.New("the filter expression is not valid")}
			}
			return nil
		},
	}
}
