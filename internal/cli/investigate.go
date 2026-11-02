package cli

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/textsafe"
)

// Exit codes an investigation adds. They are outcomes, not failures: the
// answer explains itself on stderr.
const (
	// ExitDeclined: Protect declined to answer the question as asked.
	ExitDeclined = 4
	// ExitNeedsMore: Protect needs more information; resubmit with answers.
	ExitNeedsMore = 5
)

// investigationRequest is the body of an investigation. It names no instance:
// the instance is the signed-in one.
type investigationRequest struct {
	Prompt            string   `json:"prompt"`
	Purpose           string   `json:"purpose,omitempty"`
	Shape             string   `json:"shape,omitempty"`
	Justification     string   `json:"justification,omitempty"`
	Investigating     string   `json:"investigating,omitempty"`
	AdditionalContext []string `json:"additional_context,omitempty"`
	PriorRequestID    string   `json:"prior_request_id,omitempty"`
	Agent             string   `json:"agent,omitempty"`
	AgentSession      string   `json:"agent_session,omitempty"`
	AgentAttended     *bool    `json:"agent_attended,omitempty"`
}

func (a *app) investigateCmd() *cobra.Command {
	var req investigationRequest
	var format, agent string
	var noInteractive bool
	cmd := &cobra.Command{
		Use:   "investigate [question]",
		Short: "Ask a question about this instance's decisions in plain language",
		Long: `Ask a question about this instance's decisions in plain language. Protect works out
the query, checks it, runs it against this instance's decisions only, and streams the
result back.

Say what you want to know (the question), why (--purpose) and how you'd like it laid
out (--shape). Be specific: a time window, the flow (sign-in, sign-up, ...), the outcome,
the grouping, and "top N".

Each request is recorded with who asked and why. When Protect needs more to go on it
asks questions: in a terminal this command asks them and sends the request again with
your answers; otherwise it prints them with the request id and exits 5, and you resend
the same question with --prior-request and one --context per answer.

Progress, the query and the summary go to stderr; result rows go to stdout, so the
command pipes. --json prints every event as one JSON line instead.

FOR AI AGENTS: run 'investigate schema' first. Pass --no-interactive and
--format json or csv. Anything you put in --purpose, --justification or
--investigating is recorded as the signed-in person's reason: ask them for it rather
than writing it yourself. Requests from an agent are marked as such (detected from
AI_AGENT, CLERK_PROTECT_AGENT or CLAUDECODE, or set with --agent).

Exit status: 0 answered, 1 failed, 2 a mistake in the command, 3 sign in again,
4 declined, 5 more information needed.`,
		Example: `  clerk-protect investigate \
    --purpose "find what drove yesterday's blocked sign-ups" \
    --shape "one row per country with blocked count, top 10" \
    "Which countries had the most blocked sign-ups yesterday?"

  clerk-protect investigate schema`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if req.Prompt != "" {
					return usageError("give the question as the argument or --prompt, not both")
				}
				req.Prompt = args[0]
			}
			req.Prompt = strings.TrimSpace(req.Prompt)
			if req.Prompt == "" {
				return usageError("a question is required: say what you want to know")
			}
			switch format {
			case "table", "csv", "json":
			default:
				return usageError("--format must be table, csv or json, not %q", format)
			}
			req.Agent, req.AgentSession, req.AgentAttended = investigationAgent(agent, a.getenv)
			if req.Agent != "" {
				a.notef("Recording this request as made by an AI agent (%s).\n", req.Agent)
			}
			interactive := !noInteractive && !a.jsonOut && a.isTerminal()
			c, _, err := a.client()
			if err != nil {
				return err
			}
			for {
				res, err := a.runInvestigation(cmd, c, req, format)
				if err != nil {
					return err
				}
				switch res.outcome {
				case "declined":
					return &exitError{code: ExitDeclined, err: errors.New("declined: Protect would not answer the question as asked; the reason is above")}
				case "needs_more_information":
					if !interactive {
						return &exitError{code: ExitNeedsMore, err: fmt.Errorf("more information is needed: resend with --prior-request %s and one --context per answer", res.requestID)}
					}
					answers, err := a.askInvestigationQuestions(res.questions)
					if err != nil {
						return err
					}
					// The service keeps no conversation: the whole request goes
					// back, with the answers added.
					req.AdditionalContext = append(req.AdditionalContext, answers...)
					req.PriorRequestID = res.requestID
					a.notef("\n")
					continue
				}
				return nil
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&req.Prompt, "prompt", "", "The question (or give it as the argument)")
	f.StringVar(&req.Purpose, "purpose", "", "Why you want to know")
	f.StringVar(&req.Shape, "shape", "", "How you'd like the result laid out: columns, grouping, ordering")
	f.StringVar(&req.Justification, "justification", "", "Why this data is needed, recorded with the request")
	f.StringVar(&req.Investigating, "investigating", "", "A ticket or case reference, recorded with the request")
	f.StringArrayVar(&req.AdditionalContext, "context", nil, "More context, e.g. an answer to a question Protect asked (repeatable)")
	f.StringVar(&req.PriorRequestID, "prior-request", "", "The request id this one answers, to link the two")
	f.StringVar(&format, "format", "table", "Result rows on stdout: table, csv or json (one JSON array per row)")
	f.StringVar(&agent, "agent", "", "Record this request as made by the AI agent with this name")
	f.BoolVar(&noInteractive, "no-interactive", false, "Never ask; exit 5 when more information is needed")
	cmd.AddCommand(a.investigateSchemaCmd())
	return cmd
}

func (a *app) investigateSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "The tables and columns you can ask about on this instance",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodGet, api.Path("investigation", "schema"), nil, nil)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			var s struct {
				Tables []struct {
					Name        string `json:"name"`
					Description string `json:"description"`
					Columns     []struct {
						Name        string `json:"name"`
						Type        string `json:"type"`
						Description string `json:"description"`
					} `json:"columns"`
				} `json:"tables"`
			}
			if err := json.Unmarshal(resp.Body, &s); err != nil {
				return a.printRaw(resp.Body)
			}
			for i, tbl := range s.Tables {
				if i > 0 {
					a.printf("\n")
				}
				a.printf("%s\n", tbl.Name)
				if tbl.Description != "" {
					a.printf("  %s\n", tbl.Description)
				}
				t := a.table()
				for _, col := range tbl.Columns {
					t.Row("  "+col.Name, col.Type, col.Description)
				}
				if err := t.Flush(); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// investigationAgent works out whether an AI agent is running this command:
// --agent, else AI_AGENT (a cross-tool convention), else CLERK_PROTECT_AGENT,
// else CLAUDECODE=1. The session id and whether a person is attending come
// from the agent's own variables when present.
//
// It is this program's statement, not proof: its purpose is that an honest
// agent's request is recorded as one.
func investigationAgent(flag string, getenv func(string) string) (name, session string, attended *bool) {
	switch {
	case strings.TrimSpace(flag) != "":
		name = strings.TrimSpace(flag)
	case getenv("AI_AGENT") != "":
		name = getenv("AI_AGENT")
	case getenv("CLERK_PROTECT_AGENT") != "":
		name = getenv("CLERK_PROTECT_AGENT")
	case getenv("CLAUDECODE") == "1":
		name = "claude-code"
	default:
		return "", "", nil
	}
	session = getenv("CLAUDE_CODE_SESSION_ID")
	switch getenv("CLAUDE_CODE_SESSION_ATTENDED") {
	case "1":
		t := true
		attended = &t
	case "0":
		f := false
		attended = &f
	}
	return name, session, attended
}

type investigationResult struct {
	requestID string
	outcome   string
	questions []string
}

// runInvestigation sends one request and renders its stream.
//
// A STREAM THAT DOES NOT END IN `done` IS INCOMPLETE: a result cut off by a
// dropped connection must not read as the whole answer, so a body that ends
// without it is an error whatever came before.
func (a *app) runInvestigation(cmd *cobra.Command, c *api.Client, req investigationRequest, format string) (*investigationResult, error) {
	res := &investigationResult{}
	r := &investigationRenderer{a: a, format: format}
	var failure error
	done := false
	err := c.StreamPost(ctxOf(cmd), api.Path("investigation", "query"), req, func(ev api.Event) error {
		if done {
			return fmt.Errorf("the stream continued after it finished (%s)", ev.Name)
		}
		data := json.RawMessage(ev.Data)
		if a.jsonOut {
			if err := a.printJSONLine(ev.Name, data); err != nil {
				return err
			}
		} else if err := r.handle(ev.Name, data); err != nil {
			return err
		}
		switch ev.Name {
		case "accepted":
			var p struct {
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(data, &p)
			res.requestID = p.RequestID
		case "needs_more_information":
			var p struct {
				Questions []string `json:"questions"`
			}
			if err := json.Unmarshal(data, &p); err != nil {
				return fmt.Errorf("the server sent unreadable questions: %w", err)
			}
			res.questions = p.Questions
		case "error":
			var p struct {
				Class string `json:"class"`
			}
			_ = json.Unmarshal(data, &p)
			failure = fmt.Errorf("the investigation failed (%s)", orUnknown(p.Class))
		case "done":
			var p struct {
				Outcome string `json:"outcome"`
			}
			if err := json.Unmarshal(data, &p); err != nil {
				return fmt.Errorf("the server sent an unreadable result: %w", err)
			}
			res.outcome = p.Outcome
			done = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	if failure != nil {
		return nil, failure
	}
	if !done {
		return nil, errors.New("the stream ended early; any rows printed are NOT the complete result")
	}
	if res.outcome == "needs_more_information" && len(res.questions) == 0 {
		return nil, errors.New("more information was requested without a question")
	}
	return res, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// printJSONLine writes one event as a JSON line: {"event": name, "data": ...}.
func (a *app) printJSONLine(name string, data json.RawMessage) error {
	if !json.Valid(data) {
		data, _ = json.Marshal(string(data))
	}
	b, err := json.Marshal(struct {
		Event string          `json:"event"`
		Data  json.RawMessage `json:"data"`
	}{name, data})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.stdout, "%s\n", b)
	return err
}

// askInvestigationQuestions reads one answer per question, keeping each
// answer with its question so the next request says which answer is which.
func (a *app) askInvestigationQuestions(questions []string) ([]string, error) {
	in := bufio.NewScanner(a.stdin)
	answers := make([]string, 0, len(questions))
	for _, q := range questions {
		a.notef("%s\n> ", q)
		if !in.Scan() {
			if err := in.Err(); err != nil {
				return nil, err
			}
			return nil, errCancelled
		}
		answers = append(answers, "Q: "+q+"\nA: "+strings.TrimSpace(in.Text()))
	}
	return answers, nil
}

// investigationRenderer draws a stream for a person: commentary on stderr,
// result rows on stdout. Every string from the server passes through notef or
// the table, which strip control characters; csv and json rows are stripped
// here when stdout is a terminal.
type investigationRenderer struct {
	a       *app
	format  string
	columns []string
	tbl     *table
	cw      *csv.Writer
	summary bool
}

func (r *investigationRenderer) handle(event string, data json.RawMessage) error {
	a := r.a
	switch event {
	case "accepted":
		var p struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(data, &p)
		a.notef("Request %s\n", p.RequestID)
	case "status":
		var p struct {
			Phase string `json:"phase"`
		}
		_ = json.Unmarshal(data, &p)
		a.notef("· %s\n", strings.ReplaceAll(p.Phase, "_", " "))
	case "query":
		var p struct {
			Attempt     int    `json:"attempt"`
			SQL         string `json:"sql"`
			Explanation string `json:"explanation"`
		}
		_ = json.Unmarshal(data, &p)
		a.notef("\n── query %d ──\n%s\n", p.Attempt, strings.TrimSpace(p.SQL))
		if p.Explanation != "" {
			a.notef("  (%s)\n", p.Explanation)
		}
	case "review":
		var p struct {
			Accepted bool   `json:"accepted"`
			Reason   string `json:"reason"`
		}
		_ = json.Unmarshal(data, &p)
		verdict := "accepted"
		if !p.Accepted {
			verdict = "not accepted"
		}
		if p.Reason != "" {
			a.notef("  check: %s — %s\n", verdict, p.Reason)
		} else {
			a.notef("  check: %s\n", verdict)
		}
	case "needs_more_information":
		var p struct {
			Questions []string `json:"questions"`
		}
		_ = json.Unmarshal(data, &p)
		a.notef("\nMore information is needed:\n")
		for i, q := range p.Questions {
			a.notef("  %d. %s\n", i+1, q)
		}
	case "declined":
		var p struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(data, &p)
		a.notef("\nDeclined: %s\n", orUnknown(p.Reason))
	case "columns":
		var p struct {
			Columns []struct {
				Name string `json:"name"`
			} `json:"columns"`
		}
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("the server sent unreadable columns: %w", err)
		}
		r.columns = r.columns[:0]
		for _, c := range p.Columns {
			r.columns = append(r.columns, c.Name)
		}
		return r.start()
	case "rows":
		var p struct {
			Rows [][]json.RawMessage `json:"rows"`
		}
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("the server sent unreadable rows: %w", err)
		}
		return r.write(p.Rows)
	case "summary":
		var p struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(data, &p)
		if !r.summary {
			a.notef("\n── summary ──\n")
			r.summary = true
		}
		a.notef("%s", p.Text)
	case "error":
		var p struct {
			Class string `json:"class"`
		}
		_ = json.Unmarshal(data, &p)
		a.notef("\nerror: %s\n", orUnknown(p.Class))
	case "done":
		var p struct {
			Outcome   string `json:"outcome"`
			RowCount  int64  `json:"row_count"`
			Truncated bool   `json:"truncated"`
		}
		_ = json.Unmarshal(data, &p)
		if r.summary {
			a.notef("\n")
		}
		line := fmt.Sprintf("\n%s · %d rows", strings.ReplaceAll(orUnknown(p.Outcome), "_", " "), p.RowCount)
		if p.Truncated {
			line += " (TRUNCATED at the row limit — narrow the question for the rest)"
		}
		a.notef("%s\n", line)
	}
	return nil
}

func (r *investigationRenderer) start() error {
	switch r.format {
	case "table":
		r.tbl = r.a.table()
		r.tbl.Header(r.columns...)
	case "csv":
		r.cw = csv.NewWriter(r.a.stdout)
		header := make([]string, len(r.columns))
		for i, c := range r.columns {
			header[i] = r.csvCell(c)
		}
		return r.cw.Write(header)
	}
	return nil
}

func (r *investigationRenderer) write(rows [][]json.RawMessage) error {
	if r.tbl == nil && r.cw == nil && r.format != "json" {
		return errors.New("rows arrived before their columns")
	}
	for _, row := range rows {
		if len(row) != len(r.columns) {
			return fmt.Errorf("a row has %d cells for %d columns", len(row), len(r.columns))
		}
		switch r.format {
		case "json":
			b, err := json.Marshal(row)
			if err != nil {
				return err
			}
			out := string(b)
			if r.a.streamIsTerminal(r.a.stdout) {
				out = textsafe.Strip(out)
			}
			if _, err := io.WriteString(r.a.stdout, out+"\n"); err != nil {
				return err
			}
		case "csv":
			cells := make([]string, len(row))
			for i, c := range row {
				cells[i] = r.csvCell(cellText(c))
			}
			if err := r.cw.Write(cells); err != nil {
				return err
			}
		default:
			cells := make([]any, len(row))
			for i, c := range row {
				cells[i] = cellText(c)
			}
			r.tbl.Row(cells...)
		}
	}
	return nil
}

// csvCell defuses a value a spreadsheet would read as a formula, and strips
// control characters when the file is a terminal.
func (r *investigationRenderer) csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	if r.a.streamIsTerminal(r.a.stdout) {
		s = textsafe.Strip(s)
	}
	return s
}

func (r *investigationRenderer) finish() error {
	if r.tbl != nil {
		return r.tbl.Flush()
	}
	if r.cw != nil {
		r.cw.Flush()
		return r.cw.Error()
	}
	return nil
}

// cellText is one JSON cell as text: a string unquoted, null empty, anything
// else as its JSON.
func cellText(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	if string(raw) == "null" {
		return ""
	}
	return string(raw)
}
