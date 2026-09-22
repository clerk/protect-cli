package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/httperr"
)

// replayAlreadyApplied is the server's message when a replay's change is
// already in place: applied earlier, or by another client that won the race to
// apply it. That 409 alone is a success. The server also answers 409 for a
// replay that has not finished or that failed, and nothing was applied then.
const replayAlreadyApplied = "this replay has already been applied"

type replayJob struct {
	ReplayID      string          `json:"replayId"`
	Status        string          `json:"status"`
	Error         string          `json:"error"`
	DecisionsRead int64           `json:"decisionsRead"`
	CreatedAt     string          `json:"createdAt"`
	FinishedAt    string          `json:"finishedAt"`
	AppliedAt     string          `json:"appliedAt"`
	Request       json.RawMessage `json:"request"`
	MatchesTotal  int64           `json:"matchesTotal"`
	MatchesTrunc  bool            `json:"matchesTruncated"`
}

func (j replayJob) name() string {
	var req struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(j.Request, &req)
	return req.Name
}

func (a *app) replayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Score a rule change against traffic you already had, then apply it",
	}
	cmd.AddCommand(
		a.replayCreateCmd(),
		a.replayListCmd(),
		a.replayGetCmd(),
		a.replayWatchCmd(),
		a.replayExportCmd(),
		a.replayApplyCmd(),
	)
	return cmd
}

func (a *app) replayCreateCmd() *cobra.Command {
	var file, name, since, from, to, ruleset string
	var watch bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Start a replay of a candidate change",
		Long: "The candidate change is a JSON request body in --file (the same shape the Protect Labs replay " +
			"page sends). --name, --since, --from, --to and --ruleset are applied on top of it. A replay is " +
			"a background job that reads your recent traffic, so it asks first, and needs --yes when not " +
			"running interactively.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return usageError("--file is required: the candidate change, as JSON")
			}
			raw, err := a.readJSONFile(file)
			if err != nil {
				return err
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil || body == nil {
				return usageError("%s is not a JSON object", file)
			}
			for k, v := range map[string]string{"name": name, "since": since, "from": from, "to": to, "ruleset": ruleset} {
				if v != "" {
					body[k] = v
				}
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Start a replay on this instance"); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("replay"), nil, body)
			if err != nil {
				return err
			}
			var created struct {
				ReplayID string `json:"replayId"`
				Status   string `json:"status"`
			}
			if err := json.Unmarshal(resp.Body, &created); err != nil {
				return err
			}
			if watch {
				a.notef("Started replay %s.\n", created.ReplayID)
				return a.watchReplay(cmd, created.ReplayID)
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			a.printf("Started replay %s (%s). Follow it with `clerk-protect replay watch %s`.\n", created.ReplayID, created.Status, created.ReplayID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&file, "file", "", "The replay request as JSON (- for stdin)")
	f.StringVar(&name, "name", "", "A label for the history list")
	f.StringVar(&since, "since", "", "Replay this far back (e.g. 6h)")
	f.StringVar(&from, "from", "", "Window start, RFC 3339")
	f.StringVar(&to, "to", "", "Window end, RFC 3339")
	f.StringVar(&ruleset, "ruleset", "", "Ruleset the candidate applies to")
	f.BoolVar(&watch, "watch", false, "Follow the replay until it finishes")
	return cmd
}

func (a *app) replayListCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Recent replays on this instance",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodGet, api.Path("replay"), url.Values{"limit": {strconv.Itoa(limit)}}, nil)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			var list struct {
				Replays []replayJob `json:"replays"`
			}
			if err := json.Unmarshal(resp.Body, &list); err != nil {
				return err
			}
			tw := a.table()
			_, _ = fmt.Fprintln(tw, "ID\tSTATUS\tCREATED\tDECISIONS\tCHANGED\tNAME")
			for _, j := range list.Replays {
				status := j.Status
				if j.AppliedAt != "" {
					status += " (applied)"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n", j.ReplayID, status, j.CreatedAt, j.DecisionsRead, j.MatchesTotal, j.name())
			}
			return tw.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 15, "How many")
	return cmd
}

func (a *app) replayGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <replay-id>",
		Short: "Show a replay and its report",
		Args:  exactArgs(1, "a replay id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.getAndPrint(cmd, api.Path("replay", args[0]))
		},
	}
}

func (a *app) replayWatchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch <replay-id>",
		Short: "Follow a replay until it finishes; exits 1 if it fails",
		Args:  exactArgs(1, "a replay id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.watchReplay(cmd, args[0])
		},
	}
}

func (a *app) watchReplay(cmd *cobra.Command, id string) error {
	c, _, err := a.client()
	if err != nil {
		return err
	}
	var final *replayJob
	var finalRaw string
	err = c.Stream(ctxOf(cmd), api.Path("replay", id, "watch"), nil, func(ev api.Event) error {
		var job replayJob
		if err := json.Unmarshal([]byte(ev.Data), &job); err != nil {
			return nil
		}
		switch ev.Name {
		case "succeeded", "failed":
			final, finalRaw = &job, ev.Data
			return api.ErrStop
		default:
			a.notef("%s: %s (%d decisions read)\n", id, job.Status, job.DecisionsRead)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if final == nil {
		return fmt.Errorf("the watch on replay %s ended before it finished — check it with `clerk-protect replay get %s`", id, id)
	}
	if a.jsonOut {
		if err := a.printRaw([]byte(finalRaw)); err != nil {
			return err
		}
	}
	if final.Status == "failed" || final.Error != "" {
		msg := final.Error
		if msg == "" {
			msg = "no reason given"
		}
		return &exitError{code: ExitError, err: fmt.Errorf("replay %s failed: %s", id, msg)}
	}
	if !a.jsonOut {
		a.printf("Replay %s finished: %d decisions read, %d would change.\n", id, final.DecisionsRead, final.MatchesTotal)
		if final.MatchesTrunc {
			a.printf("The export holds only the first rows of those changes.\n")
		}
		a.printf("See the report with `clerk-protect replay get %s`; apply it with `clerk-protect replay apply %s`.\n", id, id)
	}
	return nil
}

func (a *app) replayExportCmd() *cobra.Command {
	var from, to, output string
	cmd := &cobra.Command{
		Use:   "export <replay-id>",
		Short: "Download the decisions a replay would change, as JSON lines",
		Long: "With -o, the file is replaced only once the whole export has arrived: a refused or interrupted " +
			"download leaves an existing file as it was.",
		Args: exactArgs(1, "a replay id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			q := url.Values{}
			if from != "" {
				q.Set("from", strings.ToUpper(from))
			}
			if to != "" {
				q.Set("to", strings.ToUpper(to))
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			download := func(w io.Writer) error {
				return c.Download(ctxOf(cmd), api.Path("replay", args[0], "export"), q, w)
			}
			if output == "" || output == "-" {
				return download(a.stdout)
			}
			return replaceFileOnSuccess(output, download)
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "Only decisions whose outcome was this: ALLOW, CHALLENGE or DENY")
	f.StringVar(&to, "to", "", "Only decisions whose outcome would become this: ALLOW, CHALLENGE or DENY")
	f.StringVarP(&output, "output", "o", "", "Write to this file instead of standard output")
	return cmd
}

// replaceFileOnSuccess writes what fetch produces into a temporary file beside
// path, and renames it over path only once fetch has returned without error.
// A refusal, a dropped connection or an interrupt leaves an existing file
// exactly as it was, rather than truncated or empty. The file is created 0600:
// an export holds decisions, with the addresses and identifiers in them.
func replaceFileOnSuccess(path string, fetch func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.partial")
	if err != nil {
		return err
	}
	name := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := fetch(tmp); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	done = true
	return nil
}

func (a *app) replayApplyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apply <replay-id>",
		Short: "Apply the change a replay measured",
		Long: "Applies exactly the change the replay scored, as stored with the replay. A replay that was " +
			"already applied exits 0; one that has not finished, or failed, exits 1.",
		Args: exactArgs(1, "a replay id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Apply replay " + args[0] + " to this instance's rules"); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("replay", args[0], "apply"), nil, map[string]any{})
			var he *httperr.Error
			if errors.As(err, &he) && he.Status == http.StatusConflict && he.Message == replayAlreadyApplied {
				// A retry, or a second terminal: the rules are where they should be.
				if a.jsonOut {
					return a.printJSON(map[string]any{"replay_id": args[0], "already_applied": true})
				}
				a.notef("Replay %s was already applied; nothing changed.\n", args[0])
				return nil
			}
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			var applied struct {
				Applied []struct {
					Op      string `json:"op"`
					Ruleset string `json:"ruleset"`
					RuleID  string `json:"ruleId"`
				} `json:"applied"`
				Warnings []string `json:"warnings"`
			}
			if err := json.Unmarshal(resp.Body, &applied); err != nil {
				return err
			}
			a.printf("Applied replay %s.\n", args[0])
			for _, r := range applied.Applied {
				a.printf("  %s %s %s\n", r.Op, r.Ruleset, r.RuleID)
			}
			for _, w := range applied.Warnings {
				a.printf("  Note: %s\n", w)
			}
			return nil
		},
	}
}
