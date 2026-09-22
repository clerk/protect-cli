package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/httperr"
)

type rateLimit struct {
	Key         string   `json:"key,omitempty"`
	Keys        []string `json:"keys,omitempty"`
	Window      string   `json:"window"`
	Limit       *int64   `json:"limit,omitempty"`
	IdentityKey string   `json:"identityKey,omitempty"`
}

type challengeConfig struct {
	Type          string `json:"type,omitempty"`
	UploadBytes   string `json:"uploadBytes,omitempty"`
	DownloadBytes string `json:"downloadBytes,omitempty"`
}

type rule struct {
	ID          string           `json:"id"`
	Description string           `json:"description,omitempty"`
	Expression  string           `json:"expression"`
	Action      string           `json:"action"`
	Disabled    bool             `json:"disabled,omitempty"`
	ExpiresAt   string           `json:"expiresAt,omitempty"`
	RateLimit   *rateLimit       `json:"rateLimit,omitempty"`
	Challenge   *challengeConfig `json:"challenge,omitempty"`
}

type rulesPage struct {
	Rules         []json.RawMessage `json:"rules"`
	NextPageToken *string           `json:"nextPageToken"`
}

type rulesetInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// ruleBodyKeys are the fields a rule write accepts. An update sends back
// exactly these from the stored rule, because a write REPLACES the rule: a
// field left out is a field cleared.
var ruleBodyKeys = []string{"description", "expression", "action", "rateLimit", "challenge", "blockMessage", "expiresAt"}

func rulesetNames(ctx context.Context, c *api.Client) ([]rulesetInfo, error) {
	var resp struct {
		Rulesets []rulesetInfo `json:"rulesets"`
	}
	if err := c.JSON(ctx, http.MethodGet, api.Path("rulesets"), nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Rulesets, nil
}

// listRules reads every page of a ruleset.
func listRules(ctx context.Context, c *api.Client, ruleset string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	seen := map[string]bool{}
	after := ""
	for {
		q := url.Values{}
		if after != "" {
			q.Set("after", after)
		}
		var page rulesPage
		if err := c.JSON(ctx, http.MethodGet, api.Path("rulesets", ruleset, "rules"), q, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Rules...)
		if page.NextPageToken == nil || *page.NextPageToken == "" || seen[*page.NextPageToken] {
			return all, nil
		}
		seen[*page.NextPageToken] = true
		after = *page.NextPageToken
	}
}

func (a *app) rulesetsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rulesets", Short: "The rulesets rules can be written into"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List rulesets",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			sets, err := rulesetNames(ctxOf(cmd), c)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"rulesets": sets})
			}
			tw := a.table()
			_, _ = fmt.Fprintln(tw, "NAME\tLABEL\tDESCRIPTION")
			for _, s := range sets {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, s.Label, s.Description)
			}
			return tw.Flush()
		},
	})
	return cmd
}

func (a *app) rulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Read and change this instance's custom rules"}
	cmd.AddCommand(
		a.rulesListCmd(),
		a.rulesGetCmd(),
		a.rulesCreateCmd(),
		a.rulesUpdateCmd(),
		a.rulesToggleCmd("enable", "Turn a disabled rule back on"),
		a.rulesToggleCmd("disable", "Turn a rule off without deleting it (keeps its id and rate-limit counters)"),
		a.rulesDeleteCmd(),
		a.rulesReorderCmd(),
		a.rulesValidateCmd(),
	)
	return cmd
}

func (a *app) rulesListCmd() *cobra.Command {
	var ruleset string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List rules, in evaluation order",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)
			names := []string{ruleset}
			if ruleset == "" {
				sets, err := rulesetNames(ctx, c)
				if err != nil {
					return err
				}
				names = names[:0]
				for _, s := range sets {
					names = append(names, s.Name)
				}
			}
			type block struct {
				Ruleset string            `json:"ruleset"`
				Rules   []json.RawMessage `json:"rules"`
			}
			var out []block
			for _, name := range names {
				rules, err := listRules(ctx, c, name)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				if rules == nil {
					rules = []json.RawMessage{}
				}
				out = append(out, block{Ruleset: name, Rules: rules})
			}
			if a.jsonOut {
				return a.printJSON(out)
			}
			for i, b := range out {
				if i > 0 {
					a.printf("\n")
				}
				if len(b.Rules) == 0 {
					a.printf("%s: no rules\n", b.Ruleset)
					continue
				}
				a.printf("%s (%d)\n", b.Ruleset, len(b.Rules))
				for n, raw := range b.Rules {
					var r rule
					if err := json.Unmarshal(raw, &r); err != nil {
						return err
					}
					a.renderRule(n+1, r)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "Only this ruleset (default: every ruleset)")
	return cmd
}

func (a *app) renderRule(position int, r rule) {
	var tags []string
	if r.Disabled {
		tags = append(tags, "disabled")
	}
	if r.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, r.ExpiresAt); err == nil && !t.After(a.now()) {
			tags = append(tags, "expired "+r.ExpiresAt)
		} else {
			tags = append(tags, "expires "+r.ExpiresAt)
		}
	}
	suffix := ""
	if len(tags) > 0 {
		suffix = "  [" + strings.Join(tags, ", ") + "]"
	}
	if position > 0 {
		a.printf("  #%d  %s  %s%s\n", position, r.ID, strings.ToUpper(r.Action), suffix)
	} else {
		a.printf("  %s  %s%s\n", r.ID, strings.ToUpper(r.Action), suffix)
	}
	a.printf("      if: %s\n", r.Expression)
	if r.Description != "" {
		a.printf("      description: %s\n", r.Description)
	}
	if rl := r.RateLimit; rl != nil {
		keys := rl.Keys
		if len(keys) == 0 && rl.Key != "" {
			keys = []string{rl.Key}
		}
		limit := "?"
		if rl.Limit != nil {
			limit = fmt.Sprint(*rl.Limit)
		}
		line := fmt.Sprintf("%s per %s by %s", limit, rl.Window, strings.Join(keys, ", "))
		if rl.IdentityKey != "" {
			line += " (distinct " + rl.IdentityKey + ")"
		}
		a.printf("      rate limit: %s\n", line)
	}
	if ch := r.Challenge; ch != nil && ch.Type != "" {
		line := ch.Type
		if ch.UploadBytes != "" {
			line += " upload=" + ch.UploadBytes
		}
		if ch.DownloadBytes != "" {
			line += " download=" + ch.DownloadBytes
		}
		a.printf("      challenge: %s\n", line)
	}
}

func requireRuleset(ruleset string) error {
	if strings.TrimSpace(ruleset) == "" {
		return usageError("--ruleset is required (see `clerk-protect rulesets list`)")
	}
	return nil
}

func (a *app) rulesGetCmd() *cobra.Command {
	var ruleset string
	cmd := &cobra.Command{
		Use:   "get <rule-id>",
		Short: "Show one rule",
		Args:  exactArgs(1, "a rule id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodGet, api.Path("rulesets", ruleset, "rules", args[0]), nil, nil)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(resp.Body)
			}
			var r rule
			if err := json.Unmarshal(resp.Body, &r); err != nil {
				return err
			}
			a.renderRule(0, r)
			return nil
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "The rule's ruleset (required)")
	return cmd
}

// addRuleBodyFlags registers the flags a rule body is built from.
func addRuleBodyFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("expression", "", "Rule expression")
	f.String("action", "", "Rule action: block or challenge")
	f.String("description", "", "What the rule is for")
	f.StringSlice("rate-limit-keys", nil, "Rate-limit key expressions, comma-separated (e.g. ip.address)")
	f.String("rate-limit-window", "", "Rate-limit window, as an ISO 8601 duration (e.g. PT1H)")
	f.Int64("rate-limit-limit", 0, "Rate-limit threshold")
	f.String("rate-limit-identity-key", "", "Count distinct values of this expression instead of events")
	f.String("challenge-type", "", "For a challenge rule: turnstile or proof_of_transfer")
	f.String("challenge-upload-bytes", "", "proof_of_transfer: expression for the bytes the client must upload")
	f.String("challenge-download-bytes", "", "proof_of_transfer: expression for the bytes the client must download")
	f.String("expires-at", "", "Stop enforcing at this RFC 3339 time")
	f.Duration("expires-in", 0, "Stop enforcing after this long (e.g. 72h)")
	f.String("file", "", "Read the whole rule body as JSON from this file (- for stdin)")
}

func normalizeAction(s string) (string, error) {
	switch v := strings.ToUpper(strings.TrimSpace(s)); v {
	case "BLOCK", "CHALLENGE":
		return v, nil
	default:
		return "", usageError("invalid action %q (use block or challenge)", s)
	}
}

// ruleFlagOverrides returns the body fields the flags set. Only flags that were
// actually given contribute, so an update changes what was asked and nothing
// else.
func (a *app) ruleFlagOverrides(cmd *cobra.Command) (map[string]any, error) {
	f := cmd.Flags()
	out := map[string]any{}
	if f.Changed("expression") {
		v, _ := f.GetString("expression")
		out["expression"] = v
	}
	if f.Changed("action") {
		v, _ := f.GetString("action")
		action, err := normalizeAction(v)
		if err != nil {
			return nil, err
		}
		out["action"] = action
	}
	if f.Changed("description") {
		v, _ := f.GetString("description")
		out["description"] = v
	}
	if f.Changed("rate-limit-keys") || f.Changed("rate-limit-window") || f.Changed("rate-limit-limit") || f.Changed("rate-limit-identity-key") {
		keys, _ := f.GetStringSlice("rate-limit-keys")
		window, _ := f.GetString("rate-limit-window")
		limit, _ := f.GetInt64("rate-limit-limit")
		identity, _ := f.GetString("rate-limit-identity-key")
		if len(keys) == 0 || window == "" {
			return nil, usageError("a rate limit needs --rate-limit-keys and --rate-limit-window")
		}
		rl := rateLimit{Keys: keys, Window: window, IdentityKey: identity}
		if limit > 0 {
			rl.Limit = &limit
		}
		out["rateLimit"] = rl
	}
	if f.Changed("challenge-type") || f.Changed("challenge-upload-bytes") || f.Changed("challenge-download-bytes") {
		typ, _ := f.GetString("challenge-type")
		up, _ := f.GetString("challenge-upload-bytes")
		down, _ := f.GetString("challenge-download-bytes")
		typ = strings.ToLower(strings.TrimSpace(typ))
		if typ != "turnstile" && typ != "proof_of_transfer" {
			return nil, usageError("--challenge-type must be turnstile or proof_of_transfer")
		}
		out["challenge"] = challengeConfig{Type: typ, UploadBytes: up, DownloadBytes: down}
	}
	if f.Changed("expires-at") && f.Changed("expires-in") {
		return nil, usageError("--expires-at and --expires-in are mutually exclusive")
	}
	if f.Changed("expires-at") {
		v, _ := f.GetString("expires-at")
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			return nil, usageError("--expires-at must be RFC 3339, e.g. 2026-10-01T00:00:00Z")
		}
		out["expiresAt"] = v
	}
	if f.Changed("expires-in") {
		d, _ := f.GetDuration("expires-in")
		if d <= 0 {
			return nil, usageError("--expires-in must be positive")
		}
		out["expiresAt"] = a.now().Add(d).UTC().Format(time.RFC3339)
	}
	return out, nil
}

func (a *app) ruleBodyFromFile(cmd *cobra.Command) (map[string]any, bool, error) {
	path, _ := cmd.Flags().GetString("file")
	if path == "" {
		return nil, false, nil
	}
	raw, err := a.readJSONFile(path)
	if err != nil {
		return nil, true, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, true, usageError("the rule body must be a JSON object")
	}
	return body, true, nil
}

func (a *app) rulesCreateCmd() *cobra.Command {
	var ruleset string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a rule",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			body, fromFile, err := a.ruleBodyFromFile(cmd)
			if err != nil {
				return err
			}
			if !fromFile {
				body, err = a.ruleFlagOverrides(cmd)
				if err != nil {
					return err
				}
				if body["expression"] == nil || body["expression"] == "" {
					return usageError("--expression is required")
				}
				if body["action"] == nil {
					return usageError("--action is required (block or challenge)")
				}
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Create a %v rule in %s", body["action"], ruleset)); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("rulesets", ruleset, "rules"), nil, body)
			if err != nil {
				return err
			}
			return a.reportRule(resp, "Created", ruleset)
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "Ruleset to create the rule in (required)")
	addRuleBodyFlags(cmd)
	return cmd
}

func (a *app) reportRule(resp *api.Response, verb, ruleset string) error {
	if a.jsonOut {
		return a.printRaw(resp.Body)
	}
	var r rule
	if err := json.Unmarshal(resp.Body, &r); err != nil {
		return err
	}
	a.printf("%s rule %s in %s.\n", verb, r.ID, ruleset)
	a.renderRule(0, r)
	return nil
}

func (a *app) rulesUpdateCmd() *cobra.Command {
	var ruleset string
	var clearRateLimit, clearChallenge, clearExpiry bool
	cmd := &cobra.Command{
		Use:   "update <rule-id>",
		Short: "Change a rule",
		Long: "Changes only what the flags name and keeps the rest of the stored rule. With --file the " +
			"file is the whole new rule: anything it leaves out is cleared.",
		Args: exactArgs(1, "a rule id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)
			path := api.Path("rulesets", ruleset, "rules", args[0])
			body, fromFile, err := a.ruleBodyFromFile(cmd)
			if err != nil {
				return err
			}
			if !fromFile {
				var stored map[string]any
				if err := c.JSON(ctx, http.MethodGet, path, nil, nil, &stored); err != nil {
					return err
				}
				body = map[string]any{}
				for _, k := range ruleBodyKeys {
					if v, ok := stored[k]; ok {
						body[k] = v
					}
				}
				overrides, err := a.ruleFlagOverrides(cmd)
				if err != nil {
					return err
				}
				if len(overrides) == 0 && !clearRateLimit && !clearChallenge && !clearExpiry {
					return usageError("nothing to change — give a flag to change, or --file with the whole rule")
				}
				for k, v := range overrides {
					body[k] = v
				}
				if clearRateLimit {
					delete(body, "rateLimit")
				}
				if clearChallenge {
					delete(body, "challenge")
				}
				if clearExpiry {
					delete(body, "expiresAt")
				}
			}
			if err := a.confirm(fmt.Sprintf("Change rule %s in %s", args[0], ruleset)); err != nil {
				return err
			}
			resp, err := c.Do(ctx, http.MethodPut, path, nil, body)
			if err != nil {
				return err
			}
			return a.reportRule(resp, "Updated", ruleset)
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "The rule's ruleset (required)")
	addRuleBodyFlags(cmd)
	cmd.Flags().BoolVar(&clearRateLimit, "clear-rate-limit", false, "Remove the rule's rate limit")
	cmd.Flags().BoolVar(&clearChallenge, "clear-challenge", false, "Remove the rule's challenge settings")
	cmd.Flags().BoolVar(&clearExpiry, "clear-expiry", false, "Remove the rule's expiry")
	return cmd
}

func (a *app) rulesToggleCmd(verb, short string) *cobra.Command {
	var ruleset string
	cmd := &cobra.Command{
		Use:   verb + " <rule-id>",
		Short: short,
		Args:  exactArgs(1, "a rule id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			title := strings.ToUpper(verb[:1]) + verb[1:]
			if err := a.confirm(fmt.Sprintf("%s rule %s in %s", title, args[0], ruleset)); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("rulesets", ruleset, "rules", args[0], verb), nil, nil)
			if err != nil {
				return err
			}
			return a.reportRule(resp, title+"d", ruleset)
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "The rule's ruleset (required)")
	return cmd
}

func (a *app) rulesDeleteCmd() *cobra.Command {
	var ruleset string
	cmd := &cobra.Command{
		Use:   "delete <rule-id>",
		Short: "Delete a rule",
		Long:  "Deletes a rule. Its rate-limit counters go with it; `rules disable` keeps them.",
		Args:  exactArgs(1, "a rule id"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Delete rule %s from %s", args[0], ruleset)); err != nil {
				return err
			}
			if _, err := c.Do(ctxOf(cmd), http.MethodDelete, api.Path("rulesets", ruleset, "rules", args[0]), nil, nil); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"deleted": args[0], "ruleset": ruleset})
			}
			a.printf("Deleted rule %s from %s.\n", args[0], ruleset)
			return nil
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "The rule's ruleset (required)")
	return cmd
}

func (a *app) rulesValidateCmd() *cobra.Command {
	var ruleset string
	cmd := &cobra.Command{
		Use:   "validate [expression]",
		Short: "Ask whether the server would accept a rule, without creating it",
		Long: "Takes the same flags as `rules create`. The expression may also be the argument. Exits 1 " +
			"when the rule is invalid, so it works as a check in a script.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError("expected at most one expression")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			body, fromFile, err := a.ruleBodyFromFile(cmd)
			if err != nil {
				return err
			}
			if !fromFile {
				body, err = a.ruleFlagOverrides(cmd)
				if err != nil {
					return err
				}
				if len(args) == 1 {
					if cmd.Flags().Changed("expression") {
						return usageError("give the expression as an argument or with --expression, not both")
					}
					body["expression"] = args[0]
				}
				if body["expression"] == nil || body["expression"] == "" {
					return usageError("an expression is required")
				}
				if body["action"] == nil {
					body["action"] = "BLOCK"
				}
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			var verdict struct {
				Valid  bool `json:"valid"`
				Errors []struct {
					Field   string `json:"field"`
					Message string `json:"message"`
					Code    string `json:"code"`
				} `json:"errors"`
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("rulesets", ruleset, "rules", "validate"), nil, body)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(resp.Body, &verdict); err != nil {
				return err
			}
			if a.jsonOut {
				if err := a.printRaw(resp.Body); err != nil {
					return err
				}
			} else if verdict.Valid {
				a.printf("Valid %v rule for %s.\n", body["action"], ruleset)
			} else {
				a.printf("Invalid:\n")
				for _, e := range verdict.Errors {
					a.printf("  %s: %s\n", e.Field, e.Message)
				}
			}
			if !verdict.Valid {
				return &exitError{code: ExitError, err: errors.New("the rule is not valid")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ruleset, "ruleset", "", "Ruleset to validate against (required)")
	addRuleBodyFlags(cmd)
	return cmd
}

// isConflict reports a 409: the ruleset changed under a write that assumed its
// shape.
func isConflict(err error) bool {
	var he *httperr.Error
	return errors.As(err, &he) && he.Status == http.StatusConflict
}
