package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

// moveSpec is one rule and exactly one destination.
type moveSpec struct {
	id     string
	top    bool
	bottom bool
	to     int // 1-based; 0 is unset
	before string
	after  string
}

func (m moveSpec) destinations() int {
	n := 0
	for _, set := range []bool{m.top, m.bottom, m.to != 0, m.before != "", m.after != ""} {
		if set {
			n++
		}
	}
	return n
}

// planReorder computes the complete order to send.
//
// The server takes the whole permutation — the right contract for a drag and
// drop, the wrong one for a person — so the translation happens here, against
// the order just read. Everything is checked locally first: a mistyped id and a
// rule deleted a moment ago both come back from the server as the same conflict,
// and only this side still knows which one you typed.
func planReorder(current []string, move moveSpec, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		if move.id != "" {
			return nil, usageError("give either --move or a complete order, not both")
		}
		return explicitOrder(current, explicit)
	}
	if move.id == "" {
		return nil, usageError("give --move with a destination, or the complete order as arguments")
	}
	if move.destinations() != 1 {
		return nil, usageError("give exactly one of --top, --bottom, --to, --before, --after")
	}
	from := slices.Index(current, move.id)
	if from < 0 {
		return nil, usageError("rule %s is not in this ruleset", move.id)
	}
	rest := slices.Delete(slices.Clone(current), from, from+1)
	var at int
	switch {
	case move.top:
		at = 0
	case move.bottom:
		at = len(rest)
	case move.to != 0:
		if move.to < 1 || move.to > len(current) {
			return nil, usageError("--to must be between 1 and %d", len(current))
		}
		at = move.to - 1
	case move.before != "":
		at = slices.Index(rest, move.before)
		if at < 0 {
			return nil, usageError("rule %s is not in this ruleset", move.before)
		}
	case move.after != "":
		at = slices.Index(rest, move.after)
		if at < 0 {
			return nil, usageError("rule %s is not in this ruleset", move.after)
		}
		at++
	}
	return slices.Insert(rest, at, move.id), nil
}

func explicitOrder(current, explicit []string) ([]string, error) {
	seen := map[string]bool{}
	for _, id := range explicit {
		if seen[id] {
			return nil, usageError("rule %s is listed twice", id)
		}
		seen[id] = true
		if !slices.Contains(current, id) {
			return nil, usageError("rule %s is not in this ruleset", id)
		}
	}
	var missing []string
	for _, id := range current {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return nil, usageError("a complete order must name every rule; missing %s", strings.Join(missing, ", "))
	}
	return slices.Clone(explicit), nil
}

func ruleIDs(raw []json.RawMessage) ([]string, error) {
	ids := make([]string, 0, len(raw))
	for _, r := range raw {
		var head struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r, &head); err != nil {
			return nil, err
		}
		ids = append(ids, head.ID)
	}
	return ids, nil
}

func (a *app) rulesReorderCmd() *cobra.Command {
	var ruleset string
	var move moveSpec
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "reorder [rule-id...]",
		Short: "Change the order rules are evaluated in",
		Long: "Rules run top-down, and the first block or challenge that matches decides. Move one rule " +
			"with --move and one destination, or give every rule id in the new order. Reordering keeps rule " +
			"ids, so rate-limit counters survive.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRuleset(ruleset); err != nil {
				return err
			}
			if !dryRun {
				if err := a.requireConsent(); err != nil {
					return err
				}
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)
			// A --move is still meaningful against a list that changed, so it is
			// replanned and retried once on a conflict. A complete order is not:
			// applied to a different set it would drop or resurrect a rule you
			// never saw.
			attempts := 1
			if move.id != "" {
				attempts = 2
			}
			for attempt := 1; ; attempt++ {
				current, planned, err := a.planAgainstServer(ctx, c, ruleset, move, args)
				if err != nil {
					return err
				}
				if slices.Equal(current, planned) {
					if a.jsonOut {
						return a.printJSON(map[string]any{"ruleset": ruleset, "rule_ids": planned, "changed": false})
					}
					a.printf("%s is already in that order.\n", ruleset)
					return nil
				}
				if dryRun {
					if a.jsonOut {
						return a.printJSON(map[string]any{"ruleset": ruleset, "rule_ids": planned, "changed": true, "dry_run": true})
					}
					a.printOrder(current, planned)
					return nil
				}
				if attempt == 1 {
					a.printOrder(current, planned)
					if err := a.confirm("Apply this order to " + ruleset); err != nil {
						return err
					}
				}
				_, err = c.Do(ctx, http.MethodPut, api.Path("rulesets", ruleset, "rules", "order"), nil, map[string]any{"rule_ids": planned})
				if err == nil {
					if a.jsonOut {
						return a.printJSON(map[string]any{"ruleset": ruleset, "rule_ids": planned, "changed": true})
					}
					a.printf("Reordered %s.\n", ruleset)
					return nil
				}
				if !isConflict(err) || attempt >= attempts {
					return err
				}
				a.notef("The ruleset changed while reordering; trying again against the current order.\n")
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&ruleset, "ruleset", "", "Ruleset to reorder (required)")
	f.StringVar(&move.id, "move", "", "Rule to move")
	f.BoolVar(&move.top, "top", false, "Move it first")
	f.BoolVar(&move.bottom, "bottom", false, "Move it last")
	f.IntVar(&move.to, "to", 0, "Move it to this position (1 is first)")
	f.StringVar(&move.before, "before", "", "Move it before this rule")
	f.StringVar(&move.after, "after", "", "Move it after this rule")
	f.BoolVar(&dryRun, "dry-run", false, "Show the new order without applying it")
	return cmd
}

func (a *app) planAgainstServer(ctx context.Context, c *api.Client, ruleset string, move moveSpec, explicit []string) ([]string, []string, error) {
	raw, err := listRules(ctx, c, ruleset)
	if err != nil {
		return nil, nil, err
	}
	current, err := ruleIDs(raw)
	if err != nil {
		return nil, nil, err
	}
	planned, err := planReorder(current, move, explicit)
	return current, planned, err
}

func (a *app) printOrder(current, planned []string) {
	if a.jsonOut {
		return
	}
	for i, id := range planned {
		marker := "  "
		if slices.Index(current, id) != i {
			marker = "->"
		}
		a.notef("%s #%d  %s\n", marker, i+1, id)
	}
}
