package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

type binding struct {
	Name       string `json:"name"`
	SubRuleID  string `json:"subRuleId,omitempty"`
	Expression string `json:"expression"`
}

type activation struct {
	ID                string    `json:"id"`
	ProtectionName    string    `json:"protectionName"`
	ProtectionVersion int       `json:"protectionVersion"`
	Bindings          []binding `json:"bindings"`
	Disabled          bool      `json:"disabled"`
}

type protectionEntry struct {
	Protection struct {
		Name            string `json:"name"`
		DisplayName     string `json:"display_name"`
		DisplayCategory string `json:"display_category"`
		Version         int    `json:"version"`
		Description     string `json:"description"`
	} `json:"protection"`
	Activation *activation `json:"activation"`
}

func (e protectionEntry) state() string {
	switch {
	case e.Activation == nil:
		return "not set up"
	case e.Activation.Disabled:
		return "off"
	default:
		return "on"
	}
}

// listProtections returns the catalog both decoded and raw, so --json can print
// exactly what the server sent.
func listProtections(ctx context.Context, c *api.Client) ([]protectionEntry, []json.RawMessage, error) {
	var resp struct {
		Protections []json.RawMessage `json:"protections"`
	}
	if err := c.JSON(ctx, http.MethodGet, api.Path("protections"), nil, nil, &resp); err != nil {
		return nil, nil, err
	}
	entries := make([]protectionEntry, len(resp.Protections))
	for i, raw := range resp.Protections {
		if err := json.Unmarshal(raw, &entries[i]); err != nil {
			return nil, nil, err
		}
	}
	return entries, resp.Protections, nil
}

func findProtection(ctx context.Context, c *api.Client, name string) (protectionEntry, json.RawMessage, error) {
	entries, raws, err := listProtections(ctx, c)
	if err != nil {
		return protectionEntry{}, nil, err
	}
	for i, e := range entries {
		if e.Protection.Name == name {
			return e, raws[i], nil
		}
	}
	return protectionEntry{}, nil, fmt.Errorf("no protection named %q (see `clerk-protect protections list`)", name)
}

// parseBinding reads `name=expression` or `subRuleId:name=expression`.
func parseBinding(s string) (binding, error) {
	left, expr, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(left) == "" || strings.TrimSpace(expr) == "" {
		return binding{}, usageError("--bind %q: expected name=expression or subRuleId:name=expression", s)
	}
	b := binding{Name: strings.TrimSpace(left), Expression: expr}
	if sub, name, ok := strings.Cut(b.Name, ":"); ok {
		b.SubRuleID, b.Name = strings.TrimSpace(sub), strings.TrimSpace(name)
		if b.SubRuleID == "" || b.Name == "" {
			return binding{}, usageError("--bind %q: expected subRuleId:name=expression", s)
		}
	}
	return b, nil
}

func bindingKey(subRule, name string) string { return subRule + "\x00" + name }

// mergeBindings applies --bind and --unbind to the bindings the activation
// already has.
//
// MERGED, NOT REPLACED, by default — and that is the difference from the raw
// API. The server replaces the whole binding set on every write, so a request
// carrying one binding silently resets every other parameter to its default.
// That is right for a form that holds the whole set and wrong for a command
// line where you name one thing. --replace-bindings asks for the API's
// behaviour explicitly.
func mergeBindings(existing []binding, binds, unbinds []string, replace bool) ([]binding, error) {
	var out []binding
	if !replace {
		out = append(out, existing...)
	}
	for _, u := range unbinds {
		sub, name, hasSub := strings.Cut(u, ":")
		if !hasSub {
			sub, name = "", u
		}
		kept := out[:0]
		found := false
		for _, b := range out {
			if bindingKey(b.SubRuleID, b.Name) == bindingKey(sub, name) {
				found = true
				continue
			}
			kept = append(kept, b)
		}
		if !found {
			return nil, usageError("--unbind %q: no such binding", u)
		}
		out = kept
	}
	for _, s := range binds {
		b, err := parseBinding(s)
		if err != nil {
			return nil, err
		}
		replaced := false
		for i := range out {
			if bindingKey(out[i].SubRuleID, out[i].Name) == bindingKey(b.SubRuleID, b.Name) {
				out[i] = b
				replaced = true
			}
		}
		if !replaced {
			out = append(out, b)
		}
	}
	if out == nil {
		out = []binding{}
	}
	return out, nil
}

func (a *app) protectionsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "protections", Short: "Turn Clerk's ready-made protections on and off, and tune them"}
	cmd.AddCommand(
		a.protectionsListCmd(),
		a.protectionsShowCmd(),
		a.protectionsEnableCmd(),
		a.protectionsDisableCmd(),
		a.protectionsBindingsCmd(),
		a.protectionsResetCmd(),
	)
	return cmd
}

func (a *app) protectionsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List protections and whether each is on for this instance",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			entries, raws, err := listProtections(ctxOf(cmd), c)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"protections": raws})
			}
			tw := a.table()
			_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tSTATE\tCATEGORY\tTITLE")
			for _, e := range entries {
				category := e.Protection.DisplayCategory
				if category == "" {
					category = "general"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", e.Protection.Name, e.Protection.Version, e.state(), category, e.Protection.DisplayName)
			}
			return tw.Flush()
		},
	}
}

func (a *app) protectionsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one protection and this instance's settings for it",
		Args:  exactArgs(1, "a protection name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := a.client()
			if err != nil {
				return err
			}
			e, raw, err := findProtection(ctxOf(cmd), c, args[0])
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printRaw(raw)
			}
			a.printf("%s (version %d): %s\n", e.Protection.Name, e.Protection.Version, e.state())
			if e.Protection.DisplayName != "" {
				a.printf("  %s\n", e.Protection.DisplayName)
			}
			if e.Protection.Description != "" {
				a.printf("  %s\n", e.Protection.Description)
			}
			if e.Activation != nil {
				if e.Activation.ProtectionVersion != e.Protection.Version {
					a.printf("  Set up against version %d; the current version is %d.\n", e.Activation.ProtectionVersion, e.Protection.Version)
				}
				if len(e.Activation.Bindings) == 0 {
					a.printf("  Bindings: defaults\n")
				}
				for _, b := range e.Activation.Bindings {
					name := b.Name
					if b.SubRuleID != "" {
						name = b.SubRuleID + ":" + b.Name
					}
					a.printf("  %s = %s\n", name, b.Expression)
				}
			}
			return nil
		},
	}
}

func bindingFlags(cmd *cobra.Command, binds, unbinds *[]string, replace *bool) {
	cmd.Flags().StringArrayVar(binds, "bind", nil, "Set a parameter: name=expression, or subRuleId:name=expression (repeatable)")
	cmd.Flags().StringArrayVar(unbinds, "unbind", nil, "Return a parameter to its default: name, or subRuleId:name (repeatable)")
	cmd.Flags().BoolVar(replace, "replace-bindings", false, "Send exactly the --bind values given, resetting every other parameter to its default")
}

func (a *app) reportActivation(resp *api.Response, verb string) error {
	if a.jsonOut {
		return a.printRaw(resp.Body)
	}
	var act activation
	if len(resp.Body) > 0 {
		_ = json.Unmarshal(resp.Body, &act)
	}
	a.printf("%s %s.\n", verb, act.ProtectionName)
	return nil
}

func (a *app) protectionsEnableCmd() *cobra.Command {
	var binds, unbinds []string
	var replace bool
	cmd := &cobra.Command{
		Use:   "enable <name>",
		Short: "Turn a protection on, keeping its existing settings unless told otherwise",
		Args:  exactArgs(1, "a protection name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)
			e, _, err := findProtection(ctx, c, args[0])
			if err != nil {
				return err
			}
			var existing []binding
			if e.Activation != nil {
				existing = e.Activation.Bindings
			}
			bindings, err := mergeBindings(existing, binds, unbinds, replace)
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Turn on protection %s (version %d) with %d binding(s)", args[0], e.Protection.Version, len(bindings))); err != nil {
				return err
			}
			// The version is the one just read. The engine skips an activation
			// pinned to a version that is not the published one, so it must never
			// be a remembered value.
			resp, err := c.Do(ctx, http.MethodPost, api.Path("protections", args[0], "enable"), nil,
				map[string]any{"version": e.Protection.Version, "bindings": bindings})
			if err != nil {
				return err
			}
			return a.reportActivation(resp, "Turned on")
		},
	}
	bindingFlags(cmd, &binds, &unbinds, &replace)
	return cmd
}

func (a *app) protectionsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Turn a protection off, keeping its settings for later",
		Args:  exactArgs(1, "a protection name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Turn off protection " + args[0]); err != nil {
				return err
			}
			resp, err := c.Do(ctxOf(cmd), http.MethodPost, api.Path("protections", args[0], "disable"), nil, nil)
			if err != nil {
				return err
			}
			return a.reportActivation(resp, "Turned off")
		},
	}
}

func (a *app) protectionsBindingsCmd() *cobra.Command {
	var binds, unbinds []string
	var replace bool
	cmd := &cobra.Command{
		Use:   "bindings <name>",
		Short: "Change a protection's parameters without turning it on or off",
		Args:  exactArgs(1, "a protection name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(binds) == 0 && len(unbinds) == 0 && !replace {
				return usageError("give --bind, --unbind, or --replace-bindings")
			}
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			ctx := ctxOf(cmd)
			e, _, err := findProtection(ctx, c, args[0])
			if err != nil {
				return err
			}
			if e.Activation == nil {
				return fmt.Errorf("protection %s is not set up on this instance — `protections enable` it first", args[0])
			}
			bindings, err := mergeBindings(e.Activation.Bindings, binds, unbinds, replace)
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Set %d binding(s) on protection %s", len(bindings), args[0])); err != nil {
				return err
			}
			resp, err := c.Do(ctx, http.MethodPatch, api.Path("protections", args[0], "bindings"), nil, map[string]any{"bindings": bindings})
			if err != nil {
				return err
			}
			return a.reportActivation(resp, "Updated")
		},
	}
	bindingFlags(cmd, &binds, &unbinds, &replace)
	return cmd
}

func (a *app) protectionsResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset <name>",
		Short: "Remove a protection from this instance, discarding its settings",
		Args:  exactArgs(1, "a protection name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireConsent(); err != nil {
				return err
			}
			c, _, err := a.client()
			if err != nil {
				return err
			}
			if err := a.confirm("Remove protection " + args[0] + " and discard its settings"); err != nil {
				return err
			}
			if _, err := c.Do(ctxOf(cmd), http.MethodDelete, api.Path("protections", args[0], "activation"), nil, nil); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"reset": args[0]})
			}
			a.printf("Removed protection %s from this instance.\n", args[0])
			return nil
		},
	}
}
