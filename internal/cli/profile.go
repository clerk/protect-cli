package cli

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/profile"
)

func (a *app) profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "profile",
		Aliases: []string{"profiles"},
		Short:   "Name the instance, and API origin, that commands use by default",
		Long: "A profile names the instance commands act on, and optionally the API origin, so you do not repeat " +
			"--instance on every command. Choose one with --profile or " + profile.EnvProfile + ", or make one the " +
			"default with `clerk-protect profile use`.\n\n" +
			"What a command acts on, first match wins:\n" +
			"  instance    --instance, the profile's instance, the instance you signed in to last\n" +
			"  API origin  --api-url, " + config.EnvAPIURL + ", the profile's API URL, " + config.DefaultAPIBase + "\n\n" +
			"A profile is not a sign-in. A command still needs `clerk-protect login` for the profile's instance, and " +
			"fails rather than acting on another instance while there is none. Profiles change only this computer, " +
			"so these commands do not ask for --yes.",
	}
	cmd.AddCommand(a.profileListCmd(), a.profileShowCmd(), a.profileSetCmd(), a.profileUseCmd(), a.profileDeleteCmd())
	return cmd
}

func (a *app) profiles() (*profile.Set, string, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, "", err
	}
	set, err := profile.Load(dir)
	return set, dir, err
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) profileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the profiles on this computer",
		Args:  noArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			set, _, err := a.profiles()
			if err != nil {
				return err
			}
			type row struct {
				Name       string `json:"name"`
				InstanceID string `json:"instance_id,omitempty"`
				APIURL     string `json:"api_url,omitempty"`
				Default    bool   `json:"default"`
			}
			rows := []row{}
			for _, name := range set.Names() {
				p := set.Profiles[name]
				rows = append(rows, row{Name: name, InstanceID: p.InstanceID, APIURL: p.APIURL, Default: name == set.Default})
			}
			if a.jsonOut {
				return a.printJSON(rows)
			}
			if len(rows) == 0 {
				a.printf("No profiles. Create one with `clerk-protect profile set NAME --instance ins_…`.\n")
				return nil
			}
			tw := a.table()
			tw.Header("", "NAME", "INSTANCE", "API URL")
			tw.Style(0, a.out.Good)
			tw.Style(1, a.out.ID)
			for _, r := range rows {
				mark := ""
				if r.Default {
					mark = "*"
				}
				_, _ = tw.Write([]byte(mark + "\t" + r.Name + "\t" + orDash(r.InstanceID) + "\t" + orDash(r.APIURL) + "\n"))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if set.Default != "" {
				a.printf("\n* the default profile\n")
			}
			return nil
		},
	}
}

func (a *app) profileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [NAME]",
		Short: "Show which profile, instance and API origin commands would use, and why",
		Long: "Without a name, shows what a command run with the same flags and environment would act on. With a " +
			"name, shows what it would act on with --profile NAME. Nothing is sent to the server.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError("expected at most one profile name")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				a.profile = args[0]
			}
			sel, err := a.selection()
			if err != nil {
				return err
			}
			st, err := a.store()
			if err != nil {
				return err
			}
			var until time.Time
			signedIn := false
			if sel.Instance != "" {
				c, err := st.Load(sel.Base, sel.Instance)
				switch {
				case err == nil:
					signedIn, until = true, c.AuthorizationExpiresAt
				case errors.Is(err, auth.ErrLoginRequired):
					// Not signed in: what this command is here to say.
				default:
					// An id that is not one, or a credential that cannot be read,
					// fails a real command too — it is not "signed out".
					return err
				}
			}
			if a.jsonOut {
				out := map[string]any{
					"profile": nilIfEmpty(sel.Profile), "profile_source": nilIfEmpty(sel.ProfileSource),
					"instance_id": nilIfEmpty(sel.Instance), "instance_source": sel.InstanceSource,
					"api_url": sel.Base, "api_url_source": sel.BaseSource,
					"signed_in": signedIn,
				}
				if signedIn {
					out["authorization_expires_at"] = until
				}
				return a.printJSON(out)
			}
			tw := a.kvTable()
			row := func(k, v string) { _, _ = tw.Write([]byte(k + "\t" + v + "\n")) }
			row("Profile", sel.describe(sel.Profile, sel.ProfileSource, "none"))
			row("Instance", sel.describe(sel.Instance, sel.InstanceSource, "none"))
			row("API", sel.describe(sel.Base, sel.BaseSource, ""))
			switch {
			case signedIn:
				tw.Row(a.out.Label("Signed in"), a.out.Good("yes, until "+until.Local().Format(time.RFC1123)))
			default:
				tw.Row(a.out.Label("Signed in"), a.out.Warn("no — run `clerk-protect login`"))
			}
			return tw.Flush()
		},
	}
}

func (a *app) profileSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set NAME",
		Short: "Create or change a profile",
		Long: "Saves --instance and --api-url into the profile NAME, creating it if needed. Only the flags you give " +
			"change anything; --api-url \"\" removes the profile's API URL. A new profile without --instance takes " +
			"the instance you signed in to last on its API origin.",
		Args: exactArgs(1, "a profile name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !profile.ValidName(name) {
				return usageError("%q cannot name a profile: use letters, digits, '.', '_' and '-', starting with a letter or digit", name)
			}
			set, dir, err := a.profiles()
			if err != nil {
				return err
			}
			p, exists := set.Profiles[name]
			setInstance, setAPI := cmd.Flags().Changed("instance"), cmd.Flags().Changed("api-url")
			if exists && !setInstance && !setAPI {
				return usageError("nothing to change: give --instance or --api-url")
			}
			if setAPI {
				p.APIURL = ""
				if strings.TrimSpace(a.apiURL) != "" {
					if p.APIURL, err = config.ParseAPIBase(a.apiURL); err != nil {
						return usageError("%v", err)
					}
				}
			}
			switch {
			case setInstance:
				p.InstanceID = strings.TrimSpace(a.instance)
			case !exists:
				// The origin this profile is for: an --api-url given here takes the
				// flag's place, as it would for any command; otherwise the
				// environment, then the default.
				explicit := ""
				if setAPI {
					explicit = p.APIURL
				}
				base, _, err := config.APIBase(explicit, p.APIURL)
				if err != nil {
					return usageError("%v", err)
				}
				st, err := a.store()
				if err != nil {
					return err
				}
				cur, err := st.Current(base)
				if err != nil {
					return err
				}
				if cur == "" {
					return usageError("give --instance ins_…: you have not signed in to an instance on %s", base)
				}
				p.InstanceID = cur
			}
			if err := profile.Check(name, p); err != nil {
				return usageError("%v", err)
			}
			set.Profiles[name] = p
			if err := set.Save(dir); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{
					"name": name, "instance_id": nilIfEmpty(p.InstanceID), "api_url": nilIfEmpty(p.APIURL),
					"default": set.Default == name,
				})
			}
			verb := "Created"
			if exists {
				verb = "Updated"
			}
			api := p.APIURL
			if api == "" {
				api = "not set"
			}
			a.printf("%s %s: instance %s, API URL %s.\n", a.out.Good(verb+" profile"), a.out.ID(name), a.out.ID(orDash(p.InstanceID)), api)
			if set.Default != name {
				a.printf("Use it with --profile %s, or make it the default with `clerk-protect profile use %s`.\n", name, name)
			}
			return nil
		},
	}
}

func (a *app) profileUseCmd() *cobra.Command {
	var clear bool
	cmd := &cobra.Command{
		Use:   "use NAME",
		Short: "Make a profile the default",
		Long: "Commands use the default profile when neither --profile nor " + profile.EnvProfile + " names one. " +
			"--clear removes the default, so commands use the instance you signed in to last.",
		Args: func(_ *cobra.Command, args []string) error {
			switch {
			case clear && len(args) > 0:
				return usageError("give a profile name or --clear, not both")
			case !clear && len(args) != 1:
				return usageError("expected a profile name, or --clear")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			set, dir, err := a.profiles()
			if err != nil {
				return err
			}
			if clear {
				set.Default = ""
			} else {
				if _, ok := set.Profiles[args[0]]; !ok {
					return usageError("there is no profile named %q; `clerk-protect profile list` shows the profiles on this computer", args[0])
				}
				set.Default = args[0]
			}
			if err := set.Save(dir); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"default": nilIfEmpty(set.Default)})
			}
			if clear {
				a.printf("No default profile. Commands use the instance you signed in to last.\n")
			} else {
				a.printf("Commands now use profile %s (instance %s) unless --profile or --instance says otherwise.\n",
					a.out.ID(set.Default), a.out.ID(orDash(set.Profiles[set.Default].InstanceID)))
			}
			if env := strings.TrimSpace(os.Getenv(profile.EnvProfile)); env != "" {
				a.notef("%s %s=%s is set here, and wins over the default.\n", a.errp.Warn("Note:"), profile.EnvProfile, env)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&clear, "clear", false, "Remove the default profile")
	return cmd
}

func (a *app) profileDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a profile (your sign-ins are kept)",
		Args:  exactArgs(1, "a profile name"),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			set, dir, err := a.profiles()
			if err != nil {
				return err
			}
			if _, ok := set.Profiles[name]; !ok {
				return usageError("there is no profile named %q", name)
			}
			delete(set.Profiles, name)
			wasDefault := set.Default == name
			if wasDefault {
				set.Default = ""
			}
			if err := set.Save(dir); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"deleted": name, "default": nilIfEmpty(set.Default)})
			}
			a.printf("%s %s.\n", a.out.Good("Deleted profile"), a.out.ID(name))
			if wasDefault {
				a.printf("It was the default; commands now use the instance you signed in to last.\n")
			}
			return nil
		},
	}
}

// noteSelectionMismatch says so when the instance just approved in the browser
// is not the one a profile or --instance selects. The browser decides which
// instance a sign-in is for. The profile is left as it was, and commands using
// it keep acting on its own instance — failing until that instance has a
// sign-in, rather than quietly moving to this one.
func (a *app) noteSelectionMismatch(sel *selection, approved string) {
	if sel.Instance == "" || sel.Instance == approved || sel.InstanceSource == instanceFromCurrent {
		return
	}
	if sel.InstanceSource == instanceFromProfile {
		a.notef("%s profile %s uses %s, not %s. Commands with that profile keep acting on %s, and need a sign-in "+
			"for it: open Protect Labs for %s from the Clerk Dashboard, then run `clerk-protect login` again. To use "+
			"%s with the profile instead: clerk-protect profile set %s --instance %s\n",
			a.errp.Warn("Note:"), sel.Profile, sel.Instance, approved, sel.Instance, sel.Instance, approved, sel.Profile, approved)
		return
	}
	a.notef("%s you approved %s, not %s (--instance). The browser decides which instance you sign in to: open "+
		"Protect Labs for %s from the Clerk Dashboard, then run `clerk-protect login` again.\n",
		a.errp.Warn("Note:"), approved, sel.Instance, sel.Instance)
}
