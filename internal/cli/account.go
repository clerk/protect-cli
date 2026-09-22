package cli

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/keystore"
	"github.com/clerk/protect-cli/internal/version"
)

func (a *app) loginCmd() *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Approve this computer in your browser and sign in",
		Long: "Opens Protect Labs in your browser to approve this computer. Sign in to Protect Labs from " +
			"the Clerk Dashboard for the instance you want to use, then approve. The credential is bound " +
			"to a key on this computer that cannot be copied off it.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sel, err := a.selection()
			if err != nil {
				return err
			}
			base := sel.Base
			st, err := a.store()
			if err != nil {
				return err
			}
			dev, created, err := keystore.OpenOrCreate()
			if err != nil {
				return err
			}
			if created {
				a.notef("Created a device key: %s.\n", dev.Backend().Describe())
			}
			if dev.Backend().Extractable() {
				a.notef("Warning: this device key is a file. Anyone who can read it can use your credential.\n")
			}
			host, _ := os.Hostname()
			opener := a.openBrowser
			if noBrowser {
				opener = nil
			}
			creds, err := auth.Login(ctxOf(cmd), auth.LoginOptions{
				APIBase:       base,
				Key:           dev,
				ClientVersion: version.Version,
				DeviceName:    host,
				OpenBrowser:   opener,
				Out:           a.stderr,
			})
			if err != nil {
				return err
			}
			if err := st.Save(creds); err != nil {
				return err
			}
			// Signing in is the one act that chooses the instance later commands
			// act on without --instance. Renewing a token saves it but never this.
			if err := st.SetCurrent(base, creds.InstanceID); err != nil {
				return err
			}
			a.noteSelectionMismatch(sel, creds.InstanceID)
			if a.jsonOut {
				return a.printJSON(sessionView(base, creds, dev))
			}
			who := creds.Email
			if who == "" {
				who = creds.Subject
			}
			a.printf("Signed in to %s as %s.\n", creds.InstanceID, who)
			a.printf("Access renews automatically until %s; after that, run `clerk-protect login` again.\n",
				creds.AuthorizationExpiresAt.Local().Format(time.RFC1123))
			return nil
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the approval address instead of opening a browser")
	return cmd
}

type keyView struct {
	Backend     string `json:"backend"`
	Extractable bool   `json:"extractable"`
	Thumbprint  string `json:"thumbprint"`
	Fingerprint string `json:"fingerprint"`
	Protection  string `json:"protection,omitempty"`
}

type sessionJSON struct {
	APIURL                 string    `json:"api_url"`
	InstanceID             string    `json:"instance_id"`
	Subject                string    `json:"subject"`
	Email                  string    `json:"email,omitempty"`
	Scopes                 []string  `json:"scopes"`
	ExpiresAt              time.Time `json:"expires_at"`
	AuthorizationExpiresAt time.Time `json:"authorization_expires_at"`
	Key                    keyView   `json:"key"`
}

func sessionView(base string, c *auth.Credentials, dev keystore.Device) sessionJSON {
	return sessionJSON{
		APIURL: base, InstanceID: c.InstanceID, Subject: c.Subject, Email: c.Email, Scopes: c.Scopes,
		ExpiresAt: c.ExpiresAt, AuthorizationExpiresAt: c.AuthorizationExpiresAt,
		Key: keyView{
			Backend: string(dev.Backend()), Extractable: dev.Backend().Extractable(),
			Thumbprint: dev.Thumbprint(), Fingerprint: dpop.Fingerprint(dev.Thumbprint()), Protection: dev.Protection(),
		},
	}
}

func (a *app) logoutCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove a stored sign-in",
		Long: "Removes the stored sign-in for the current instance (or --instance). That changes only this " +
			"computer, so it does not ask for --yes. With --all, removes every stored sign-in and deletes this " +
			"computer's device key, which cannot be undone: it asks first, and when not running interactively " +
			"it needs --yes. A signed-out token cannot be used without the device key, and expires on its own " +
			"within the hour.",
		Args: noArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			st, err := a.store()
			if err != nil {
				return err
			}
			if all {
				if err := a.confirm("Remove every stored sign-in and delete this computer's device key"); err != nil {
					return err
				}
				if err := st.RemoveAll(); err != nil {
					return err
				}
				if err := keystore.Delete(); err != nil {
					return err
				}
				a.printf("Signed out everywhere and deleted the device key.\n")
				return nil
			}
			sel, err := a.selection()
			if err != nil {
				return err
			}
			removed, err := st.Remove(sel.Base, sel.Instance)
			if err != nil {
				return err
			}
			a.printf("Signed out of %s.\n", removed)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Remove every sign-in and delete the device key")
	return cmd
}

func (a *app) whoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show who you are signed in as, and what you may do",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, creds, err := a.client()
			if err != nil {
				return err
			}
			sel, err := a.selection()
			if err != nil {
				return err
			}
			var me map[string]any
			if err := client.JSON(ctxOf(cmd), http.MethodGet, api.Path("me"), nil, nil, &me); err != nil {
				return err
			}
			info, err := keystore.Status()
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{
					"api_url":                  client.Base,
					"profile":                  nilIfEmpty(sel.Profile),
					"server":                   me,
					"authorization_expires_at": creds.AuthorizationExpiresAt,
					"key": keyView{
						Backend: string(info.Backend), Extractable: info.Backend.Extractable(),
						Thumbprint: info.Thumbprint, Fingerprint: dpop.Fingerprint(info.Thumbprint), Protection: info.Protection,
					},
				})
			}
			str := func(k string) string { s, _ := me[k].(string); return s }
			var scopes []string
			if list, ok := me["scopes"].([]any); ok {
				for _, s := range list {
					if v, ok := s.(string); ok {
						scopes = append(scopes, v)
					}
				}
			}
			tw := a.table()
			row := func(k, v string) { _, _ = tw.Write([]byte(k + "\t" + v + "\n")) }
			row("Instance", str("instance_id"))
			if sel.Profile != "" {
				row("Profile", sel.Profile+" (from "+sel.ProfileSource+")")
			}
			row("Signed in as", strings.TrimSpace(str("email")+" ("+str("subject")+")"))
			row("Credential", str("credential"))
			row("Permissions", strings.Join(scopes, ", "))
			row("Token expires", str("expires_at"))
			row("Authorization expires", creds.AuthorizationExpiresAt.UTC().Format(time.RFC3339))
			row("Device key", string(info.Backend)+" (fingerprint "+dpop.Fingerprint(info.Thumbprint)+")")
			row("API", client.Base)
			return tw.Flush()
		},
	}
}

func (a *app) keysCmd() *cobra.Command {
	keys := &cobra.Command{Use: "keys", Short: "Inspect this computer's device key"}
	keys.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show where the device key lives and whether it can leave this computer",
		Args:  noArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info, err := keystore.Status()
			if errors.Is(err, keystore.ErrUnsupported) {
				return err
			}
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{
					"exists": info.Exists, "backend": info.Backend, "extractable": info.Backend.Extractable(),
					"thumbprint": info.Thumbprint, "fingerprint": dpop.Fingerprint(info.Thumbprint),
					"protection": info.Protection, "enforced": info.Enforced, "location": info.Location,
				})
			}
			if !info.Exists {
				a.printf("No device key on this computer. `clerk-protect login` creates one.\n")
				return nil
			}
			tw := a.table()
			row := func(k, v string) { _, _ = tw.Write([]byte(k + "\t" + v + "\n")) }
			row("Stored in", info.Backend.Describe())
			if info.Backend.Extractable() {
				row("Extractable", "YES")
			} else {
				row("Extractable", "no")
			}
			row("Fingerprint", dpop.Fingerprint(info.Thumbprint))
			row("Thumbprint", info.Thumbprint)
			if info.Protection != "" {
				row("Protection", info.Protection)
			}
			if info.Enforced != "" && info.Enforced != info.Protection {
				row("Enforced", info.Enforced)
			}
			row("Location", info.Location)
			return tw.Flush()
		},
	})
	return keys
}
