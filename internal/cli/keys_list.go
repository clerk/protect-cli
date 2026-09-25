package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/dpop"
)

// cliGrant is one computer signed in to the CLI as you, as the server lists it.
type cliGrant struct {
	GrantID       string `json:"grant_id"`
	KeyThumbprint string `json:"key_thumbprint"`
	Device        string `json:"device"`
	ClientName    string `json:"client_name"`
	ClientVersion string `json:"client_version"`
	ApprovedAt    string `json:"approved_at"`
	ExpiresAt     string `json:"expires_at"`
	ThisDevice    bool   `json:"this_device"`
}

// keysListCmd lists the computers signed in to the CLI as you in this
// instance. A view: a sign-in ends when its authorization does, and `logout`
// ends this computer's sooner.
func (a *app) keysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the computers signed in to the CLI as you, and when each sign-in ends",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, err := a.client()
			if err != nil {
				return err
			}
			if a.jsonOut {
				var raw json.RawMessage
				if err := client.JSON(ctxOf(cmd), http.MethodGet, api.Path("cli", "grants"), nil, nil, &raw); err != nil {
					return err
				}
				return a.printRaw(raw)
			}
			var list struct {
				Grants []cliGrant `json:"grants"`
			}
			if err := client.JSON(ctxOf(cmd), http.MethodGet, api.Path("cli", "grants"), nil, nil, &list); err != nil {
				return err
			}
			if len(list.Grants) == 0 {
				a.printf("No computer is signed in as you.\n")
				return nil
			}
			tw := a.table()
			tw.Header("", "COMPUTER", "ENDS", "FINGERPRINT", "CLIENT", "APPROVED")
			tw.Style(0, a.out.Good)
			tw.Style(3, a.out.Emphasis)
			for _, g := range list.Grants {
				marker := ""
				if g.ThisDevice {
					marker = "*"
				}
				device := g.Device
				if device == "" {
					device = "(unnamed)"
				}
				tw.Row(marker, device, until(a.now(), g.ExpiresAt), dpop.Fingerprint(g.KeyThumbprint),
					orDash(strings.TrimSpace(g.ClientName+" "+g.ClientVersion)), g.ApprovedAt)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			a.notef("%s\n", a.errp.Muted("Computer names are what each CLI reported; * is this computer. "+
				"A sign-in ends on its own, and `clerk-protect logout` ends this one now."))
			return nil
		},
	}
}

// until renders an RFC 3339 time as how long from now, to the minute.
func until(now time.Time, value string) string {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	d := t.Sub(now).Round(time.Minute)
	switch {
	case d <= 0:
		return "ended"
	case d < time.Hour:
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("in %dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}
