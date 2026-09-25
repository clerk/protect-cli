package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/httperr"
)

// consolePathRe is the shape of a page on the console: a site-relative path of
// letters, digits, '/', '_' and '-' — no query, no fragment, no dot segment.
// The same shape the server accepts for a page to return to after signing in.
var consolePathRe = regexp.MustCompile(`^/[A-Za-z0-9/_-]*$`)

// consoleURL is a page on the console, which is served from the API origin.
func consoleURL(base, path string) (string, error) {
	if path == "" {
		path = "/"
	}
	if !consolePathRe.MatchString(path) || strings.HasPrefix(path, "//") {
		return "", usageError("--path %q: give a page on the console, like /rules or /trace", path)
	}
	u, err := url.Parse(base + path)
	if err != nil {
		return "", usageError("--path %q: %v", path, err)
	}
	return u.String(), nil
}

func (a *app) consoleCmd() *cobra.Command {
	console := &cobra.Command{Use: "console", Short: "Protect Labs in your browser"}
	console.AddCommand(a.consoleOpenCmd())
	return console
}

// consoleOpenCmd opens the console, signed in as this computer's sign-in.
//
// With a sign-in for the selected instance it asks the server for a one-time
// sign-in link and opens that, so the browser lands in Protect Labs as you, on
// that instance. The link is opened, never printed: it is a credential for about
// a minute, and a terminal's scrollback and logs are not the place for one. The
// browser session it starts is yours alone (never an operator's), ends when this
// computer's sign-in would, and cannot approve another computer's sign-in.
//
// Without a sign-in — or against a server that cannot mint one — it opens the
// console unsigned-in, as it always did, and says so.
func (a *app) consoleOpenCmd() *cobra.Command {
	var path string
	var noBrowser, noSignIn bool
	cmd := &cobra.Command{
		Use:   "open",
		Short: "Open Protect Labs in your browser, signed in",
		Long: "Opens Protect Labs in your browser at --path when given (for example /rules or /cli), signed in as " +
			"this computer's sign-in for the selected instance. The browser session ends when this computer's " +
			"sign-in would, and cannot approve a new command-line sign-in — do that from the Clerk Dashboard.\n\n" +
			"With --no-sign-in, or when this computer is not signed in, the page opens without signing in and " +
			"shows whichever instance your browser is already signed in to. --no-browser prints the page's address " +
			"without signing in: a sign-in link is only ever opened, never printed.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sel, err := a.selection()
			if err != nil {
				return err
			}
			target, err := consoleURL(sel.Base, path)
			if err != nil {
				return err
			}
			returnTo := path
			if returnTo == "" {
				returnTo = "/"
			}

			signedIn := false
			open := target
			why := ""
			switch {
			case noBrowser:
				why = "--no-browser prints the address only; a sign-in link is only ever opened"
			case noSignIn:
				why = "--no-sign-in"
			default:
				link, reason := a.consoleSignInLink(cmd, returnTo)
				if link != "" {
					open, signedIn = link, true
				} else {
					why = reason
				}
			}

			var openErr error
			if !noBrowser {
				openErr = a.openBrowser(open)
			}
			if a.jsonOut {
				if err := a.printJSON(map[string]any{
					"url": target, "instance_id": nilIfEmpty(sel.Instance), "signed_in": signedIn,
					"opened": !noBrowser && openErr == nil,
				}); err != nil {
					return err
				}
			} else if signedIn {
				a.printf("%s %s, signed in to %s.\n", a.out.Good("Opened"), a.out.Emphasis(target), a.out.ID(sel.Instance))
			} else {
				a.printf("%s\n", a.out.Emphasis(target))
			}
			if !signedIn && !a.jsonOut && sel.Instance != "" {
				a.notef("Not signed in (%s): the page shows the instance your browser is signed in to, which may "+
					"not be %s.\n", why, sel.describe(sel.Instance, sel.InstanceSource, ""))
			}
			if openErr != nil {
				return fmt.Errorf("could not open a browser (%w); open the address above", openErr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Page to open, for example /rules or /cli")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the address instead of opening a browser (not signed in)")
	cmd.Flags().BoolVar(&noSignIn, "no-sign-in", false, "Open the page without signing the browser in")
	return cmd
}

// consoleSignInLink asks the server for a one-time console sign-in link. It
// returns the link, or "" and the reason there is none — no sign-in on this
// computer, a server that cannot mint one, or its refusal — which the caller
// reports rather than fails on, because the page can still open.
func (a *app) consoleSignInLink(cmd *cobra.Command, returnTo string) (string, string) {
	c, _, err := a.client()
	if err != nil {
		return "", "this computer has no sign-in for it — run `clerk-protect login`"
	}
	var out struct {
		LoginURL string `json:"login_url"`
	}
	if err := c.JSON(ctxOf(cmd), http.MethodPost, api.Path("cli", "console-link"), nil,
		map[string]string{"return_to": returnTo}, &out); err != nil {
		var he *httperr.Error
		if errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusMethodNotAllowed) {
			return "", "this server cannot sign a browser in yet"
		}
		return "", "the server did not sign the browser in: " + err.Error()
	}
	// Only a link on the API origin is opened: the server builds it from its own
	// console origin, and a response is not a place to take a destination from on
	// trust.
	if !strings.HasPrefix(out.LoginURL, strings.TrimRight(c.Base, "/")+"/labs/auth/callback?") {
		return "", "the server's sign-in link was not for this console"
	}
	return out.LoginURL, ""
}
