package cli

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
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

// consoleOpenCmd opens the console and nothing more.
//
// It cannot sign the browser in, by design: the browser's session is started
// only from the Clerk Dashboard, and a credential bound to this computer's key
// is never turned into a browser session, which could be copied off it. So the
// page shows whichever instance the browser is signed in to, and this command
// says which instance it names, so a difference is visible rather than silent.
func (a *app) consoleOpenCmd() *cobra.Command {
	var path string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "open",
		Short: "Open Protect Labs in your browser",
		Long: "Opens Protect Labs in your browser, at --path when given (for example /rules or /trace). Nothing is " +
			"sent to the server, and this computer's sign-in is not used.\n\n" +
			"Your browser has its own Protect Labs sign-in, for the instance you last opened Protect Labs for from " +
			"the Clerk Dashboard, and the page shows that instance. If it is not the instance you want, open " +
			"Protect Labs for that instance from the Clerk Dashboard.",
		Args: noArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			sel, err := a.selection()
			if err != nil {
				return err
			}
			target, err := consoleURL(sel.Base, path)
			if err != nil {
				return err
			}
			var openErr error
			if !noBrowser {
				openErr = a.openBrowser(target)
			}
			if a.jsonOut {
				if err := a.printJSON(map[string]any{
					"url": target, "instance_id": nilIfEmpty(sel.Instance), "opened": !noBrowser && openErr == nil,
				}); err != nil {
					return err
				}
			} else {
				a.printf("%s\n", a.out.Emphasis(target))
			}
			if sel.Instance != "" {
				a.notef("The page shows the instance your browser is signed in to. This command names %s; if the "+
					"page shows another, open Protect Labs for %s from the Clerk Dashboard.\n",
					sel.describe(sel.Instance, sel.InstanceSource, ""), sel.Instance)
			}
			if openErr != nil {
				return fmt.Errorf("could not open a browser (%w); open the address above", openErr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Page to open, for example /rules or /trace")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the address instead of opening a browser")
	return cmd
}
