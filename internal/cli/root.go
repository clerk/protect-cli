// Package cli is the clerk-protect command tree.
//
// Written for people and for scripts alike: every command takes --json for
// stable machine output, no command prompts when stdin is not a terminal, and
// the exit code says what kind of failure happened.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/profile"
	"github.com/clerk/protect-cli/internal/textsafe"
	"github.com/clerk/protect-cli/internal/version"
)

// Exit codes. A contract with every script that runs this binary: add codes,
// never renumber them.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
	// ExitAuth means only `clerk-protect login` can fix it.
	ExitAuth = 3
)

type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	jsonOut  bool
	instance string
	apiURL   string
	profile  string
	yes      bool

	// sel is what commands act on, once a command has asked (see selection).
	sel *selection

	// Hooks, replaced in tests.
	openBrowser func(string) error
	isTerminal  func() bool
	now         func() time.Time
	// traceTTY is the terminal the interactive trace view reads keys from and
	// draws on.
	traceTTY func() (in, out *os.File)
}

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return run(args, stdin, stdout, stderr, stdinIsTerminal)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, isTerminal func() bool) int {
	return newApp(stdin, stdout, stderr, isTerminal).execute(args)
}

func newApp(stdin io.Reader, stdout, stderr io.Writer, isTerminal func() bool) *app {
	auth.UserAgent = fmt.Sprintf("clerk-protect/%s (%s/%s)", version.Version, runtime.GOOS, runtime.GOARCH)
	return &app{
		stdin: stdin, stdout: stdout, stderr: stderr,
		openBrowser: auth.OpenBrowser, isTerminal: isTerminal, now: time.Now,
		traceTTY: func() (*os.File, *os.File) { return os.Stdin, os.Stdout },
	}
}

// execute runs one command line and returns its exit code.
func (a *app) execute(args []string) int {
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, errCancelled) {
		_, _ = fmt.Fprintln(a.stderr, "Cancelled.")
		return ExitError
	}
	// An error can carry the server's words; they reach a terminal only stripped.
	_, _ = fmt.Fprintf(a.stderr, "Error: %s\n", textsafe.Strip(err.Error()))
	return codeFor(err)
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageError(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

var errCancelled = errors.New("cancelled")

func codeFor(err error) int {
	if errors.Is(err, auth.ErrLoginRequired) || errors.Is(err, auth.ErrAccessDenied) {
		return ExitAuth
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	// cobra's own argument and command errors carry no type.
	msg := err.Error()
	if strings.HasPrefix(msg, "unknown command") || strings.HasPrefix(msg, "unknown flag") ||
		strings.HasPrefix(msg, "unknown shorthand flag") || strings.Contains(msg, "required flag") {
		return ExitUsage
	}
	return ExitError
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "clerk-protect",
		Short:         "Manage Clerk Protect for your instance from the command line",
		Version:       version.Version,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			// Set here, after flag parsing, so a runtime error does not print the
			// usage text while a flag mistake still does.
			cmd.SilenceUsage = true
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &exitError{code: ExitUsage, err: err}
	})
	pf := root.PersistentFlags()
	pf.BoolVar(&a.jsonOut, "json", false, "Print machine-readable JSON")
	pf.StringVar(&a.instance, "instance", "", "Instance to act on (default: the profile's instance, else the one you signed in to last)")
	pf.StringVar(&a.profile, "profile", "", "Profile to use (default: "+profile.EnvProfile+", else the default profile)")
	pf.StringVar(&a.apiURL, "api-url", "", "API origin (default "+config.DefaultAPIBase+"; also "+config.EnvAPIURL+", or the profile's)")
	pf.BoolVarP(&a.yes, "yes", "y", false, "Confirm changes without prompting (required when not running interactively)")

	root.AddCommand(
		a.loginCmd(),
		a.logoutCmd(),
		a.whoamiCmd(),
		a.keysCmd(),
		a.profileCmd(),
		a.rulesCmd(),
		a.rulesetsCmd(),
		a.schemaCmd(),
		a.fieldsCmd(),
		a.protectionsCmd(),
		a.insightsCmd(),
		a.traceCmd(),
		a.consoleCmd(),
		a.matchesCmd(),
		a.replayCmd(),
	)
	return root
}

// noArgs and exactArgs report argument mistakes as usage errors.
func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageError("unexpected argument %q", args[0])
	}
	return nil
}

func exactArgs(n int, names string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != n {
			return usageError("expected %s", names)
		}
		return nil
	}
}
