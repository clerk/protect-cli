package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/clerk/protect-cli/internal/api"
	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/keystore"
	"github.com/clerk/protect-cli/internal/profile"
	"github.com/clerk/protect-cli/internal/term"
	"github.com/clerk/protect-cli/internal/textsafe"
)

// selection is what a command acts on — the API origin and the instance — and
// where each came from.
type selection struct {
	Profile        string // "" when no profile applies
	ProfileSource  string
	Base           string
	BaseSource     string
	Instance       string // "" when nothing names one and nobody has signed in
	InstanceSource string
}

// Where an instance came from.
const (
	instanceFromFlag    = "--instance"
	instanceFromProfile = config.SourceProfile
	instanceFromCurrent = "last sign-in"
)

// selection resolves the profile, then the API origin and the instance, first
// match winning:
//
//	API origin  --api-url, CLERK_PROTECT_API_URL, the profile's, the default
//	instance    --instance, the profile's, the one signed in to last
//
// Resolved when a command first asks rather than before every command, so a
// damaged profiles file stops the commands that act on an instance — which
// must not guess — and not `help`, `keys status` or `logout --all`.
func (a *app) selection() (*selection, error) {
	if a.sel != nil {
		return a.sel, nil
	}
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	profiles, err := profile.Load(dir)
	if err != nil {
		return nil, err
	}
	name, source, err := profiles.Selected(a.profile)
	if err != nil {
		return nil, usageError("%v", err)
	}
	prof := profiles.Profiles[name] // the zero profile when none is selected
	sel := &selection{Profile: name, ProfileSource: source}
	sel.Base, sel.BaseSource, err = config.APIBase(a.apiURL, prof.APIURL)
	if err != nil {
		return nil, usageError("%v", err)
	}
	switch {
	case a.instance != "":
		sel.Instance, sel.InstanceSource = a.instance, instanceFromFlag
	case prof.InstanceID != "":
		sel.Instance, sel.InstanceSource = prof.InstanceID, instanceFromProfile
	default:
		cur, err := auth.Store{Dir: dir}.Current(sel.Base)
		if err != nil {
			return nil, err
		}
		sel.Instance, sel.InstanceSource = cur, instanceFromCurrent
	}
	a.sel = sel
	return sel, nil
}

// describe renders a resolved value with where it came from.
func (sel *selection) describe(value, source, none string) string {
	if value == "" {
		return none
	}
	if source == config.SourceProfile {
		source = "profile " + sel.Profile
	}
	return value + " (from " + source + ")"
}

func (a *app) store() (auth.Store, error) {
	dir, err := config.Dir()
	if err != nil {
		return auth.Store{}, err
	}
	return auth.Store{Dir: dir}, nil
}

// client builds a signed API client for the selected instance.
//
// The stored credential names the device key it was bound to. A token bound to
// a key this machine no longer holds would be refused on every request with a
// message about proofs; it is caught here and reported as what it is.
func (a *app) client() (*api.Client, *auth.Credentials, error) {
	sel, err := a.selection()
	if err != nil {
		return nil, nil, err
	}
	base := sel.Base
	st, err := a.store()
	if err != nil {
		return nil, nil, err
	}
	// A profile's instance with no sign-in is "not signed in to" that instance —
	// never a fall back to the one signed in to last.
	creds, err := st.Load(base, sel.Instance)
	if err != nil {
		return nil, nil, err
	}
	dev, err := keystore.Open()
	if errors.Is(err, keystore.ErrNoKey) {
		return nil, nil, auth.LoginRequired("this computer has no device key")
	}
	if err != nil {
		return nil, nil, err
	}
	if creds.KeyThumbprint != dev.Thumbprint() {
		return nil, nil, auth.LoginRequired("this computer's device key changed after you signed in")
	}
	proofs, err := dpop.NewBuilder(dev)
	if err != nil {
		return nil, nil, err
	}
	session := &auth.Session{Base: base, Store: st, Creds: creds, Proofs: proofs}
	return &api.Client{Base: base, Tokens: session, Proofs: proofs, UserAgent: auth.UserAgent}, creds, nil
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// printRaw re-indents a JSON response for display.
//
// With --json the server's JSON is printed as it came: JSON escapes its control
// characters, and a program reading it wants the values unchanged. Without
// --json the output is for a terminal and passes through textsafe.Strip — as
// does a body that is not JSON at all, which escapes nothing.
func (a *app) printRaw(raw []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, bytes.TrimSpace(raw), "", "  "); err != nil {
		_, err := io.WriteString(a.stdout, textsafe.Strip(string(raw)))
		return err
	}
	buf.WriteByte('\n')
	out := buf.String()
	if !a.jsonOut {
		out = textsafe.Strip(out)
	}
	_, err := io.WriteString(a.stdout, out)
	return err
}

// printf and notef write human output, and server text reaches both — rule
// expressions, protection names, error messages — so both strip terminal
// control sequences from what they write.
func (a *app) printf(format string, args ...any) {
	_, _ = io.WriteString(a.stdout, textsafe.Strip(fmt.Sprintf(format, args...)))
}

func (a *app) notef(format string, args ...any) {
	_, _ = io.WriteString(a.stderr, textsafe.Strip(fmt.Sprintf(format, args...)))
}

// table is a tabwriter that strips terminal control sequences from each write
// before aligning it, so a column is measured by what is shown.
type table struct{ *tabwriter.Writer }

func (t table) Write(p []byte) (int, error) {
	if _, err := t.Writer.Write([]byte(textsafe.Strip(string(p)))); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *app) table() table { return table{tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)} }

func stdinIsTerminal() bool { return term.IsTerminal(os.Stdin.Fd()) }

// requireConsent refuses a change before it sends anything, when nobody can be
// asked and --yes was not given. Every command that changes configuration calls
// it before its first request, so a script that forgot --yes reaches the server
// not at all — not even with the reads a confirmation would have shown.
func (a *app) requireConsent() error {
	if a.yes || a.isTerminal() {
		return nil
	}
	return usageError("this command changes your configuration — pass --yes to confirm when not running interactively")
}

// confirm asks before a change. With --yes it does not ask; with stdin not a
// terminal it refuses, because a prompt nobody can answer is a hang and a
// default of "yes" is a change nobody approved.
func (a *app) confirm(action string) error {
	if a.yes {
		return nil
	}
	if !a.isTerminal() {
		return usageError("%s — pass --yes to confirm when not running interactively", action)
	}
	a.notef("%s? [y/N]: ", action)
	line, _ := bufio.NewReader(a.stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errCancelled
}

// readJSONFile reads a JSON document from a path, or stdin for "-".
func (a *app) readJSONFile(path string) (json.RawMessage, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(a.stdin, 16<<20))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, usageError("%s is not valid JSON", path)
	}
	return json.RawMessage(bytes.TrimSpace(data)), nil
}

// jsonBody is a request body given as --query text or a --file, or an empty
// object when neither was.
func (a *app) jsonBody(query, file string) (map[string]any, error) {
	body := map[string]any{}
	switch {
	case query != "" && file != "":
		return nil, usageError("give --query or --file, not both")
	case query != "":
		if err := json.Unmarshal([]byte(query), &body); err != nil {
			return nil, usageError("--query is not a JSON object: %v", err)
		}
	case file != "":
		raw, err := a.readJSONFile(file)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, usageError("%s is not a JSON object: %v", file, err)
		}
	}
	if body == nil {
		body = map[string]any{}
	}
	return body, nil
}

// ctx is the command's context; cobra always sets one through ExecuteContext.
func ctxOf(c interface{ Context() context.Context }) context.Context {
	if ctx := c.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
