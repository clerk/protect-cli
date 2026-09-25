package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/clerk/protect-cli/internal/profile"
)

// runWithBrowser runs a command with the browser replaced by open, and without
// the --api-url f.run adds.
func (f *fakeAPI) runWithBrowser(t *testing.T, open func(string) error, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(""), &out, &errOut, func() bool { return false })
	a.openBrowser = open
	return a.execute(args), out.String(), errOut.String()
}

// consoleOpenArgs is `console open` followed by args. The command is spelled as
// one string on purpose: scripts/ci-changed reads a quoted top-level directory
// name followed by another quoted word — the shape of a path joined from its
// segments — as a path this module reads from the repository, and these are
// command words, not a path.
func consoleOpenArgs(args ...string) []string {
	return append(strings.Fields("console open"), args...)
}

// consoleLinkRoute answers POST /labs/api/cli/console-link as the server does:
// a one-time link on the console's own origin, returning to the page asked for.
func (f *fakeAPI) consoleLinkRoute(t *testing.T) *[]string {
	t.Helper()
	var asked []string
	f.mux.HandleFunc("POST /labs/api/cli/console-link", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ReturnTo string `json:"return_to"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, body.ReturnTo)
		f.json(w, 200, `{"login_url":"`+f.srv.URL+`/labs/auth/callback?code=one-time-secret","expires_at":"2030-01-01T00:00:00Z"}`)
	})
	return &asked
}

// Signed in, console open asks for a one-time sign-in link for the page and
// opens THAT — and never prints it: it is a credential for a minute, and a
// terminal's scrollback is not the place for one.
func TestConsoleOpen_signsTheBrowserInAndNeverPrintsTheLink(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	asked := f.consoleLinkRoute(t)
	var opened []string
	browser := func(u string) error { opened = append(opened, u); return nil }

	code, out, errOut := f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL, "--path", "/rules")...)
	if code != ExitOK || len(opened) != 1 || !strings.HasPrefix(opened[0], f.srv.URL+"/labs/auth/callback?code=") {
		t.Fatalf("code %d opened %v err %s", code, opened, errOut)
	}
	if len(*asked) != 1 || (*asked)[0] != "/rules" {
		t.Fatalf("asked to return to %v, want /rules", *asked)
	}
	if strings.Contains(out+errOut, "one-time-secret") {
		t.Fatalf("the sign-in link was printed: out %q err %q", out, errOut)
	}
	if !strings.Contains(out, "signed in to "+instanceA) {
		t.Fatalf("did not say it signed in: %s", out)
	}

	// --json reports it, without the link.
	opened = nil
	code, out, _ = f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL, "--json")...)
	var got map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &got) != nil || got["signed_in"] != true || strings.Contains(out, "one-time-secret") {
		t.Fatalf("--json: code %d out %s", code, out)
	}
}

// --no-browser and --no-sign-in open (or print) the page itself and ask the
// server for nothing.
func TestConsoleOpen_withoutSigningIn(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	asked := f.consoleLinkRoute(t)
	var opened []string
	browser := func(u string) error { opened = append(opened, u); return nil }

	code, out, errOut := f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL, "--no-sign-in", "--path", "/trace")...)
	if code != ExitOK || len(opened) != 1 || opened[0] != f.srv.URL+"/trace" || !strings.Contains(errOut, "Not signed in (--no-sign-in)") {
		t.Fatalf("--no-sign-in: code %d opened %v out %s err %s", code, opened, out, errOut)
	}

	opened = nil
	code, out, _ = f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL, "--no-browser", "--json")...)
	var got map[string]any
	if code != ExitOK || len(opened) != 0 || json.Unmarshal([]byte(out), &got) != nil || got["url"] != f.srv.URL+"/" ||
		got["opened"] != false || got["signed_in"] != false {
		t.Fatalf("--no-browser --json: code %d opened %v out %s", code, opened, out)
	}
	if len(*asked) != 0 {
		t.Fatalf("asked the server for a sign-in link: %v", *asked)
	}
}

// A server that predates the route, or a computer with no sign-in, still opens
// the page — unsigned-in, and saying so.
func TestConsoleOpen_fallsBackToThePage(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t) // no console-link route mounted: the fake answers 404
	var opened []string
	code, _, errOut := f.runWithBrowser(t, func(u string) error { opened = append(opened, u); return nil },
		consoleOpenArgs("--api-url", f.srv.URL)...)
	if code != ExitOK || len(opened) != 1 || opened[0] != f.srv.URL+"/" || !strings.Contains(errOut, "cannot sign a browser in yet") {
		t.Fatalf("older server: code %d opened %v err %s", code, opened, errOut)
	}
}

// The page is on the origin commands would use: a profile's API URL decides it,
// as it decides where requests go.
func TestConsoleOpen_followsTheProfile(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	const origin = "http://127.0.0.1:1"
	f.writeProfiles(t, &profile.Set{Profiles: map[string]profile.Profile{"lab": {InstanceID: "ins_9zzz", APIURL: origin}}})
	var opened []string
	code, _, errOut := f.runWithBrowser(t, func(u string) error { opened = append(opened, u); return nil },
		consoleOpenArgs("--profile", "lab", "--path", "/trace")...)
	if code != ExitOK || len(opened) != 1 || opened[0] != origin+"/trace" {
		t.Fatalf("code %d opened %v err %s", code, opened, errOut)
	}
	if !strings.Contains(errOut, "ins_9zzz (from profile lab)") {
		t.Fatalf("did not name the profile's instance: %s", errOut)
	}
}

// Only a page on the console is opened: nothing with a query, a fragment, a dot
// segment, another origin or a scheme reaches the browser.
func TestConsoleOpen_refusesAnythingButAPage(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	for _, path := range []string{
		"rules", "/rules?next=https://evil.example", "/rules#top", "/../x", "//evil.example", "/a b",
		"https://evil.example/", "/rules/./x",
	} {
		called := false
		code, _, errOut := f.runWithBrowser(t, func(string) error { called = true; return nil },
			consoleOpenArgs("--api-url", f.srv.URL, "--path", path)...)
		if code != ExitUsage || called {
			t.Errorf("--path %q: code %d, browser opened %v, err %s", path, code, called, errOut)
		}
	}
}

// A browser that cannot be opened still leaves the address to open by hand, and
// the command says it failed.
func TestConsoleOpen_reportsABrowserThatDidNotOpen(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	code, out, errOut := f.runWithBrowser(t, func(string) error { return errors.New("no display") },
		consoleOpenArgs("--api-url", f.srv.URL)...)
	if code != ExitError || !strings.Contains(out, f.srv.URL+"/") || !strings.Contains(errOut, "could not open a browser") {
		t.Fatalf("code %d out %s err %s", code, out, errOut)
	}
}
