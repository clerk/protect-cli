package cli

import (
	"bytes"
	"encoding/json"
	"errors"
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

// console open opens a page on the API origin — the console's — names the
// instance the command would act on, and sends nothing: the browser signs in on
// its own, and this computer's credential never becomes a browser session.
func TestConsoleOpen_opensThePageAndSendsNothing(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	before := f.callCount()
	var opened []string
	browser := func(u string) error { opened = append(opened, u); return nil }

	code, out, errOut := f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL, "--path", "/rules")...)
	if code != ExitOK || len(opened) != 1 || opened[0] != f.srv.URL+"/rules" {
		t.Fatalf("code %d opened %v err %s", code, opened, errOut)
	}
	if !strings.Contains(out, f.srv.URL+"/rules") || !strings.Contains(errOut, instanceA+" (from last sign-in)") {
		t.Fatalf("did not print the address and name the instance: out %s err %s", out, errOut)
	}

	opened = nil
	if code, _, _ := f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL)...); code != ExitOK || len(opened) != 1 || opened[0] != f.srv.URL+"/" {
		t.Fatalf("no --path: code %d opened %v", code, opened)
	}

	opened = nil
	code, out, _ = f.runWithBrowser(t, browser, consoleOpenArgs("--api-url", f.srv.URL, "--no-browser", "--json")...)
	var got map[string]any
	if code != ExitOK || len(opened) != 0 || json.Unmarshal([]byte(out), &got) != nil || got["url"] != f.srv.URL+"/" || got["opened"] != false {
		t.Fatalf("--no-browser --json: code %d opened %v out %s", code, opened, out)
	}

	if f.callCount() != before {
		t.Fatalf("console open sent %d requests", f.callCount()-before)
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
