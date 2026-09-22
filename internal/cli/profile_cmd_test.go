package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/profile"
)

// runBare runs a command without the --api-url every other run adds, so a
// profile's API URL, or the environment, decides the origin.
func (f *fakeAPI) runBare(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errOut, func() bool { return false })
	return code, out.String(), errOut.String()
}

func (f *fakeAPI) writeProfiles(t *testing.T, set *profile.Set) {
	t.Helper()
	if err := set.Save(f.dir); err != nil {
		t.Fatal(err)
	}
}

// clearProfileEnv keeps a profile selected in the shell running the tests out
// of them.
func clearProfileEnv(t *testing.T) {
	t.Helper()
	t.Setenv(profile.EnvProfile, "")
}

type whoamiJSON struct {
	Server struct {
		InstanceID string `json:"instance_id"`
	} `json:"server"`
	Profile *string `json:"profile"`
}

// whoami reports which instance's sign-in a request carried: the fake server
// answers /me with the instance of the token it was given.
func (f *fakeAPI) whoami(t *testing.T, args ...string) (instance, profileName string) {
	t.Helper()
	code, out, errOut := f.run(t, append(args, "whoami", "--json")...)
	if code != ExitOK {
		t.Fatalf("whoami %v: code %d err %s", args, code, errOut)
	}
	var w whoamiJSON
	if err := json.Unmarshal([]byte(out), &w); err != nil {
		t.Fatalf("whoami %v: %v: %s", args, err, out)
	}
	if w.Profile != nil {
		profileName = *w.Profile
	}
	return w.Server.InstanceID, profileName
}

// What a command acts on, first match wins: --instance; the selected profile's
// instance, where --profile beats CLERK_PROTECT_PROFILE beats the default
// profile; the instance signed in to last.
func TestProfiles_chooseTheInstanceAndFlagsStillWin(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t) // instance A, signed in to last
	const instanceB = "ins_2bbb"
	f.storeCredential(t, instanceB, "tok-b", 10*time.Minute, 50*time.Minute, false)

	check := func(label, wantInstance, wantProfile string, args ...string) {
		t.Helper()
		instance, name := f.whoami(t, args...)
		if instance != wantInstance || name != wantProfile {
			t.Errorf("%s: acted on %s with profile %q, want %s with %q", label, instance, name, wantInstance, wantProfile)
		}
	}

	check("no profiles", instanceA, "")
	f.writeProfiles(t, &profile.Set{Default: "b", Profiles: map[string]profile.Profile{
		"a": {InstanceID: instanceA}, "b": {InstanceID: instanceB},
	}})
	check("the default profile", instanceB, "b")
	check("--instance over the profile", instanceA, "b", "--instance", instanceA)
	t.Setenv(profile.EnvProfile, "a")
	check("the environment over the default", instanceA, "a")
	check("--profile over the environment", instanceB, "b", "--profile", "b")
	t.Setenv(profile.EnvProfile, "")

	if code, _, errOut := f.run(t, "profile", "use", "--clear"); code != ExitOK {
		t.Fatalf("profile use --clear: code %d err %s", code, errOut)
	}
	check("the default cleared", instanceA, "")
}

// A profile names an instance this computer has no sign-in for. A change with
// that profile fails and sends nothing — rather than landing on the instance
// signed in to last, which is signed in and would accept it.
func TestProfiles_anInstanceWithNoSignInFailsClosed(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.writeProfiles(t, &profile.Set{Default: "other", Profiles: map[string]profile.Profile{"other": {InstanceID: "ins_9zzz"}}})

	before := f.callCount()
	code, _, errOut := f.run(t, "rules", "delete", "r1", "--ruleset", "SIGN_IN", "--yes")
	if code != ExitAuth || !strings.Contains(errOut, "ins_9zzz") {
		t.Fatalf("code %d err %s; want exit 3 naming ins_9zzz", code, errOut)
	}
	if f.callCount() != before {
		t.Fatal("a request was sent for an instance with no sign-in")
	}
}

// The browser decides which instance a sign-in is for. Approving another
// instance than the default profile's keeps the sign-in and says so, and leaves
// the profile alone: commands with it still act on its own instance, and fail
// until that instance has a sign-in.
func TestProfiles_loginToAnotherInstanceLeavesTheProfileAlone(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	const approved = "ins_2bbb"
	f.mux.HandleFunc("POST /labs/cli/token", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		f.mu.Lock()
		f.tokens["tok-login"] = approved
		f.mu.Unlock()
		f.json(w, 200, mustJSON(auth.TokenResponse{
			AccessToken: "tok-login", TokenType: "DPoP", InstanceID: approved, Subject: "user_1", GrantID: "cli_grant",
			Scopes:                 []string{"protect:rules:read"},
			ExpiresAt:              now.Add(time.Hour).UTC().Format(time.RFC3339),
			AuthorizationExpiresAt: now.Add(8 * time.Hour).UTC().Format(time.RFC3339),
		}))
	})
	want := &profile.Set{Default: "work", Profiles: map[string]profile.Profile{"work": {InstanceID: "ins_9zzz"}}}
	f.writeProfiles(t, want)

	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(""), &out, &errOut, func() bool { return false })
	a.openBrowser = func(authorize string) error {
		u, err := url.Parse(authorize)
		if err != nil {
			return err
		}
		q := u.Query()
		go func() {
			resp, err := http.Get(q.Get("redirect_uri") + "?code=code-1&state=" + url.QueryEscape(q.Get("state")))
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	if code := a.execute([]string{"--api-url", f.srv.URL, "login"}); code != ExitOK {
		t.Fatalf("login: code %d out %s err %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "profile work uses ins_9zzz, not ins_2bbb") {
		t.Fatalf("login did not say the approved instance is not the profile's:\n%s", errOut.String())
	}

	got, err := profile.Load(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Default != "work" || len(got.Profiles) != 1 || got.Profiles["work"] != want.Profiles["work"] {
		t.Fatalf("login changed the profiles: %+v", got)
	}
	if cur, err := (auth.Store{Dir: f.dir}).Current(f.srv.URL); err != nil || cur != approved {
		t.Fatalf("instance signed in to last: %q (%v), want %s", cur, err, approved)
	}

	before := f.callCount()
	code, _, stderr := f.run(t, "rules", "list", "--ruleset", "SIGN_IN")
	if code != ExitAuth || !strings.Contains(stderr, "ins_9zzz") {
		t.Fatalf("rules list with the profile: code %d err %s; want exit 3 naming ins_9zzz", code, stderr)
	}
	if f.callCount() != before {
		t.Fatal("a request was sent for the profile's instance, which has no sign-in")
	}
}

// A sign-in is stored for one API host, so a profile's API URL chooses which
// deployment's sign-ins apply: pointed at another host, it finds none there and
// sends nothing to either server. The environment variable still wins over a
// profile's API URL.
func TestProfiles_anAPIURLSelectsThatHostsSignInsOnly(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(other.Close)
	f.writeProfiles(t, &profile.Set{Profiles: map[string]profile.Profile{
		"here":  {InstanceID: instanceA, APIURL: f.srv.URL},
		"there": {InstanceID: instanceA, APIURL: other.URL},
	}})

	code, out, errOut := f.runBare(t, "--profile", "here", "whoami", "--json")
	if code != ExitOK || !strings.Contains(out, `"api_url": "`+f.srv.URL+`"`) {
		t.Fatalf("profile here: code %d out %s err %s", code, out, errOut)
	}

	before := f.callCount()
	code, _, errOut = f.runBare(t, "--profile", "there", "whoami")
	if code != ExitAuth || !strings.Contains(errOut, instanceA) {
		t.Fatalf("profile there: code %d err %s; want exit 3, not signed in to %s", code, errOut, instanceA)
	}
	if f.callCount() != before || elsewhere.Load() != 0 {
		t.Fatalf("requests sent: %d to the signed-in host, %d to the other", f.callCount()-before, elsewhere.Load())
	}

	t.Setenv(config.EnvAPIURL, f.srv.URL)
	if code, _, errOut := f.runBare(t, "--profile", "there", "whoami"); code != ExitOK {
		t.Fatalf("%s did not win over the profile's API URL: code %d err %s", config.EnvAPIURL, code, errOut)
	}
}

// Profile commands change only this computer: they need no --yes and send
// nothing, and their mistakes exit 2.
func TestProfiles_commandsChangeOnlyThisComputer(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	t.Setenv(config.EnvAPIURL, f.srv.URL)
	before := f.callCount()

	// Right after signing in, a new profile takes that instance.
	if code, out, errOut := f.runBare(t, "profile", "set", "work"); code != ExitOK || !strings.Contains(out, instanceA) {
		t.Fatalf("profile set: code %d out %s err %s", code, out, errOut)
	}
	if code, _, errOut := f.runBare(t, "profile", "use", "work"); code != ExitOK {
		t.Fatalf("profile use: code %d err %s", code, errOut)
	}
	code, out, errOut := f.runBare(t, "profile", "show", "--json")
	var shown map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &shown) != nil {
		t.Fatalf("profile show: code %d out %s err %s", code, out, errOut)
	}
	if shown["profile"] != "work" || shown["instance_source"] != "profile" || shown["api_url_source"] != config.EnvAPIURL || shown["signed_in"] != true {
		t.Fatalf("profile show: %s", out)
	}
	if code, _, errOut := f.runBare(t, "profile", "set", "work", "--instance", "ins_9zzz"); code != ExitOK {
		t.Fatalf("profile set --instance: code %d err %s", code, errOut)
	}
	code, out, _ = f.runBare(t, "profile", "list", "--json")
	if code != ExitOK || !strings.Contains(out, `"instance_id": "ins_9zzz"`) || !strings.Contains(out, `"default": true`) {
		t.Fatalf("profile list: code %d out %s", code, out)
	}
	if code, out, _ := f.runBare(t, "profile", "delete", "work"); code != ExitOK || !strings.Contains(out, "It was the default") {
		t.Fatalf("profile delete: code %d out %s", code, out)
	}

	for _, args := range [][]string{
		{"profile", "set", "bad/name", "--instance", instanceA},
		{"profile", "set", "x", "--instance", "not-an-instance"},
		{"profile", "use", "nope"},
		{"profile", "use", "nope", "--clear"},
		{"profile", "delete", "nope"},
		{"--profile", "nope", "whoami"},
	} {
		if code, _, errOut := f.runBare(t, args...); code != ExitUsage {
			t.Errorf("%v: code %d err %s, want 2", args, code, errOut)
		}
	}
	if f.callCount() != before {
		t.Fatalf("profile commands sent %d requests", f.callCount()-before)
	}
}

// A damaged profiles file stops what acts on an instance, naming the file — it
// must not guess — and nothing else.
func TestProfiles_aDamagedFileStopsOnlyWhatActsOnAnInstance(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	if err := os.WriteFile(profile.Path(f.dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.callCount()
	code, _, errOut := f.run(t, "whoami")
	if code != ExitError || !strings.Contains(errOut, profile.Path(f.dir)) {
		t.Fatalf("whoami: code %d err %s; want exit 1 naming the profiles file", code, errOut)
	}
	if f.callCount() != before {
		t.Fatal("a request was sent despite a damaged profiles file")
	}
	for _, args := range [][]string{{"keys", "status"}, {"--help"}} {
		if code, _, errOut := f.run(t, args...); code != ExitOK {
			t.Errorf("%v: code %d err %s", args, code, errOut)
		}
	}
}

// A new profile given --api-url takes the instance signed in to last on THAT
// origin, even while CLERK_PROTECT_API_URL points the shell somewhere else: an
// origin named on the command line is the one meant, as it is for any command.
func TestProfiles_setTakesTheInstanceFromTheOriginItWasGiven(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	t.Setenv(config.EnvAPIURL, "http://127.0.0.1:1")
	code, out, errOut := f.runBare(t, "profile", "set", "work", "--api-url", f.srv.URL)
	if code != ExitOK || !strings.Contains(out, instanceA) {
		t.Fatalf("code %d out %s err %s; want the instance signed in to on %s", code, out, errOut, f.srv.URL)
	}
}

// profile show reports an instance with no sign-in as signed out — and anything
// a real command would fail on, an id that is not one or a credential that
// cannot be read, as the error it is.
func TestProfiles_showSurfacesWhatARealCommandWouldFailOn(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	code, out, errOut := f.run(t, "profile", "show", "--json", "--instance", "ins_9zzz")
	if code != ExitOK || !strings.Contains(out, `"signed_in": false`) {
		t.Fatalf("no sign-in: code %d out %s err %s", code, out, errOut)
	}
	if code, _, errOut := f.run(t, "profile", "show", "--instance", "../ins_2abc"); code == ExitOK {
		t.Fatalf("an id that is not one: code 0, err %s", errOut)
	}
	host := strings.ReplaceAll(strings.TrimPrefix(f.srv.URL, "http://"), ":", "_")
	if err := os.WriteFile(f.dir+"/credentials/"+host+"/"+instanceA+".json", []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := f.run(t, "profile", "show"); code == ExitOK || !strings.Contains(errOut, "unreadable") {
		t.Fatalf("an unreadable credential: code %d err %s", code, errOut)
	}
}
