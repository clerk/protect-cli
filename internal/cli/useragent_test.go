package cli

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/version"
)

// The server reads the User-Agent's version to tell a CLI a newer release
// exists, so EVERY request carries the exact version the binary was built as —
// renewals and API calls alike — in one parseable shape.
func TestUserAgent_everyRequestNamesTheExactVersion(t *testing.T) {
	was := version.Version
	version.Version = "v9.8.7-rc.1"
	t.Cleanup(func() { version.Version = was })
	want := "clerk-protect/v9.8.7-rc.1 (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
	if got := version.UserAgent(); got != want {
		t.Fatalf("UserAgent() = %q, want %q", got, want)
	}

	f := newFakeAPI(t)
	f.signIn(t)
	// Past half its hour, so the first command renews it before calling the API.
	f.storeCredential(t, instanceA, "tok", 40*time.Minute, 20*time.Minute, true)

	if code, _, errOut := f.run(t, "whoami", "--json"); code != ExitOK {
		t.Fatalf("whoami: %s", errOut)
	}
	if code, _, errOut := f.run(t, "rules", "list", "--ruleset", "SIGN_IN", "--json"); code != ExitOK {
		t.Fatalf("rules list: %s", errOut)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	renewed := false
	for i, call := range f.calls {
		if f.agents[i] != want {
			t.Errorf("%s carried User-Agent %q, want %q", call, f.agents[i], want)
		}
		renewed = renewed || strings.HasSuffix(call, "/labs/api/cli/renew")
	}
	if !renewed {
		t.Fatal("no renewal was made, so its User-Agent went unchecked")
	}
}
