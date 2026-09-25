package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestKeysList_showsEachComputerWithItsFingerprintAndEnd(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	ends := time.Now().Add(7*time.Hour + 30*time.Minute + 20*time.Second).UTC().Format(time.RFC3339)
	body := `{"grants":[` +
		`{"grant_id":"cli_a","key_thumbprint":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs","device":"laptop",` +
		`"client_name":"clerk-protect","client_version":"v0.3.2","approved_at":"2026-09-22T10:00:00Z",` +
		`"expires_at":"` + ends + `","this_device":true},` +
		`{"grant_id":"cli_b","key_thumbprint":"abcdEFGHijkl","device":"",` +
		`"client_name":"","client_version":"","approved_at":"2026-09-22T09:00:00Z",` +
		`"expires_at":"2026-09-22T09:30:00Z","this_device":false}]}`
	f.mux.HandleFunc("GET /labs/api/cli/grants", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	code, out, errOut := f.run(t, "keys", "list")
	if code != ExitOK {
		t.Fatalf("keys list: code %d err %s", code, errOut)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "FINGERPRINT") {
		t.Fatalf("want a header and two rows:\n%s", out)
	}
	for _, want := range []string{"*", "laptop", "in 7h30m", "NzbL-sXh8", "clerk-protect v0.3.2"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("this computer's row lacks %q: %q", want, lines[1])
		}
	}
	for _, want := range []string{"(unnamed)", "ended", "abcd-EFGH", "-"} {
		if !strings.Contains(lines[2], want) {
			t.Errorf("the other row lacks %q: %q", want, lines[2])
		}
	}
	if strings.HasPrefix(strings.TrimSpace(lines[2]), "*") {
		t.Errorf("another computer is marked as this one: %q", lines[2])
	}

	// --json is the server's list as sent.
	code, out, _ = f.run(t, "keys", "list", "--json")
	if code != ExitOK || !strings.Contains(out, `"this_device": true`) || !strings.Contains(out, `"grant_id": "cli_b"`) {
		t.Fatalf("keys list --json: code %d out %s", code, out)
	}
}

func TestKeysList_noComputerSaysSo(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.mux.HandleFunc("GET /labs/api/cli/grants", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"grants":[]}`))
	})
	if code, out, _ := f.run(t, "keys", "list"); code != ExitOK || !strings.Contains(out, "No computer is signed in") {
		t.Fatalf("code %d out %q", code, out)
	}
}
