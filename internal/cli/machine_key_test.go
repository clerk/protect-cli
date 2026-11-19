package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/auth"
	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/machinekey"
)

// A machine key acts with no sign-in at all: an empty configuration directory,
// a key file, and the environment variable naming it. The server sees a proof
// from that key at the mint, then the minted token with a proof from the same
// key on the API call.
func TestMachineKey_actsAsTheKeyWithNoSignIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("key files are refused on Windows")
	}
	t.Setenv(config.EnvConfigDir, t.TempDir())
	t.Setenv(config.EnvAPIURL, "")
	clearProfileEnv(t)
	keyPath := filepath.Join(t.TempDir(), "ci.pem")
	key, err := machinekey.Generate(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var mints int
	var mintBodies []string
	var sessionJKT string // the target_jkt the latest mint proof named
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/labs/cli/machine-token":
			proof := r.Header.Get("DPoP")
			v, err := dpop.Verify(proof, r.Method, srv.URL+r.URL.Path, "", time.Minute)
			if err != nil || v.Thumbprint != key.Thumbprint {
				t.Errorf("mint proof: %v (thumb %s)", err, v.Thumbprint)
				w.WriteHeader(400)
				return
			}
			target := proofClaim(t, proof, "target_jkt")
			if target == "" || target == key.Thumbprint {
				t.Errorf("the mint proof named no separate session key: %q", target)
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			mints++
			mintBodies = append(mintBodies, string(body))
			sessionJKT = target
			mu.Unlock()
			now := time.Now()
			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: "mtok", TokenType: "DPoP", InstanceID: instanceA, Subject: "mk_2abc", GrantID: "mk_2abc",
				Scopes:                 []string{"protect:labs", "protect:rules:read"},
				ExpiresAt:              now.Add(5 * time.Minute).UTC().Format(time.RFC3339),
				AuthorizationExpiresAt: now.Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
			})
		case "/labs/api/me":
			v, err := dpop.Verify(r.Header.Get("DPoP"), r.Method, srv.URL+r.URL.Path, "mtok", time.Minute)
			mu.Lock()
			want := sessionJKT
			mu.Unlock()
			// Signed by the run's session key — the token's binding — and NOT by
			// the machine key, which signed only the mint.
			if r.Header.Get("Authorization") != "DPoP mtok" || err != nil || v.Thumbprint != want || v.Thumbprint == key.Thumbprint {
				t.Errorf("API call not signed by the session key: %q %v (thumb %s, want %s)", r.Header.Get("Authorization"), err, v.Thumbprint, want)
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"instance_id":"` + instanceA + `","subject":"mk_2abc","scopes":["protect:labs"],"credential":"device_token"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv(machinekey.EnvMachineKey, "file:"+keyPath)
	run := func(args ...string) (int, string, string) {
		var out, errOut strings.Builder
		code := run(append([]string{"--api-url", srv.URL}, args...), strings.NewReader(""), &out, &errOut, func() bool { return false })
		return code, out.String(), errOut.String()
	}
	code, out, errOut := run("machine-key", "test", "--json")
	if code != ExitOK || !strings.Contains(out, `"key_id": "mk_2abc"`) || !strings.Contains(out, `"instance_id": "`+instanceA+`"`) {
		t.Fatalf("machine-key test: code %d out %s err %s", code, out, errOut)
	}
	// With --instance, the instance is sent for the server to check.
	if code, _, errOut := run("--instance", instanceA, "whoami"); code != ExitOK {
		t.Fatalf("whoami as a machine: code %d err %s", code, errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	if mints != 2 {
		t.Fatalf("minted %d tokens over two runs, want one per run", mints)
	}
	if mintBodies[0] != "" || !strings.Contains(mintBodies[1], instanceA) {
		t.Fatalf("mint bodies %q: the first run named no instance, the second named --instance", mintBodies)
	}
}

// Registering proves possession of the machine key in a second proof, while
// the request itself is made as the person signed in.
func TestMachineKey_registerSendsAProofFromTheMachineKey(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	keyPath := filepath.Join(t.TempDir(), "ci.pem")
	key, err := machinekey.Generate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	f.mux.HandleFunc("POST /labs/api/cli/machine-keys", func(w http.ResponseWriter, r *http.Request) {
		v, err := dpop.Verify(r.Header.Get("Machine-Key-Proof"), r.Method, f.srv.URL+r.URL.Path, "", time.Minute)
		if err != nil || v.Thumbprint != key.Thumbprint {
			t.Errorf("machine key proof: %v", err)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		f.json(w, 201, `{"machine_key":{"key_id":"mk_2abc","name":"CI","state":"pending","key_thumbprint":"`+key.Thumbprint+
			`","requested_scopes":["protect:labs"]},"approval_url":"https://console.example/cli/#machine-keys"}`)
	})
	code, out, errOut := f.run(t, "machine-key", "register", "--key", keyPath, "--name", "CI", "--scope", "protect:labs")
	if code != ExitOK || !strings.Contains(out, "mk_2abc") || !strings.Contains(errOut, "approves it") {
		t.Fatalf("register: code %d out %s err %s", code, out, errOut)
	}
	if got["name"] != "CI" || got["key_backend"] != machinekey.BackendFile {
		t.Fatalf("register body = %v", got)
	}
}

func TestMachineKey_registerRefusesWhileActingAsAMachine(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	t.Setenv(machinekey.EnvMachineKey, "file:/nonexistent.pem")
	if code, _, errOut := f.run(t, "machine-key", "register", "--key", "/x.pem", "--name", "CI"); code != ExitUsage {
		t.Fatalf("code %d err %s, want a usage error", code, errOut)
	}
}

func TestMachineKey_createRequiresADestination(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"machine-key", "create"}, strings.NewReader(""), &out, &errOut, func() bool { return false }); code != ExitUsage {
		t.Fatalf("code %d err %s", code, errOut.String())
	}
}

// proofClaim reads one claim from a proof's payload. Only after dpop.Verify
// has checked the signature.
func proofClaim(t *testing.T, proof, name string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", proof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	v, _ := claims[name].(string)
	return v
}
