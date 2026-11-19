package machinekey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGenerate_writesAPrivateFileAndRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "ci.pem")
	key, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Extractable || key.Thumbprint == "" {
		t.Fatalf("key = %+v", key)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	// Reading it back gives the same key.
	again, err := Resolve(context.Background(), "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Thumbprint != key.Thumbprint {
		t.Fatalf("round trip changed the key: %s != %s", again.Thumbprint, key.Thumbprint)
	}
	// An approved key overwritten would end every server's access silently.
	if _, err := Generate(path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Generate: %v", err)
	}
}

func pemFor(t *testing.T, sec1 bool) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if sec1 {
		der, _ := x509.MarshalECPrivateKey(priv)
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	} else {
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	k, err := newKey(signer{priv}, true, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), k.Thumbprint
}

// Every shape a secret store hands a PEM back in.
func TestParse_acceptsTheShapesSecretStoresProduce(t *testing.T) {
	pkcs8, thumb8 := pemFor(t, false)
	sec1, thumb1 := pemFor(t, true)
	cases := map[string]struct{ in, want string }{
		"pkcs8":             {pkcs8, thumb8},
		"sec1":              {sec1, thumb1},
		"escaped newlines":  {strings.ReplaceAll(strings.TrimSpace(pkcs8), "\n", `\n`), thumb8},
		"base64":            {base64.StdEncoding.EncodeToString([]byte(pkcs8)), thumb8},
		"surrounding space": {"\n  " + pkcs8 + "  \n", thumb8},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			k, err := Parse([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if k.Thumbprint != tc.want {
				t.Fatalf("thumbprint %s, want %s", k.Thumbprint, tc.want)
			}
		})
	}
}

func TestParse_refusesWhatIsNotAP256PrivateKey(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p384)
	cases := map[string]string{
		"empty":      "",
		"not a key":  "hello",
		"public key": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		"P-384":      string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestExpand_mapsEachSourceToWhatItReads(t *testing.T) {
	cases := []struct {
		spec string
		kind SourceKind
		args []string
	}{
		{"file:/etc/key.pem", SourceFile, []string{"/etc/key.pem"}},
		{"file:///etc/key.pem", SourceFile, []string{"/etc/key.pem"}},
		{"./key.pem", SourceFile, []string{"./key.pem"}},
		{"/abs/key.pem", SourceFile, []string{"/abs/key.pem"}},
		{"C:/keys/key.pem", SourceFile, []string{"C:/keys/key.pem"}},
		{"env:CI_KEY", SourceEnv, []string{"CI_KEY"}},
		{"exec:/bin/fetch one two", SourceExec, []string{"/bin/fetch", "one", "two"}},
		{"keystore:ci-runner", SourceKeystore, []string{"ci-runner"}},
		{"aws-ssm:/prod/key", SourceExec, []string{"aws", "ssm", "get-parameter", "--name", "/prod/key", "--with-decryption", "--query", "Parameter.Value", "--output", "text"}},
		{"gcp-secret:projects/p1/secrets/s1", SourceExec, []string{"gcloud", "secrets", "versions", "access", "latest", "--secret", "s1", "--project", "p1"}},
		{"gcp-secret:projects/p1/secrets/s1/versions/7", SourceExec, []string{"gcloud", "secrets", "versions", "access", "7", "--secret", "s1", "--project", "p1"}},
		{"vault:secret/data/cp#key", SourceExec, []string{"vault", "kv", "get", "-field=key", "secret/data/cp"}},
		{"op://Infra/cp/private-key", SourceExec, []string{"op", "read", "--no-newline", "op://Infra/cp/private-key"}},
	}
	for _, tc := range cases {
		kind, args, err := Expand(tc.spec)
		if err != nil {
			t.Errorf("%s: %v", tc.spec, err)
			continue
		}
		if kind != tc.kind || !slices.Equal(args, tc.args) {
			t.Errorf("%s: got %s %q, want %s %q", tc.spec, kind, args, tc.kind, tc.args)
		}
	}
}

// Anything that could become a flag of the store's CLI, or a scheme nobody
// implemented, is refused rather than guessed at.
func TestExpand_refusesAmbiguousOrFlagShapedSources(t *testing.T) {
	for _, spec := range []string{
		"", "-rf", "file:", "file:-x", "env:1BAD", "env:A-B", "exec:", "exec:-c x",
		"aws-ssm:--profile", "gcp-secret:secrets/x", "vault:path", "vault:-x#f", "vault:p#a=b",
		"keystore:../x", "https://example.com/key", "s3://bucket/key", "azure:thing",
	} {
		if _, _, err := Expand(spec); err == nil {
			t.Errorf("%q: expanded", spec)
		}
	}
}

func TestResolve_readsEnvAndExecSources(t *testing.T) {
	pkcs8, thumb := pemFor(t, false)
	t.Setenv("MK_TEST_PEM", strings.ReplaceAll(strings.TrimSpace(pkcs8), "\n", `\n`))
	k, err := Resolve(context.Background(), "env:MK_TEST_PEM")
	if err != nil || k.Thumbprint != thumb {
		t.Fatalf("env: %v %v", k, err)
	}
	if _, err := Resolve(context.Background(), "env:MK_TEST_UNSET_VAR"); err == nil {
		t.Fatal("an unset variable resolved")
	}

	var gotArgv []string
	saved := runner
	t.Cleanup(func() { runner = saved })
	runner = func(_ context.Context, argv []string) ([]byte, error) {
		gotArgv = argv
		return []byte(pkcs8), nil
	}
	k, err = Resolve(context.Background(), "aws-ssm:/prod/key")
	if err != nil || k.Thumbprint != thumb {
		t.Fatalf("aws-ssm: %v %v", k, err)
	}
	if gotArgv[0] != "aws" || !slices.Contains(gotArgv, "/prod/key") {
		t.Fatalf("ran %q", gotArgv)
	}
	runner = func(context.Context, []string) ([]byte, error) { return nil, errors.New("denied") }
	if _, err := Resolve(context.Background(), "op://a/b/c"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("a failing command: %v", err)
	}
}

// The real runner, against a real program, so the no-shell claim is tested
// rather than asserted: an argument with a shell metacharacter arrives as text.
func TestRunner_runsTheProgramWithoutAShell(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("no /bin/echo")
	}
	out, err := runner(context.Background(), []string{"/bin/echo", "a;", "$(whoami)"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "a; $(whoami)" {
		t.Fatalf("echo printed %q — the arguments went through a shell", got)
	}
}

func TestGenerate_refusesAKeyFileOnWindows(t *testing.T) {
	if _, err := generate(filepath.Join(t.TempDir(), "k.pem"), "windows"); err == nil {
		t.Fatal("wrote an extractable key file on Windows, where a file mode restricts nothing")
	}
}

func TestResolve_warnsAboutAKeyFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "k.pem")
	if _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	k, err := Resolve(context.Background(), path)
	if err != nil || k.Warning != "" {
		t.Fatalf("a 0600 file warned: %q %v", k.Warning, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	k, err = Resolve(context.Background(), path)
	if err != nil || !strings.Contains(k.Warning, "readable by other accounts") {
		t.Fatalf("a 0644 file: %q %v", k.Warning, err)
	}
}

// Codex review: a source whose child keeps stdout open must still end near
// the limit, not when the grandchild does.
func TestRunner_doesNotWaitForAGrandchildHoldingTheOutput(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _ = runner(ctx, []string{"/bin/sh", "-c", "sleep 6 & wait"})
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("the source ran %s past a 100ms limit", d)
	}
}
