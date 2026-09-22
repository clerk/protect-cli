package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/dpop"
)

// isolate points the keystore at a temporary directory. Every test in this
// package calls it FIRST: a test that forgot would read and rewrite the real
// device key of whoever runs the suite.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	return dir
}

func skipFileBackendOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the key file backend is refused on Windows")
	}
}

func TestIsolate_redirectsTheKeystore(t *testing.T) {
	dir := isolate(t)
	got, err := config.Dir()
	if err != nil || got != dir {
		t.Fatalf("config.Dir() = %q, %v; want the temporary directory", got, err)
	}
}

func TestFileBackend_roundTrip(t *testing.T) {
	skipFileBackendOnWindows(t)
	dir := isolate(t)
	t.Setenv(EnvKeyBackend, "file")

	if _, err := Open(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Open on an empty directory: %v, want ErrNoKey", err)
	}
	d, created, err := OpenOrCreate()
	if err != nil || !created {
		t.Fatalf("OpenOrCreate = %v, created=%v", err, created)
	}
	if d.Backend() != BackendFile || !d.Backend().Extractable() {
		t.Fatalf("backend %q; a key file must say it is extractable", d.Backend())
	}
	fi, err := os.Stat(filepath.Join(dir, fileKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
	}

	digest := sha256.Sum256([]byte("hello"))
	sig, err := d.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub := d.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	thumb, _ := dpop.Thumbprint(pub)
	if d.Thumbprint() != thumb {
		t.Fatalf("Thumbprint() = %q, want %q", d.Thumbprint(), thumb)
	}

	again, created, err := OpenOrCreate()
	if err != nil || created || again.Thumbprint() != d.Thumbprint() {
		t.Fatalf("second OpenOrCreate: %v created=%v — a new key would strand every credential", err, created)
	}

	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Open after Delete: %v, want ErrNoKey", err)
	}
}

// The file backend is an opt-in, never a fallback: with the variable unset, a
// key file on disk is not used.
func TestFileBackend_isNeverChosenImplicitly(t *testing.T) {
	skipFileBackendOnWindows(t)
	isolate(t)
	t.Setenv(EnvKeyBackend, "file")
	if _, _, err := OpenOrCreate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKeyBackend, "")
	d, err := Open()
	if err == nil && d.Backend() == BackendFile {
		t.Fatal("the key file was used without CLERK_PROTECT_KEY_BACKEND=file")
	}
}

// On Windows a file mode is not an ACL, so the key file is refused there
// rather than written readable by whoever the directory lets in.
func TestFileBackend_isRefusedOnWindows(t *testing.T) {
	if err := fileBackendAllowed("windows"); err == nil {
		t.Fatal("the key file backend was allowed on Windows")
	}
	for _, goos := range []string{"darwin", "linux", "freebsd"} {
		if err := fileBackendAllowed(goos); err != nil {
			t.Errorf("control: refused on %s: %v", goos, err)
		}
	}
	if runtime.GOOS == "windows" {
		dir := isolate(t)
		t.Setenv(EnvKeyBackend, "file")
		if _, _, err := OpenOrCreate(); err == nil {
			t.Fatal("OpenOrCreate created a key file on Windows")
		}
		if _, err := os.Stat(filepath.Join(dir, fileKeyName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a key file was written: %v", err)
		}
	}
}

func TestSelectedMode_refusesAnUnknownBackend(t *testing.T) {
	isolate(t)
	t.Setenv(EnvKeyBackend, "keychain-please")
	if _, err := Open(); err == nil {
		t.Fatal("an unknown backend name was accepted")
	}
}

func TestBackend_describesEveryBackend(t *testing.T) {
	for _, b := range []Backend{BackendSecureEnclave, BackendTPM, BackendSoftware, BackendFile} {
		if b.Describe() == string(b) {
			t.Errorf("%q has no description", b)
		}
		if b.Extractable() != (b == BackendFile) {
			t.Errorf("%q extractable = %v", b, b.Extractable())
		}
	}
}

func TestParseProtection(t *testing.T) {
	for in, want := range map[string]Protection{"": ProtectionSilent, "silent": ProtectionSilent, "PRESENCE": ProtectionPresence, "auto": ProtectionAuto} {
		got, err := ParseProtection(in)
		if err != nil || got != want {
			t.Errorf("ParseProtection(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseProtection("sometimes"); err == nil {
		t.Error("an unknown policy was accepted")
	}
}
