//go:build darwin

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// NO TEST HERE MAY SIGN WITH A PRESENCE KEY. On a Mac with Touch ID enrolled
// that blocks on a dialog nobody answers. Presence is never exercised; silent
// is set explicitly, and the default is silent anyway.

func requireEnclave(t *testing.T) {
	t.Helper()
	if err := enclaveSupported(); err != nil {
		t.Skipf("no usable Secure Enclave: %v", err)
	}
}

// What this proves: an enclave key is created, signs, reloads to the same
// thumbprint, reports its backend and policy, and what is written to disk does
// not parse as a private key. It does NOT prove the key cannot be exported —
// that is a property of the Secure Enclave, which no test here can observe.
func TestSecureEnclave_createsAKeyThatSignsReloadsAndIsNotStoredAsAPrivateKey(t *testing.T) {
	requireEnclave(t)
	dir := isolate(t)
	t.Setenv(EnvKeyBackend, "")
	t.Setenv(EnvKeyProtection, "silent")

	d, created, err := OpenOrCreate()
	if err != nil || !created {
		t.Fatalf("OpenOrCreate = %v created=%v", err, created)
	}
	if d.Backend() != BackendSecureEnclave || d.Backend().Extractable() || d.Protection() != "silent" {
		t.Fatalf("backend %q protection %q", d.Backend(), d.Protection())
	}

	digest := sha256.Sum256([]byte("hello secure enclave"))
	sig, err := d.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(d.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the enclave signature does not verify")
	}

	again, err := Open()
	if err != nil || again.Thumbprint() != d.Thumbprint() {
		t.Fatalf("reload: %v — thumbprint changed, which would strand every credential", err)
	}

	// The stored blob is the enclave's wrapped key, not a key: it must not parse
	// as one.
	raw, err := os.ReadFile(filepath.Join(dir, enclaveRecordName))
	if err != nil {
		t.Fatal(err)
	}
	var rec enclaveRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseECPrivateKey(rec.Key); err == nil {
		t.Fatal("the stored blob parses as an EC private key")
	}

	info, err := Status()
	if err != nil || info.Enforced != "silent" {
		t.Fatalf("Status = %+v, %v; the enclave should report it signs without a prompt", info, err)
	}

	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, enclaveRecordName)); !os.IsNotExist(err) {
		t.Fatal("Delete left the key record behind")
	}
}

func TestSecureEnclave_refusesAnythingButSHA256(t *testing.T) {
	requireEnclave(t)
	isolate(t)
	t.Setenv(EnvKeyBackend, "")
	t.Setenv(EnvKeyProtection, "silent")
	d, _, err := OpenOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Sign(rand.Reader, make([]byte, 48), crypto.SHA384); err == nil {
		t.Fatal("signed a SHA-384 digest")
	}
}
