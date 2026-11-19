package machinekey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
)

// argAfter returns the value following flag in argv.
func argAfter(argv []string, flag string) string {
	if i := slices.Index(argv, flag); i >= 0 && i+1 < len(argv) {
		return argv[i+1]
	}
	return ""
}

// fakeKMS stands in for the aws and gcloud tools, holding a real key so a
// proof signed through them can be verified for real. It records each call.
type fakeKMS struct {
	priv  *ecdsa.PrivateKey
	calls [][]string
}

func newFakeKMS(t *testing.T, curve elliptic.Curve) *fakeKMS {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKMS{priv: priv}
	saved := runner
	t.Cleanup(func() { runner = saved })
	runner = f.run
	return f
}

func (f *fakeKMS) run(_ context.Context, argv []string) ([]byte, error) {
	f.calls = append(f.calls, argv)
	spki, _ := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	switch {
	case slices.Equal(argv[:3], []string{"aws", "kms", "get-public-key"}):
		return []byte(base64.StdEncoding.EncodeToString(spki) + "\n"), nil
	case slices.Equal(argv[:3], []string{"aws", "kms", "sign"}):
		if argAfter(argv, "--message-type") != "DIGEST" || argAfter(argv, "--signing-algorithm") != "ECDSA_SHA_256" {
			return nil, errors.New("fake aws: wrong signing mode")
		}
		digest, err := os.ReadFile(strings.TrimPrefix(argAfter(argv, "--message"), "fileb://"))
		if err != nil {
			return nil, err
		}
		sig, err := ecdsa.SignASN1(rand.Reader, f.priv, digest)
		if err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(sig)), nil
	case slices.Equal(argv[:5], []string{"gcloud", "kms", "keys", "versions", "get-public-key"}):
		out := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
		return nil, os.WriteFile(argAfter(argv, "--output-file"), out, 0o600)
	case slices.Equal(argv[:3], []string{"gcloud", "kms", "asymmetric-sign"}):
		msg, err := os.ReadFile(argAfter(argv, "--input-file"))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(msg) // gcloud hashes the input itself
		sig, err := ecdsa.SignASN1(rand.Reader, f.priv, sum[:])
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(argAfter(argv, "--signature-file"), sig, 0o600)
	}
	return nil, errors.New("fake kms: unexpected " + strings.Join(argv, " "))
}

const gcpVersion = "projects/my-project/locations/global/keyRings/ring/cryptoKeys/clerk-protect/cryptoKeyVersions/1"

// The property that matters: a proof built through each KMS signer verifies
// against the KMS key's own thumbprint, and the private key was never here.
func TestKMS_signsProofsThatVerify(t *testing.T) {
	for _, spec := range []string{"kms-aws:alias/clerk-protect", "kms-gcp:" + gcpVersion} {
		t.Run(spec, func(t *testing.T) {
			f := newFakeKMS(t, elliptic.P256())
			key, err := Resolve(context.Background(), spec)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := dpop.Thumbprint(&f.priv.PublicKey)
			if key.Thumbprint != want || key.Extractable {
				t.Fatalf("key = %+v, want thumbprint %s and non-extractable", key, want)
			}
			b, err := dpop.NewBuilder(key.Signer)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := b.MintProof("POST", "https://console.example/labs/cli/machine-token", want)
			if err != nil {
				t.Fatal(err)
			}
			v, err := dpop.Verify(proof, "POST", "https://console.example/labs/cli/machine-token", "", time.Minute)
			if err != nil || v.Thumbprint != want {
				t.Fatalf("the KMS-signed proof did not verify: %v", err)
			}
		})
	}
}

// AWS signs a digest; gcloud is handed the message and hashes it. Each tool is
// called the way its own contract says — the wrong one produces a signature
// over the wrong bytes that never verifies.
func TestKMS_callsEachToolInItsOwnMode(t *testing.T) {
	f := newFakeKMS(t, elliptic.P256())
	key, err := Resolve(context.Background(), "kms-gcp:"+gcpVersion)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := dpop.NewBuilder(key.Signer)
	if _, err := b.Proof("GET", "https://x.example/", ""); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if last[0] != "gcloud" || argAfter(last, "--digest-algorithm") != "sha256" || argAfter(last, "--project") != "my-project" {
		t.Fatalf("gcloud called as %q", last)
	}
}

func TestKMS_refusesAKeyThatIsNotP256(t *testing.T) {
	newFakeKMS(t, elliptic.P384())
	for _, spec := range []string{"kms-aws:alias/clerk-protect", "kms-gcp:" + gcpVersion} {
		if _, err := Resolve(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "P-256") {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestKMS_refusesMalformedKeyNames(t *testing.T) {
	for _, spec := range []string{
		"kms-aws:", "kms-aws:--profile", "kms-aws:alias/a b", "kms-aws:arn:aws:s3:::bucket",
		"kms-gcp:projects/p/keyRings/r", "kms-gcp:" + gcpVersion + "/extra", "kms-gcp:--x",
	} {
		if _, _, err := Expand(spec); err == nil {
			t.Errorf("%q expanded", spec)
		}
	}
	for _, spec := range []string{
		"kms-aws:1234abcd-12ab-34cd-56ef-1234567890ab",
		"kms-aws:mrk-1234abcd12ab34cd56ef1234567890ab",
		"kms-aws:arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"kms-aws:arn:aws:kms:us-east-1:111122223333:alias/clerk-protect",
		"kms-aws:alias/clerk-protect",
	} {
		if _, _, err := Expand(spec); err != nil {
			t.Errorf("%q: %v", spec, err)
		}
	}
}
