package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The RFC 9449 example key (§4.1) and the thumbprint the RFC's own examples
// bind tokens to (§6.1). A vector from the specification rather than one this
// code produced, so a thumbprint that is internally consistent but wrong —
// members out of order, padding left on — fails here.
func TestThumbprint_matchesTheRFCVector(t *testing.T) {
	x, _ := b64.DecodeString("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs")
	y, _ := b64.DecodeString("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA")
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if want := "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"; got != want {
		t.Fatalf("Thumbprint = %q, want the RFC 9449 value %q", got, want)
	}
}

// Decode the proof by hand and check the signature with crypto/ecdsa directly —
// not with this package's Verify, which would share any mistake Proof made.
func TestProof_isAWellFormedSignedJWS(t *testing.T) {
	key := newKey(t)
	b, err := NewBuilder(key)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1_800_000_000, 0)
	b.Now = func() time.Time { return fixed }
	proof, err := b.Proof("GET", "https://api.example.test/labs/api/me", "the-token")
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof has %d parts", len(parts))
	}
	var hdr map[string]any
	raw, _ := b64.DecodeString(parts[0])
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["typ"] != "dpop+jwt" || hdr["alg"] != "ES256" {
		t.Fatalf("header %v", hdr)
	}
	jwk, _ := hdr["jwk"].(map[string]any)
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["d"] != nil {
		t.Fatalf("jwk %v — and it must never carry the private part", jwk)
	}

	var c map[string]any
	raw, _ = b64.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("the-token"))
	if c["htm"] != "GET" || c["htu"] != "https://api.example.test/labs/api/me" ||
		c["iat"] != float64(fixed.Unix()) || c["ath"] != b64.EncodeToString(sum[:]) {
		t.Fatalf("claims %v", c)
	}
	if jti, _ := c["jti"].(string); len(jti) < 16 {
		t.Fatalf("jti %q is too short to be random", jti)
	}

	sig, _ := b64.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64 (r||s)", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the signature does not verify against the key")
	}
}

func TestProof_withoutATokenCarriesNoATH(t *testing.T) {
	b, _ := NewBuilder(newKey(t))
	proof, err := b.Proof("POST", "https://api.example.test/labs/cli/token", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b64.DecodeString(strings.Split(proof, ".")[1])
	if strings.Contains(string(raw), `"ath"`) {
		t.Fatalf("claims %s carry ath with no token", raw)
	}
}

func TestProof_everyProofHasAFreshJTI(t *testing.T) {
	key := newKey(t)
	b, _ := NewBuilder(key)
	seen := map[string]bool{}
	for range 50 {
		p, err := b.Proof("GET", "https://api.example.test/x", "t")
		if err != nil {
			t.Fatal(err)
		}
		v, err := Verify(p, "GET", "https://api.example.test/x", "t", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if seen[v.JTI] {
			t.Fatalf("jti %q repeated — the server's replay cache would refuse the second request", v.JTI)
		}
		seen[v.JTI] = true
	}
}

// Verify is test infrastructure for the other packages; it must refuse what a
// server refuses or those tests prove nothing.
func TestVerify_refusesATamperedOrMisboundProof(t *testing.T) {
	key := newKey(t)
	b, _ := NewBuilder(key)
	proof, _ := b.Proof("GET", "https://api.example.test/a", "tok")
	thumb, _ := Thumbprint(&key.PublicKey)

	v, err := Verify(proof, "GET", "https://api.example.test/a", "tok", time.Minute)
	if err != nil || v.Thumbprint != thumb {
		t.Fatalf("control: Verify = %+v, %v", v, err)
	}
	for name, check := range map[string]func() error{
		"wrong method": func() error {
			_, e := Verify(proof, "POST", "https://api.example.test/a", "tok", time.Minute)
			return e
		},
		"wrong url": func() error { _, e := Verify(proof, "GET", "https://api.example.test/b", "tok", time.Minute); return e },
		"wrong token": func() error {
			_, e := Verify(proof, "GET", "https://api.example.test/a", "other", time.Minute)
			return e
		},
		"missing token": func() error { _, e := Verify(proof, "GET", "https://api.example.test/a", "", time.Minute); return e },
		"bad signature": func() error {
			_, e := Verify(proof[:len(proof)-4]+"AAAA", "GET", "https://api.example.test/a", "tok", time.Minute)
			return e
		},
		"stale": func() error {
			_, e := Verify(proof, "GET", "https://api.example.test/a", "tok", -time.Second)
			return e
		},
	} {
		if check() == nil {
			t.Errorf("%s: Verify accepted it", name)
		}
	}
}

func TestJOSEToDER_roundTrips(t *testing.T) {
	key := newKey(t)
	digest := sha256.Sum256([]byte("x"))
	der, err := key.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := derToJOSE(der)
	if err != nil {
		t.Fatal(err)
	}
	back, err := JOSEToDER(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], back) {
		t.Fatal("round-tripped signature does not verify")
	}
}

func TestFingerprint(t *testing.T) {
	if got := Fingerprint("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"); got != "0ZcO-CORZ" {
		t.Fatalf("Fingerprint = %q", got)
	}
}
