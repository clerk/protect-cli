package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Verified is what Verify established about a proof.
type Verified struct {
	Thumbprint string
	JTI        string
	IssuedAt   time.Time
}

// Verify checks a proof the way a server does: header shape, signature against
// the embedded key, method, URL, freshness, jti presence, and — when
// accessToken is non-empty — the ath binding.
//
// The CLI never verifies its own proofs in production. This exists so the tests
// in this module can stand up a server that refuses exactly what the real one
// refuses, rather than one that accepts anything shaped like a JWT.
func Verify(proof, htm, htu, accessToken string, maxAge time.Duration) (Verified, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return Verified{}, errors.New("dpop: not a compact JWS")
	}
	hdrRaw, err := b64.DecodeString(parts[0])
	if err != nil {
		return Verified{}, fmt.Errorf("dpop: header: %w", err)
	}
	var hdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK JWK    `json:"jwk"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return Verified{}, fmt.Errorf("dpop: header: %w", err)
	}
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" || hdr.JWK.Kty != "EC" || hdr.JWK.Crv != "P-256" {
		return Verified{}, fmt.Errorf("dpop: bad header typ=%q alg=%q", hdr.Typ, hdr.Alg)
	}
	x, errX := b64.DecodeString(hdr.JWK.X)
	y, errY := b64.DecodeString(hdr.JWK.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return Verified{}, errors.New("dpop: bad jwk coordinates")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return Verified{}, fmt.Errorf("dpop: jwk: %w", err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return Verified{}, errors.New("dpop: signature is not 64 bytes")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return Verified{}, errors.New("dpop: signature does not verify")
	}

	bodyRaw, err := b64.DecodeString(parts[1])
	if err != nil {
		return Verified{}, fmt.Errorf("dpop: claims: %w", err)
	}
	var c claims
	if err := json.Unmarshal(bodyRaw, &c); err != nil {
		return Verified{}, fmt.Errorf("dpop: claims: %w", err)
	}
	switch {
	case c.JTI == "":
		return Verified{}, errors.New("dpop: missing jti")
	case c.HTM != htm:
		return Verified{}, fmt.Errorf("dpop: htm %q, want %q", c.HTM, htm)
	case c.HTU != htu:
		return Verified{}, fmt.Errorf("dpop: htu %q, want %q", c.HTU, htu)
	}
	iat := time.Unix(c.IAT, 0)
	if time.Since(iat) > maxAge || time.Until(iat) > 5*time.Second {
		return Verified{}, errors.New("dpop: proof is not fresh")
	}
	if accessToken == "" {
		if c.ATH != "" {
			return Verified{}, errors.New("dpop: unexpected ath")
		}
	} else {
		sum := sha256.Sum256([]byte(accessToken))
		if c.ATH != b64.EncodeToString(sum[:]) {
			return Verified{}, errors.New("dpop: ath does not match the token")
		}
	}
	thumb, err := Thumbprint(pub)
	if err != nil {
		return Verified{}, err
	}
	return Verified{Thumbprint: thumb, JTI: c.JTI, IssuedAt: iat}, nil
}
