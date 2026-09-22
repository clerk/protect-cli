// Package dpop builds RFC 9449 DPoP proofs: a small signed JWT, one per
// request, proving the caller holds the private key its access token is bound
// to.
//
// Written here rather than taken from a library because this binary's
// dependency closure is reviewed module by module, and a proof is forty lines
// of JOSE that are easier to read than a dependency is to audit.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var b64 = base64.RawURLEncoding

// JWK is the public half of a P-256 key in the form a proof header carries.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// PublicJWK encodes a P-256 public key.
func PublicJWK(pub *ecdsa.PublicKey) (JWK, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return JWK{}, errors.New("dpop: the key is not a P-256 key")
	}
	raw, err := pub.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("dpop: encode public key: %w", err)
	}
	if len(raw) != 65 || raw[0] != 4 {
		return JWK{}, fmt.Errorf("dpop: unexpected public key encoding (%d bytes)", len(raw))
	}
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1:33]), Y: b64.EncodeToString(raw[33:65])}, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of a P-256 key: the value the
// server binds a token to, and the one the browser shows when it asks you to
// approve this machine.
//
// The canonical input is fixed by the RFC — members in lexical order, no
// whitespace — so it is written out rather than left to a JSON encoder whose
// ordering is an implementation detail.
func Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	jwk, err := PublicJWK(pub)
	if err != nil {
		return "", err
	}
	canonical := `{"crv":"P-256","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

// Fingerprint is the short form of a thumbprint shown to a person: its first
// eight characters, split in two. The browser approval page shows the same
// eight characters, which is how a person tells that the machine asking is the
// one in front of them.
func Fingerprint(thumbprint string) string {
	if len(thumbprint) < 8 {
		return thumbprint
	}
	return thumbprint[:4] + "-" + thumbprint[4:8]
}

// Builder signs proofs with one key.
type Builder struct {
	signer crypto.Signer
	header []byte // the encoded header, which never changes for a key
	// Now is the clock; nil means time.Now. Tests set it.
	Now func() time.Time
}

// NewBuilder returns a Builder for a P-256 signer.
func NewBuilder(signer crypto.Signer) (*Builder, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("dpop: signer public key is %T, want an ECDSA key", signer.Public())
	}
	jwk, err := PublicJWK(pub)
	if err != nil {
		return nil, err
	}
	header, err := json.Marshal(struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK JWK    `json:"jwk"`
	}{Typ: "dpop+jwt", Alg: "ES256", JWK: jwk})
	if err != nil {
		return nil, err
	}
	return &Builder{signer: signer, header: header}, nil
}

type claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
}

// Proof builds a proof for one request.
//
// htu is the request URL WITHOUT query or fragment (RFC 9449 §4.2). accessToken
// is empty for a request that presents no token yet — the code exchange — and
// otherwise binds the proof to it through `ath`, so a proof cannot be moved to
// a different token.
//
// Every proof gets a fresh random jti. The server keeps a replay cache, and a
// proof without a jti would skip it.
func (b *Builder) Proof(htm, htu, accessToken string) (string, error) {
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", fmt.Errorf("dpop: generate jti: %w", err)
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	c := claims{JTI: b64.EncodeToString(jti[:]), HTM: htm, HTU: htu, IAT: now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		c.ATH = b64.EncodeToString(sum[:])
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(b.header) + "." + b64.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	der, err := b.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: sign proof: %w", err)
	}
	raw, err := derToJOSE(der)
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(raw), nil
}

// derToJOSE converts an ASN.1 DER ECDSA signature — what crypto.Signer returns
// — into the fixed-width r||s JWS requires. Getting this wrong produces a proof
// that looks well-formed and never verifies.
func derToJOSE(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, errors.New("dpop: the key returned a malformed signature")
	}
	if sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, errors.New("dpop: the key returned an oversized signature")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

// JOSEToDER is the inverse, for key stores that return r||s natively.
func JOSEToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("dpop: raw signature is %d bytes, want 64", len(raw))
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:32]),
		S: new(big.Int).SetBytes(raw[32:]),
	})
}
