package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// randomToken is n bytes of CSPRNG output, base64url without padding.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewPKCE returns an RFC 7636 verifier and its S256 challenge.
//
// The verifier never leaves this process until the code exchange. That is what
// makes an intercepted authorization code worthless on its own: the server
// redeems a code only together with the verifier whose hash it was issued for.
func NewPKCE() (verifier, challenge string, err error) {
	verifier, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	return verifier, S256(verifier), nil
}

// S256 is the PKCE challenge for a verifier.
func S256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
