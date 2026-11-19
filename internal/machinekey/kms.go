package machinekey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Machine keys held in a cloud KMS.
//
// The private key is generated inside the KMS and never leaves it — not to this
// program, not to the server, not to anyone. What the server needs is
// permission to ask the KMS for a signature, which is the cloud identity it
// already runs as (an instance role, a workload identity), so there is no
// secret to distribute at all.
//
// The KMS is asked for ONE signature per run: the mint request, which names
// this run's in-memory session key. Every API request after that is signed by
// the session key. So a command costs one KMS call, however many requests it
// makes, and the cloud's own audit log records each one.
//
// Reached through the cloud's own command-line tool, for the reason the secret
// sources are (source.go): this binary links no SDK.
//
//	kms-aws:<key id, key ARN, or alias/NAME>     aws kms get-public-key / sign
//	    the key must be KeySpec ECC_NIST_P256, KeyUsage SIGN_VERIFY
//	kms-gcp:projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
//	    the key version must be EC_SIGN_P256_SHA256

const (
	BackendAWSKMS = "aws-kms (non-extractable)"
	BackendGCPKMS = "gcp-kms (non-extractable)"
)

var (
	// A key id (UUID), a multi-Region key id, a key ARN, an alias name, or an
	// alias ARN. Nothing that could read as a flag or carry a space.
	awsKeyRe = regexp.MustCompile(`^(?:arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(?:key|alias)/[A-Za-z0-9/_+=,.@-]+|alias/[A-Za-z0-9/_-]+|(?:mrk-)?[0-9a-f-]{32,36})$`)
	gcpKeyRe = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/([a-z0-9-]+)/keyRings/([A-Za-z0-9_-]{1,63})/cryptoKeys/([A-Za-z0-9_-]{1,63})/cryptoKeyVersions/([0-9]{1,10})$`)
)

// kmsKey is a P-256 key whose private half is in a KMS. It satisfies
// crypto.Signer for callers that hash first (AWS signs a digest) and the dpop
// package's MessageSigner for ones that hash themselves (gcloud takes data).
type kmsKey struct {
	pub         *ecdsa.PublicKey
	signDigest  func(digest []byte) ([]byte, error)
	signMessage func(message []byte) ([]byte, error)
}

func (k *kmsKey) Public() crypto.PublicKey { return k.pub }

func (k *kmsKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("a KMS machine key signs SHA-256 digests only")
	}
	if k.signDigest == nil {
		return nil, errors.New("this KMS signs messages, not digests")
	}
	return k.signDigest(digest)
}

// gcpMessageKey exposes SignMessage, so the dpop builder hands it the whole
// message for gcloud to hash. kmsKey itself does NOT have the method: an AWS
// key must be seen as a plain crypto.Signer and signed by digest.
type gcpMessageKey struct{ *kmsKey }

func (g gcpMessageKey) SignMessage(message []byte) ([]byte, error) {
	return g.signMessage(message)
}

// withTemp writes data to a private temporary file, runs fn with its path, and
// removes it. The cloud tools read binary input from files more reliably than
// from standard input across platforms; what is written is a digest or a
// to-be-signed message, never key material.
func withTemp(data []byte, fn func(path string) error) error {
	dir, err := os.MkdirTemp("", "clerk-protect-kms-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, "in")
	if data != nil {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return err
		}
	}
	return fn(p)
}

func parseP256SPKI(der []byte, what string) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s returned an unreadable public key: %w", what, err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not a P-256 signing key", what)
	}
	return ec, nil
}

func decodeB64(out []byte, what string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, fmt.Errorf("%s returned unreadable output", what)
	}
	return b, nil
}

func openAWSKMS(ctx context.Context, keyID string) (*Key, error) {
	if !awsKeyRe.MatchString(keyID) {
		return nil, fmt.Errorf("%q is not an AWS KMS key id, key ARN or alias", keyID)
	}
	out, err := runner(ctx, []string{"aws", "kms", "get-public-key", "--key-id", keyID,
		"--output", "text", "--query", "PublicKey"})
	if err != nil {
		return nil, fmt.Errorf("read the KMS public key: %w", err)
	}
	der, err := decodeB64(out, "aws kms get-public-key")
	if err != nil {
		return nil, err
	}
	pub, err := parseP256SPKI(der, "the AWS KMS key (it must be KeySpec ECC_NIST_P256)")
	if err != nil {
		return nil, err
	}
	k := &kmsKey{pub: pub}
	k.signDigest = func(digest []byte) ([]byte, error) {
		var sig []byte
		err := withTemp(digest, func(path string) error {
			out, err := runner(ctx, []string{"aws", "kms", "sign", "--key-id", keyID,
				"--message-type", "DIGEST", "--signing-algorithm", "ECDSA_SHA_256",
				"--message", "fileb://" + path, "--output", "text", "--query", "Signature"})
			if err != nil {
				return err
			}
			sig, err = decodeB64(out, "aws kms sign")
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("sign with the KMS key: %w", err)
		}
		return sig, nil
	}
	return newKey(k, false, BackendAWSKMS)
}

func openGCPKMS(ctx context.Context, name string) (*Key, error) {
	m := gcpKeyRe.FindStringSubmatch(name)
	if m == nil {
		return nil, errors.New("kms-gcp: wants projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V")
	}
	project, location, ring, key, version := m[1], m[2], m[3], m[4], m[5]
	scope := []string{"--version", version, "--key", key, "--keyring", ring, "--location", location, "--project", project}

	var pemBytes []byte
	err := withTemp(nil, func(path string) error {
		argv := []string{"gcloud", "kms", "keys", "versions", "get-public-key", version,
			"--key", key, "--keyring", ring, "--location", location, "--project", project,
			"--output-file", path}
		if _, err := runner(ctx, argv); err != nil {
			return err
		}
		var err error
		pemBytes, err = os.ReadFile(path)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read the KMS public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("gcloud returned no PEM public key")
	}
	pub, err := parseP256SPKI(block.Bytes, "the Cloud KMS key version (it must be EC_SIGN_P256_SHA256)")
	if err != nil {
		return nil, err
	}
	k := &kmsKey{pub: pub}
	k.signMessage = func(message []byte) ([]byte, error) {
		var sig []byte
		err := withTemp(message, func(path string) error {
			sigPath := path + ".sig"
			argv := append([]string{"gcloud", "kms", "asymmetric-sign"}, scope...)
			argv = append(argv, "--digest-algorithm", "sha256", "--input-file", path, "--signature-file", sigPath)
			if _, err := runner(ctx, argv); err != nil {
				return err
			}
			var err error
			sig, err = os.ReadFile(sigPath)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("sign with the KMS key: %w", err)
		}
		return sig, nil
	}
	return newKey(gcpMessageKey{k}, false, BackendGCPKMS)
}
