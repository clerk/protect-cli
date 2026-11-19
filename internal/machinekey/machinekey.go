// Package machinekey holds the keys servers use to run clerk-protect without a
// person signing in.
//
// A machine key is a P-256 key pair. A person registers its public half with
// their instance, an administrator of the instance approves it once in the
// browser, and from then on whoever holds the private half can ask for short
// tokens on its own until the approval is revoked or ends.
//
// Two kinds, chosen when the key is made:
//
//	extractable      A PEM file. Copy it into your secret storage — a cloud
//	                 parameter store, a vault, a password manager — and hand it
//	                 to each server at run time. Whoever can read it can use it.
//	non-extractable  Generated inside this computer's hardware key store, where
//	                 the platform has one (macOS, Windows). It works only on this
//	                 computer and cannot be copied anywhere.
//
// At run time the key is named by a SOURCE (see Resolve): a file, an
// environment variable, or a command that prints it — which is how every
// secret store's own tooling already hands secrets to a process.
package machinekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/clerk/protect-cli/internal/config"
	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/keystore"
)

// EnvMachineKey names the machine key source a command runs with. Set, every
// command authenticates as the machine key instead of a person's sign-in.
const EnvMachineKey = "CLERK_PROTECT_MACHINE_KEY"

// Key is a loaded machine key.
type Key struct {
	crypto.Signer
	// Thumbprint is the RFC 7638 thumbprint the server knows the key by.
	Thumbprint string
	// Extractable reports whether the private key came from somewhere it can
	// be copied from (anything but this computer's hardware store).
	Extractable bool
	// Backend is the label sent with a registration: what kind of key this is,
	// as this program knows it. The server shows it and never trusts it.
	Backend string
	// Warning is something about where the key was read from that its holder
	// should hear — a key file other accounts can read — without refusing.
	Warning string
}

func newKey(s crypto.Signer, extractable bool, backend string) (*Key, error) {
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("a machine key must be a P-256 key")
	}
	thumb, err := dpop.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &Key{Signer: s, Thumbprint: thumb, Extractable: extractable, Backend: backend}, nil
}

// BackendFile labels an extractable key, wherever it was read from.
const BackendFile = "file (extractable)"

// Generate makes a new extractable machine key and writes it to path as a
// PKCS#8 PEM file, readable only by this user. It refuses to replace an
// existing file: overwriting a key that was approved would silently end every
// server's access with nothing to say why.
func Generate(path string) (*Key, error) {
	return generate(path, runtime.GOOS)
}

func generate(path, goos string) (*Key, error) {
	if path == "" || path == "-" || strings.HasPrefix(path, "-") {
		return nil, errors.New("the key file path must not be empty or start with '-'")
	}
	// On Windows a file mode is not an access-control list: 0600 sets only the
	// read-only attribute, and the file inherits its directory's ACL, which may
	// let other accounts read it. The device key refuses a file there for the
	// same reason; a machine key that should stay put belongs in Windows key
	// storage instead.
	if goos == "windows" {
		return nil, errors.New("an extractable key file cannot be restricted to you on Windows; " +
			"use --non-extractable --name NAME for a key held by Windows key storage, or create the file on another system and keep it in your secret storage")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s already exists — choose another path, or delete it first if that key was never approved", path)
		}
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return newKey(priv, true, BackendFile)
}

// nameRe is a stored key's name: it becomes a directory.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether s can name a key kept in the hardware store.
func ValidName(s string) bool { return nameRe.MatchString(s) && !strings.Contains(s, "..") }

func storedDir(name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("%q is not a key name (letters, digits, '.', '_' and '-', starting with a letter or digit)", name)
	}
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "machine-keys", name), nil
}

// GenerateStored makes a non-extractable machine key in this computer's
// hardware key store, under name. It refuses where there is no such store —
// there is no quiet fallback to a file.
func GenerateStored(name string) (*Key, error) {
	dir, err := storedDir(name)
	if err != nil {
		return nil, err
	}
	if _, err := keystore.OpenPlatformAt(dir); err == nil {
		return nil, fmt.Errorf("a machine key named %q already exists on this computer", name)
	} else if !errors.Is(err, keystore.ErrNoKey) {
		if errors.Is(err, keystore.ErrUnsupported) {
			return nil, unsupportedStore()
		}
		return nil, err
	}
	d, err := keystore.CreatePlatformAt(dir)
	if err != nil {
		if errors.Is(err, keystore.ErrUnsupported) {
			return nil, unsupportedStore()
		}
		return nil, err
	}
	return newKey(d, false, string(d.Backend()))
}

func openStored(name string) (*Key, error) {
	dir, err := storedDir(name)
	if err != nil {
		return nil, err
	}
	d, err := keystore.OpenPlatformAt(dir)
	if errors.Is(err, keystore.ErrNoKey) {
		return nil, fmt.Errorf("no machine key named %q on this computer", name)
	}
	if errors.Is(err, keystore.ErrUnsupported) {
		return nil, unsupportedStore()
	}
	if err != nil {
		return nil, err
	}
	return newKey(d, false, string(d.Backend()))
}

func unsupportedStore() error {
	return errors.New("this computer has no supported non-extractable key store (macOS and Windows do); " +
		"create an extractable key with `clerk-protect machine-key create --out <path>` and keep it in your secret storage")
}

// Parse reads a machine key's private half from what a source produced.
//
// Accepted: a PEM block (PKCS#8 "PRIVATE KEY" or SEC 1 "EC PRIVATE KEY"); the
// same with its line breaks written as the two characters `\n`, which is how a
// PEM survives a single-line environment variable or a JSON field; or either of
// those base64-encoded, which is how some stores hand back binary-safe values.
func Parse(data []byte) (*Key, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, errors.New("the key source produced nothing")
	}
	if !strings.Contains(text, "-----BEGIN") {
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, errors.New("the key source did not produce a PEM key (or a base64-encoded one)")
		}
		text = strings.TrimSpace(string(decoded))
	}
	if !strings.Contains(text, "\n") && strings.Contains(text, `\n`) {
		text = strings.ReplaceAll(text, `\n`, "\n")
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("the key source did not produce a PEM key")
	}
	var priv *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse the machine key: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("a machine key must be a P-256 EC key")
		}
		priv = ec
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse the machine key: %w", err)
		}
		priv = k
	default:
		return nil, fmt.Errorf("a %q PEM block is not a private key", block.Type)
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("a machine key must be a P-256 key")
	}
	return newKey(signer{priv}, true, BackendFile)
}

// signer signs with crypto/rand, whatever reader the caller passes.
type signer struct{ priv *ecdsa.PrivateKey }

func (s signer) Public() crypto.PublicKey { return &s.priv.PublicKey }
func (s signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.priv.Sign(rand.Reader, digest, opts)
}
