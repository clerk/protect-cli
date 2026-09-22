//go:build darwin

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/fsutil"
)

const (
	platformBackendName = string(BackendSecureEnclave)
	enclaveRecordName   = "device-key.json"
	enclaveRecordV1     = 1
	// presencePrompt is what macOS shows when a presence-protected key signs.
	presencePrompt = "Clerk Protect CLI wants to sign in"
)

// enclaveRecord is the on-disk form of the key. Key is the SEP-wrapped blob:
// not secret in the way a private key is, but still written 0600 — the policy
// is nobody else's business and a writable record is a downgrade vector.
type enclaveRecord struct {
	Version    int        `json:"version"`
	Backend    string     `json:"backend"`
	Protection Protection `json:"protection"`
	Key        []byte     `json:"key"`
	CreatedAt  time.Time  `json:"created_at"`
}

type enclaveDevice struct {
	blob       []byte
	pub        *ecdsa.PublicKey
	protection Protection
	thumb      string
}

func (d *enclaveDevice) Public() crypto.PublicKey { return d.pub }
func (d *enclaveDevice) Backend() Backend         { return BackendSecureEnclave }
func (d *enclaveDevice) Thumbprint() string       { return d.thumb }
func (d *enclaveDevice) Protection() string       { return string(d.protection) }

func (d *enclaveDevice) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// The enclave implements one digest algorithm. Refuse anything else rather
	// than hand it a digest it would misread.
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, errors.New("keystore: the Secure Enclave signs SHA-256 digests only")
	}
	prompt := ""
	if d.protection == ProtectionPresence {
		prompt = presencePrompt
	}
	return enclaveSign(d.blob, digest, prompt, false)
}

func recordPath(dir string) string { return filepath.Join(dir, enclaveRecordName) }

func platformOpen(dir string) (Device, error) {
	data, err := os.ReadFile(recordPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	var rec enclaveRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("read %s: %w", recordPath(dir), err)
	}
	if rec.Backend != string(BackendSecureEnclave) || len(rec.Key) == 0 {
		return nil, fmt.Errorf("%s is not a Secure Enclave key record", recordPath(dir))
	}
	return newEnclaveDevice(rec)
}

func newEnclaveDevice(rec enclaveRecord) (*enclaveDevice, error) {
	point, err := enclavePublic(rec.Key)
	if err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("parse the Secure Enclave public key: %w", err)
	}
	thumb, err := dpop.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &enclaveDevice{blob: rec.Key, pub: pub, protection: rec.Protection, thumb: thumb}, nil
}

func resolveProtection() (Protection, error) {
	p, err := ParseProtection(os.Getenv(EnvKeyProtection))
	if err != nil {
		return "", fmt.Errorf("%s: %w", EnvKeyProtection, err)
	}
	if p == ProtectionAuto {
		if biometryEnrolled() {
			return ProtectionPresence, nil
		}
		return ProtectionSilent, nil
	}
	return p, nil
}

func platformCreate(dir string) (Device, error) {
	if err := enclaveSupported(); err != nil {
		return nil, fmt.Errorf("%w: %v (set %s=file to use an extractable key file instead)", ErrUnsupported, err, EnvKeyBackend)
	}
	protection, err := resolveProtection()
	if err != nil {
		return nil, err
	}
	blob, err := enclaveGenerate(protection == ProtectionPresence)
	if err != nil {
		return nil, err
	}
	rec := enclaveRecord{
		Version:    enclaveRecordV1,
		Backend:    string(BackendSecureEnclave),
		Protection: protection,
		Key:        blob,
		CreatedAt:  time.Now().UTC(),
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(recordPath(dir), data, 0o600); err != nil {
		return nil, err
	}
	return newEnclaveDevice(rec)
}

// platformDelete removes the record. The key was never in the Keychain, so the
// wrapped blob is the only copy: removing it destroys the key.
func platformDelete(dir string) error {
	if err := os.Remove(recordPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// platformEnforced asks the enclave what it enforces instead of trusting the
// record: a signature with all UI forbidden succeeds for a silent key and is
// refused for a presence-gated one. Never shows a dialog.
func platformEnforced(d Device) string {
	e, ok := d.(*enclaveDevice)
	if !ok {
		return ""
	}
	probe := sha256.Sum256([]byte("clerk-protect: verify key protection"))
	if _, err := enclaveSign(e.blob, probe[:], "", true); err != nil {
		return string(ProtectionPresence)
	}
	return string(ProtectionSilent)
}
