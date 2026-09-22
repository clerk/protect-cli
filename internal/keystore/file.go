package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/fsutil"
)

const fileKeyName = "device-key.pem"

// fileDevice is the explicit opt-in backend: a PEM private key, mode 0600.
//
// EXTRACTABLE, and labelled so everywhere it is shown. It exists for machines
// with no hardware key store and for automated environments, and is never
// chosen unless CLERK_PROTECT_KEY_BACKEND=file asks for it.
type fileDevice struct {
	priv  *ecdsa.PrivateKey
	thumb string
}

func (d *fileDevice) Public() crypto.PublicKey { return &d.priv.PublicKey }
func (d *fileDevice) Backend() Backend         { return BackendFile }
func (d *fileDevice) Thumbprint() string       { return d.thumb }
func (d *fileDevice) Protection() string       { return "" }

func (d *fileDevice) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return d.priv.Sign(rand.Reader, digest, opts)
}

func newFileDevice(priv *ecdsa.PrivateKey) (*fileDevice, error) {
	thumb, err := dpop.Thumbprint(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &fileDevice{priv: priv, thumb: thumb}, nil
}

func openFile(dir string) (Device, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileKeyName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM key", filepath.Join(dir, fileKeyName))
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Join(dir, fileKeyName), err)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not a P-256 key", filepath.Join(dir, fileKeyName))
	}
	return newFileDevice(priv)
}

func createFile(dir string) (Device, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, fileKeyName), data, 0o600); err != nil {
		return nil, err
	}
	return newFileDevice(priv)
}

func deleteFile(dir string) error {
	if err := os.Remove(filepath.Join(dir, fileKeyName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
