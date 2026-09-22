// Package keystore holds this machine's device key: the P-256 key every
// clerk-protect credential is bound to.
//
// The credential the CLI stores is useless without this key — every request
// carries a proof signed by it, and the server refuses a token presented
// without one. So the key's storage IS the credential's security, and the
// backends are ranked by one question: can the private key leave the machine?
//
//	secure-enclave           macOS. Generated inside the Secure Enclave; what
//	                         is stored is a blob only this Mac's enclave can
//	                         unwrap.
//	tpm                      Windows with a TPM 2.0. Generated inside the TPM.
//	software-non-exportable  Windows without a TPM. The operating system will
//	                         not export it, but it is protected by the user's
//	                         Windows secrets rather than by hardware.
//	file                     Explicit opt-in only, and never on Windows. A PEM
//	                         file: whoever can read it can use the credential.
//
// There is no silent fallback from a hardware store to a file. A machine that
// cannot hold a non-extractable key refuses, and says how to opt in.
package keystore

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/clerk/protect-cli/internal/config"
)

// Backend names where a device key lives.
type Backend string

const (
	BackendSecureEnclave Backend = "secure-enclave"
	BackendTPM           Backend = "tpm"
	BackendSoftware      Backend = "software-non-exportable"
	BackendFile          Backend = "file"
)

// Extractable reports whether the private key can be copied off the machine.
func (b Backend) Extractable() bool { return b == BackendFile }

// Describe is the one-line explanation shown by `keys status`.
func (b Backend) Describe() string {
	switch b {
	case BackendSecureEnclave:
		return "Secure Enclave — the private key cannot leave this Mac"
	case BackendTPM:
		return "TPM — the private key cannot leave this computer's security chip"
	case BackendSoftware:
		return "Windows key storage — not exportable, but protected by your Windows account rather than by hardware"
	case BackendFile:
		return "key file — EXTRACTABLE: anyone who can read the file can use your credential"
	default:
		return string(b)
	}
}

// Device is a loaded device key.
type Device interface {
	crypto.Signer
	Backend() Backend
	// Thumbprint is the RFC 7638 thumbprint tokens are bound to.
	Thumbprint() string
	// Protection names a local policy on top of the backend — `presence` or
	// `silent` on a Mac — and is empty where none applies.
	Protection() string
}

const (
	// EnvKeyBackend selects the backend. Empty means this platform's hardware
	// store; "file" opts in to an extractable key file.
	EnvKeyBackend = "CLERK_PROTECT_KEY_BACKEND"

	// EnvKeyProtection chooses the Mac policy for a NEW key: silent (the
	// default), presence, or auto. It has no effect on an existing key.
	EnvKeyProtection = "CLERK_PROTECT_KEY_PROTECTION"
)

// ErrNoKey means this machine has no device key yet.
var ErrNoKey = errors.New("no device key on this machine — run `clerk-protect login`")

// ErrUnsupported means this machine cannot hold a non-extractable key.
var ErrUnsupported = errors.New("this computer has no supported non-extractable key store")

type mode int

const (
	modePlatform mode = iota
	modeFile
)

func selectedMode() (mode, error) {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvKeyBackend))); v {
	case "", platformBackendName:
		return modePlatform, nil
	case "file":
		if err := fileBackendAllowed(runtime.GOOS); err != nil {
			return modePlatform, err
		}
		return modeFile, nil
	default:
		return modePlatform, fmt.Errorf("%s=%q is not a key backend (use %q, or \"file\" for an extractable key file)",
			EnvKeyBackend, v, platformBackendName)
	}
}

// fileBackendAllowed refuses the key file where a file mode cannot make it
// private. On Windows, 0600 is not an access-control list: the mode sets only
// the read-only attribute, and the file takes its directory's inherited ACL,
// which may grant other accounts read access. A key file readable by another
// account is that account's credential too.
func fileBackendAllowed(goos string) error {
	if goos == "windows" {
		return fmt.Errorf("%s=file is not supported on Windows: a key file there cannot be restricted to you, and whoever can read it can use your credential — leave %s unset to use Windows key storage",
			EnvKeyBackend, EnvKeyBackend)
	}
	return nil
}

// Open loads the existing device key. ErrNoKey when there is none.
func Open() (Device, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	m, err := selectedMode()
	if err != nil {
		return nil, err
	}
	if m == modeFile {
		return openFile(dir)
	}
	return platformOpen(dir)
}

// OpenOrCreate loads the device key, creating one on first use. The second
// return reports whether it was created.
func OpenOrCreate() (Device, bool, error) {
	d, err := Open()
	if err == nil {
		return d, false, nil
	}
	if !errors.Is(err, ErrNoKey) {
		return nil, false, err
	}
	dir, err := config.Dir()
	if err != nil {
		return nil, false, err
	}
	m, err := selectedMode()
	if err != nil {
		return nil, false, err
	}
	if m == modeFile {
		d, err = createFile(dir)
	} else {
		d, err = platformCreate(dir)
	}
	if err != nil {
		return nil, false, err
	}
	return d, true, nil
}

// Delete removes the device key from every backend that holds one. Every
// credential bound to it stops working — a replacement key has a different
// thumbprint and cannot be made to match.
func Delete() error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	return errors.Join(deleteFile(dir), platformDelete(dir))
}

// Info describes the device key without signing anything with it, except where
// Enforced says otherwise.
type Info struct {
	Exists     bool
	Backend    Backend
	Thumbprint string
	Protection string
	// Enforced is what the hardware actually enforces, where it can be asked
	// without putting a prompt on screen. Empty when it cannot be asked.
	Enforced string
	Location string
}

// Status reports on the device key.
func Status() (Info, error) {
	d, err := Open()
	if errors.Is(err, ErrNoKey) {
		return Info{}, nil
	}
	if err != nil {
		return Info{}, err
	}
	dir, err := config.Dir()
	if err != nil {
		return Info{}, err
	}
	info := Info{
		Exists:     true,
		Backend:    d.Backend(),
		Thumbprint: d.Thumbprint(),
		Protection: d.Protection(),
		Location:   dir,
	}
	if d.Backend() != BackendFile {
		info.Enforced = platformEnforced(d)
	}
	return info, nil
}
