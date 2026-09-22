//go:build !darwin && !windows

package keystore

import "fmt"

// No hardware key store is supported on this platform yet. Every platform call
// refuses and names the explicit opt-in, rather than falling back to a key file
// the person never chose.
const platformBackendName = "none"

func unsupported() error {
	return fmt.Errorf("%w: set %s=file to use a key file instead — it is extractable, so anyone who can read it can use your credential",
		ErrUnsupported, EnvKeyBackend)
}

func platformOpen(string) (Device, error)   { return nil, unsupported() }
func platformCreate(string) (Device, error) { return nil, unsupported() }
func platformDelete(string) error           { return nil }
func platformEnforced(Device) string        { return "" }
