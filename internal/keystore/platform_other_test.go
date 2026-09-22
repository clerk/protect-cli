//go:build !darwin && !windows

package keystore

import (
	"errors"
	"testing"
)

// With no hardware key store, the platform path refuses — it does not quietly
// create a key file.
func TestPlatform_refusesWithoutAnExplicitOptIn(t *testing.T) {
	isolate(t)
	t.Setenv(EnvKeyBackend, "")
	if _, _, err := OpenOrCreate(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("OpenOrCreate = %v, want ErrUnsupported", err)
	}
}
