//go:build !darwin && !linux

package termtest

import (
	"os"
	"runtime"
	"testing"
)

// OpenPTY skips the test: there is no pseudo-terminal support here.
func OpenPTY(t testing.TB) (controller, tty *os.File) {
	t.Helper()
	t.Skipf("no pseudo-terminal support on %s", runtime.GOOS)
	return nil, nil
}

// LocalFlags skips the test, as OpenPTY does.
func LocalFlags(t testing.TB, _ *os.File) uint64 {
	t.Helper()
	t.Skipf("no pseudo-terminal support on %s", runtime.GOOS)
	return 0
}

// SetSize skips the test, as OpenPTY does.
func SetSize(t testing.TB, _ *os.File, _, _ uint16) {
	t.Helper()
	t.Skipf("no pseudo-terminal support on %s", runtime.GOOS)
}
