//go:build linux

package term

import (
	"os"
	"syscall"
	"testing"
)

// openPseudoTerminal opens a new pseudo-terminal's controlling side, which on
// Linux answers terminal requests on behalf of its terminal side.
func openPseudoTerminal(t *testing.T) *os.File {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	return ptmx
}
