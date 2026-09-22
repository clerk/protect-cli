//go:build !darwin && !linux

package term

import (
	"os"
	"testing"
)

func openPseudoTerminal(t *testing.T) *os.File {
	t.Skip("no pseudo-terminal helper for this platform")
	return nil
}
