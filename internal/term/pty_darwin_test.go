//go:build darwin

package term

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// openPseudoTerminal opens the terminal side of a new pseudo-terminal. On macOS
// the controlling side answers no terminal requests, so the other side is
// opened: grant it, unlock it, ask its name.
func openPseudoTerminal(t *testing.T) *os.File {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	fd := ptmx.Fd()
	for _, req := range []uintptr{syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, 0); errno != 0 {
			t.Fatalf("set up the pseudo-terminal: %v", errno)
		}
	}
	var name [128]byte
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		t.Fatalf("name the pseudo-terminal: %v", errno)
	}
	n := bytes.IndexByte(name[:], 0)
	if n < 0 {
		n = len(name)
	}
	tty, err := os.OpenFile(string(name[:n]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name[:n], err)
	}
	t.Cleanup(func() { _ = tty.Close() })
	return tty
}
