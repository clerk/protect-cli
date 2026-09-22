//go:build darwin

package termtest

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// OpenPTY opens a pseudo-terminal: the controlling side, which a test writes
// keys to and reads the screen from, and the terminal side a command runs on.
// On macOS the controlling side answers no terminal requests, so the terminal
// side is granted, unlocked and opened by name.
func OpenPTY(t testing.TB) (controller, tty *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	fd := ptmx.Fd()
	for _, req := range []uintptr{syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		if err := ioctl(fd, req, nil); err != nil {
			t.Fatalf("set up the pseudo-terminal: %v", err)
		}
	}
	var name [128]byte
	if err := ioctl(fd, syscall.TIOCPTYGNAME, unsafe.Pointer(&name[0])); err != nil {
		t.Fatalf("name the pseudo-terminal: %v", err)
	}
	n := bytes.IndexByte(name[:], 0)
	if n < 0 {
		n = len(name)
	}
	tty, err = os.OpenFile(string(name[:n]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name[:n], err)
	}
	t.Cleanup(func() { _ = tty.Close() })
	return ptmx, tty
}

// LocalFlags reads a terminal's local modes: line editing, echo, signals.
func LocalFlags(t testing.TB, f *os.File) uint64 {
	t.Helper()
	var tio syscall.Termios
	if err := ioctl(f.Fd(), syscall.TIOCGETA, unsafe.Pointer(&tio)); err != nil {
		t.Fatalf("read the terminal's settings: %v", err)
	}
	return tio.Lflag
}
