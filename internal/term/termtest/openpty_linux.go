//go:build linux

package termtest

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// OpenPTY opens a pseudo-terminal: the controlling side, which a test writes
// keys to and reads the screen from, and the terminal side a command runs on.
// On Linux the terminal side is unlocked, then opened by its number.
func OpenPTY(t testing.TB) (controller, tty *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	fd := ptmx.Fd()
	var unlock int32
	if err := ioctl(fd, syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		t.Fatalf("unlock the pseudo-terminal: %v", err)
	}
	var n uint32
	if err := ioctl(fd, syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		t.Fatalf("number the pseudo-terminal: %v", err)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	tty, err = os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	t.Cleanup(func() { _ = tty.Close() })
	return ptmx, tty
}

// LocalFlags reads a terminal's local modes: line editing, echo, signals.
func LocalFlags(t testing.TB, f *os.File) uint64 {
	t.Helper()
	var tio syscall.Termios
	if err := ioctl(f.Fd(), syscall.TCGETS, unsafe.Pointer(&tio)); err != nil {
		t.Fatalf("read the terminal's settings: %v", err)
	}
	return uint64(tio.Lflag)
}
