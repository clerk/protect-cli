//go:build darwin || linux

package termtest

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// SetSize sets a terminal's window size, in cells.
func SetSize(t testing.TB, f *os.File, cols, rows uint16) {
	t.Helper()
	ws := struct{ Row, Col, Xpixel, Ypixel uint16 }{Row: rows, Col: cols}
	if err := ioctl(f.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
		t.Fatalf("set the window size: %v", err)
	}
}

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}
