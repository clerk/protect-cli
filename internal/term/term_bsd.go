//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package term

import (
	"syscall"
	"unsafe"
)

// The requests that read and write a terminal's settings.
const (
	ioctlGetTermios = syscall.TIOCGETA
	ioctlSetTermios = syscall.TIOCSETA
)

// IsTerminal reports whether fd is a terminal: whether the terminal driver
// answers TIOCGETA, the request for its settings.
func IsTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGETA, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
