//go:build linux

package term

import (
	"syscall"
	"unsafe"
)

// The requests that read and write a terminal's settings.
const (
	ioctlGetTermios = syscall.TCGETS
	ioctlSetTermios = syscall.TCSETS
)

// IsTerminal reports whether fd is a terminal: whether the terminal driver
// answers TCGETS, the request for its settings.
func IsTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
