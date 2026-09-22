//go:build windows

package term

import "syscall"

// IsTerminal reports whether fd is a console: whether Windows answers a
// request for its console mode. A redirected handle — a file, a pipe, NUL — has
// none.
func IsTerminal(fd uintptr) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(fd), &mode) == nil
}
