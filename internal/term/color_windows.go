//go:build windows

package term

import "syscall"

// EnableColor asks the console behind fd to interpret escape sequences, which
// is what colour is made of, and reports whether it will. A Windows console
// shows them as text until virtual-terminal processing is on; one too old to
// support it refuses the mode, and the caller then writes no colour at all.
func EnableColor(fd uintptr) bool {
	var mode uint32
	if err := syscall.GetConsoleMode(syscall.Handle(fd), &mode); err != nil {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	return setConsoleMode(fd, mode|enableProcessedOutput|enableVirtualTerminalProcessing) == nil
}
