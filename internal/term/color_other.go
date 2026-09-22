//go:build !windows

package term

// EnableColor reports whether the terminal behind fd will interpret colour
// sequences. Terminals outside Windows do, with nothing to switch on.
func EnableColor(uintptr) bool { return true }
