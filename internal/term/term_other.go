//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package term

// IsTerminal reports false on a platform with no terminal check here — Solaris,
// illumos and AIX among them — so a change refuses without --yes rather than
// waiting on a prompt. Those platforms have no key storage but the opt-in file
// backend either.
func IsTerminal(uintptr) bool { return false }
