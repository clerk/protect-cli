//go:build !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !linux && !windows

package term

import "errors"

// ErrNoRawMode means this platform has no raw terminal mode here; callers fall
// back to plain output.
var ErrNoRawMode = errors.New("no interactive terminal support on this platform")

// State is empty where there is no raw mode.
type State struct{}

// MakeRaw is not available on this platform.
func MakeRaw(uintptr, uintptr) (*State, error) { return nil, ErrNoRawMode }

// Restore has nothing to restore on this platform.
func Restore(uintptr, uintptr, *State) error { return nil }

// Size is not available on this platform.
func Size(uintptr) (int, int, error) { return 0, 0, ErrNoRawMode }
