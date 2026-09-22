//go:build windows

package term

import (
	"syscall"
	"unsafe"
)

// The console calls the standard library does not export, from the same DLL it
// loads them from.
var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

const (
	enableProcessedInput            = 0x0001
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableVirtualTerminalInput      = 0x0200
	enableProcessedOutput           = 0x0001
	enableVirtualTerminalProcessing = 0x0004
)

// State is the console's modes from before MakeRaw changed them.
type State struct {
	in, out uint32
}

// MakeRaw puts the console into raw mode: keys arrive as they are pressed,
// unechoed, as the escape sequences a terminal sends, and output understands
// escape sequences too. It returns the modes Restore puts back.
func MakeRaw(in, out uintptr) (*State, error) {
	var s State
	if err := syscall.GetConsoleMode(syscall.Handle(in), &s.in); err != nil {
		return nil, err
	}
	if err := syscall.GetConsoleMode(syscall.Handle(out), &s.out); err != nil {
		return nil, err
	}
	if err := setConsoleMode(in, s.in&^(enableProcessedInput|enableLineInput|enableEchoInput)|enableVirtualTerminalInput); err != nil {
		return nil, err
	}
	if err := setConsoleMode(out, s.out|enableProcessedOutput|enableVirtualTerminalProcessing); err != nil {
		_ = setConsoleMode(in, s.in)
		return nil, err
	}
	return &s, nil
}

// Restore puts back the modes MakeRaw replaced.
func Restore(in, out uintptr, s *State) error {
	errIn := setConsoleMode(in, s.in)
	if err := setConsoleMode(out, s.out); err != nil {
		return err
	}
	return errIn
}

func setConsoleMode(h uintptr, mode uint32) error {
	if r, _, err := procSetConsoleMode.Call(h, uintptr(mode)); r == 0 {
		return err
	}
	return nil
}

// consoleScreenBufferInfo is CONSOLE_SCREEN_BUFFER_INFO: the buffer size and
// cursor position, the attributes, the visible window, and its largest size.
type consoleScreenBufferInfo struct {
	sizeX, sizeY                           int16
	cursorX, cursorY                       int16
	attributes                             uint16
	windowLeft, windowTop                  int16
	windowRight, windowBottom              int16
	maximumWindowSizeX, maximumWindowSizeY int16
}

// Size is the console window's width and height, in cells.
func Size(out uintptr) (width, height int, err error) {
	var info consoleScreenBufferInfo
	if r, _, err := procGetConsoleScreenBufferInfo.Call(out, uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, 0, err
	}
	return int(info.windowRight-info.windowLeft) + 1, int(info.windowBottom-info.windowTop) + 1, nil
}
