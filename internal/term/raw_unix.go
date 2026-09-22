//go:build darwin || dragonfly || freebsd || netbsd || openbsd || linux

package term

import (
	"syscall"
	"unsafe"
)

// State is a terminal's settings from before MakeRaw changed them.
type State struct {
	termios syscall.Termios
}

// MakeRaw puts the terminal on in into raw mode — each key arrives as it is
// pressed, unechoed, and Ctrl-C arrives as a byte rather than as a signal — and
// returns the settings Restore puts back. out is unused here; Windows needs it.
func MakeRaw(in, _ uintptr) (*State, error) {
	var t syscall.Termios
	if err := ioctl(in, ioctlGetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	old := t
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := ioctl(in, ioctlSetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return &State{termios: old}, nil
}

// Restore puts back the settings MakeRaw replaced.
func Restore(in, _ uintptr, s *State) error {
	return ioctl(in, ioctlSetTermios, unsafe.Pointer(&s.termios))
}

// Size is the terminal's width and height, in cells.
func Size(out uintptr) (width, height int, err error) {
	var ws struct{ Row, Col, Xpixel, Ypixel uint16 }
	if err := ioctl(out, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	return int(ws.Col), int(ws.Row), nil
}

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}
