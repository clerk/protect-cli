//go:build darwin || linux

package term

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// MakeRaw turns off line editing, echo and keyboard signals on a real terminal,
// Restore puts every setting back, and Size reads the window size the terminal
// holds.
func TestMakeRawRestoreAndSize(t *testing.T) {
	tty := openPseudoTerminal(t)
	fd := tty.Fd()
	get := func() syscall.Termios {
		t.Helper()
		var tio syscall.Termios
		if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&tio)); err != nil {
			t.Fatal(err)
		}
		return tio
	}
	before := get()
	if before.Lflag&syscall.ICANON == 0 {
		t.Skip("this pseudo-terminal starts without line editing, so raw mode would prove nothing")
	}
	saved, err := MakeRaw(fd, fd)
	if err != nil {
		t.Fatalf("MakeRaw: %v", err)
	}
	if raw := get(); raw.Lflag&(syscall.ICANON|syscall.ECHO|syscall.ISIG) != 0 {
		t.Fatalf("still cooked after MakeRaw: lflag %#x", raw.Lflag)
	}
	if err := Restore(fd, fd, saved); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if after := get(); after.Lflag != before.Lflag || after.Iflag != before.Iflag || after.Oflag != before.Oflag || after.Cflag != before.Cflag {
		t.Fatalf("Restore did not put the settings back: lflag %#x, was %#x", after.Lflag, before.Lflag)
	}

	ws := struct{ Row, Col, Xpixel, Ypixel uint16 }{Row: 33, Col: 111}
	if err := ioctl(fd, syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
		t.Fatalf("set the window size: %v", err)
	}
	if w, h, err := Size(fd); err != nil || w != 111 || h != 33 {
		t.Fatalf("Size = %d×%d, %v; want 111×33", w, h, err)
	}
}

// Something that is not a terminal is refused raw mode, not half-changed.
func TestMakeRaw_refusesAFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-a-terminal")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := MakeRaw(f.Fd(), f.Fd()); err == nil {
		t.Fatal("MakeRaw accepted a regular file")
	}
	if _, _, err := Size(f.Fd()); err == nil {
		t.Fatal("Size answered for a regular file")
	}
}
