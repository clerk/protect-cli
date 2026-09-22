package term

import (
	"os"
	"runtime"
	"testing"
)

// /dev/null is a character device and not a terminal. It is what cron hands a
// job, so the check that confused the two prompted a job nobody could answer.
func TestIsTerminal_devNullIsNotATerminal(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	if IsTerminal(null.Fd()) {
		t.Fatalf("%s reported as a terminal", os.DevNull)
	}
	if runtime.GOOS != "windows" {
		fi, err := null.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeCharDevice == 0 {
			t.Fatalf("control: %s is not a character device here, so this test proves nothing", os.DevNull)
		}
	}
}

func TestIsTerminal_aPipeIsNotATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if IsTerminal(r.Fd()) || IsTerminal(w.Fd()) {
		t.Fatal("a pipe reported as a terminal")
	}
}

// POSITIVE CONTROL: a pseudo-terminal is a terminal. Without this, an
// IsTerminal that always said false would pass both tests above.
func TestIsTerminal_aPseudoTerminalIsATerminal(t *testing.T) {
	tty := openPseudoTerminal(t)
	if !IsTerminal(tty.Fd()) {
		t.Fatalf("pseudo-terminal %s was not reported as a terminal", tty.Name())
	}
}
