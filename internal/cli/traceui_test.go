package cli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/term/termtest"
)

// screen collects what a command drew on a pseudo-terminal.
type screen struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *screen) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.String(), want) {
		if time.Now().After(deadline) {
			drawn := s.String()
			if len(drawn) > 2000 {
				drawn = drawn[len(drawn)-2000:]
			}
			t.Fatalf("the screen never showed %q; it ends:\n%q", want, drawn)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The interactive view on a real terminal: it takes raw mode and the alternate
// screen, draws what the stream carries — without letting a decision's text
// control the terminal — quits on q, and leaves the terminal exactly as it
// found it. Skipped where there is no pseudo-terminal.
func TestTraceView_runsOnATerminalAndPutsItBack(t *testing.T) {
	f := newFakeAPI(t)
	f.signIn(t)
	f.mux.HandleFunc("GET /labs/api/trace/columns", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, 200, traceColumnsJSON)
	})
	f.mux.HandleFunc("GET /labs/api/trace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: status\ndata: {\"engines\":2,\"connected\":2}\n\n"+
			"event: decision\ndata: {\"decision\":\"DENY\",\"ip\":\"10.0.0.1\\u001b]52;c;ZXZpbA==\\u0007\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})

	controller, tty := termtest.OpenPTY(t)
	termtest.SetSize(t, tty, 100, 30)
	before := termtest.LocalFlags(t, tty)

	var drawn screen
	go func() { _, _ = io.Copy(&drawn, controller) }()

	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(""), &out, &errOut, func() bool { return true })
	a.traceTTY = func() (*os.File, *os.File) { return tty, tty }
	done := make(chan int, 1)
	go func() { done <- a.execute([]string{"--api-url", f.srv.URL, "trace"}) }()

	drawn.waitFor(t, "10.0.0.1")
	drawn.waitFor(t, "LIVE")
	if _, err := controller.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("trace exited %d: %s", code, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("q did not end the view")
	}
	drawn.waitFor(t, "\x1b[?1049l")

	all := drawn.String()
	if !strings.Contains(all, "\x1b[?1049h") {
		t.Error("the view did not take the alternate screen")
	}
	if strings.Contains(all, "\x1b]52") || strings.Contains(all, "\x07") {
		t.Error("a decision's text reached the terminal as a control sequence")
	}
	if after := termtest.LocalFlags(t, tty); after != before {
		t.Errorf("the terminal was not put back: local modes %#x, were %#x", after, before)
	}
	if out.Len() != 0 {
		t.Errorf("the view wrote to standard output as well as the terminal: %q", out.String())
	}
}
