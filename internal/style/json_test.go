package style

import (
	"strings"
	"testing"
)

func TestJSON_coloursTokensAndStripsFirst(t *testing.T) {
	in := "{\n  \"key\": \"va\\\"l\x1b]0;x\x07\",\n  \"n\": -1.5,\n  \"b\": [true, null]\n}\n"
	got := string(New(true).JSON(in))
	for _, want := range []string{
		"\x1b[36m\"key\"\x1b[0m", "\x1b[32m\"va\\\"l]0;x\"\x1b[0m",
		"\x1b[33m-1.5\x1b[0m", "\x1b[33mtrue\x1b[0m", "\x1b[33mnull\x1b[0m",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
	if want := "{\n  \"key\": \"va\\\"l]0;x\",\n  \"n\": -1.5,\n  \"b\": [true, null]\n}\n"; Visible(got) != want {
		t.Errorf("visible text changed: %q", Visible(got))
	}
	if off := string(New(false).JSON(in)); strings.Contains(off, "\x1b") {
		t.Errorf("the off palette coloured, or kept a control: %q", off)
	}
}
