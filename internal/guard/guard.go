// Package guard checks a built clerk-protect binary before it can ship.
//
// The binary is PUBLIC. What it carries is checked on the artifact itself,
// because checking the source is not the same question: a string can arrive
// through a dependency nobody imported by name, a module can arrive
// transitively, and debug information and build stamps are added by the build,
// not written by anyone.
//
//  1. No term from the forbidden-term list appears anywhere in the bytes.
//     The list is supplied by the caller, not compiled in — see LoadTerms.
//  2. Every linked module is on the reviewed allowlist, and none is replaced.
//  3. The artifact carries no debug information, no version-control build
//     settings, and none of the builder's file paths.
package guard

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"runtime/debug"
	"sort"
	"strings"
)

// LoadTerms reads a forbidden-term list: one term per line, blank lines and
// "#" comments ignored, each folded to lower case because Scan matches that
// way.
//
// The list is NOT compiled in, because this source is public
// (github.com/clerk/protect-cli) and a roster of internal names is the very
// thing the scan exists to keep out of what ships. The release pipeline holds
// the list and passes it in. A build with no list still checks the artifact and
// its modules, and says plainly that the term scan did not run.
func LoadTerms(r io.Reader) ([]string, error) {
	var terms []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		terms = append(terms, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(terms) == 0 {
		return nil, fmt.Errorf("the forbidden-term list is empty — a list that matches nothing passes every binary")
	}
	return terms, nil
}

// MainModule is the only main module a release may be built from.
const MainModule = "github.com/clerk/protect-cli"

// Finding is one forbidden term found in a binary.
type Finding struct {
	Term    string
	Offset  int
	Context string
}

func (f Finding) String() string {
	return fmt.Sprintf("%q at offset %d: …%s…", f.Term, f.Offset, f.Context)
}

// Redacted names a finding without naming the term or the bytes around it: what
// a PUBLIC log may carry. A release of this CLI is built in a public repository,
// so a scan that failed there would otherwise print the list — and the context
// it prints contains the term by construction. The offset is enough to find it
// again locally, with the list in hand.
func (f Finding) Redacted() string {
	return fmt.Sprintf("a forbidden term at offset %d (term and context hidden)", f.Offset)
}

// Scan returns every occurrence of any term in data.
func Scan(data []byte, terms []string) []Finding {
	lower := asciiLower(data)
	var out []Finding
	for _, term := range terms {
		needle := []byte(term)
		for from := 0; ; {
			i := bytes.Index(lower[from:], needle)
			if i < 0 {
				break
			}
			at := from + i
			out = append(out, Finding{Term: term, Offset: at, Context: printable(data, at, len(needle))})
			from = at + len(needle)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// asciiLower folds A-Z byte for byte. NOT bytes.ToLower: that decodes UTF-8,
// and a binary is mostly invalid UTF-8, each bad byte becoming a three-byte
// U+FFFD — the terms are still found, but every offset after the first bad
// byte points somewhere else, and so does the context printed beside it.
func asciiLower(data []byte) []byte {
	out := make([]byte, len(data))
	for i, c := range data {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func printable(data []byte, at, n int) string {
	lo, hi := max(0, at-24), min(len(data), at+n+24)
	b := make([]byte, 0, hi-lo)
	for _, c := range data[lo:hi] {
		if c >= 0x20 && c <= 0x7e {
			b = append(b, c)
		} else {
			b = append(b, '.')
		}
	}
	return string(b)
}

// Modules is what `go version -m` reports about a binary.
type Modules struct {
	Main     string
	Deps     []string
	Replaced []string
}

// ParseModules reads `go version -m` output.
func ParseModules(output string) (Modules, error) {
	var m Modules
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "mod":
			m.Main = fields[1]
		case "dep":
			m.Deps = append(m.Deps, fields[1])
		case "=>":
			m.Replaced = append(m.Replaced, fields[1])
		}
	}
	if err := sc.Err(); err != nil {
		return m, err
	}
	if m.Main == "" {
		return m, fmt.Errorf("no main module in go version -m output — is this a Go binary built with module support?")
	}
	return m, nil
}

// LoadAllowlist reads one module path per line; blank lines and # comments are
// ignored.
func LoadAllowlist(r io.Reader) (map[string]bool, error) {
	allow := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allow[line] = true
	}
	return allow, sc.Err()
}

// CheckModules returns every violation: a different main module, a dependency
// not on the allowlist, and any replacement at all.
func CheckModules(m Modules, allow map[string]bool) []string {
	var out []string
	if m.Main != MainModule {
		out = append(out, fmt.Sprintf("main module is %q, want %q", m.Main, MainModule))
	}
	for _, dep := range m.Deps {
		if !allow[dep] {
			out = append(out, fmt.Sprintf("module %s is linked but not in allowed-modules.txt", dep))
		}
	}
	for _, r := range m.Replaced {
		out = append(out, fmt.Sprintf("module replacement %s — a released binary must build from published modules", r))
	}
	return out
}

// CheckArtifact returns every way a built binary carries more than a release
// may: debug information, which names every function, type and source line;
// version-control build settings, which name the commit and whether the tree
// was dirty; and a build that kept the builder's file paths.
func CheckArtifact(path string) ([]string, error) {
	sections, err := DebugSections(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range sections {
		out = append(out, fmt.Sprintf("debug information: %s — build with -ldflags=-w", s))
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the build information of %s: %w", path, err)
	}
	return append(out, CheckBuildSettings(bi.Settings)...), nil
}

// CheckBuildSettings returns every build setting a release must not carry: any
// vcs stamp, and the absence of -trimpath.
func CheckBuildSettings(settings []debug.BuildSetting) []string {
	var out []string
	trimmed := false
	for _, s := range settings {
		switch {
		case s.Key == "vcs" || strings.HasPrefix(s.Key, "vcs."):
			out = append(out, fmt.Sprintf("build setting %s=%s — build with -buildvcs=false", s.Key, s.Value))
		case s.Key == "-trimpath" && s.Value == "true":
			trimmed = true
		}
	}
	if !trimmed {
		out = append(out, "built without -trimpath — the builder's file paths are in the binary")
	}
	return out
}

// DebugSections names the debug-information sections and segments of an ELF,
// Mach-O or PE binary: `.debug_*` and `.zdebug_*`, Mach-O's `__DWARF` segment
// and its `__debug_*` sections.
func DebugSections(path string) ([]string, error) {
	var found []string
	add := func(kind, name string) {
		n := strings.ToLower(name)
		if strings.HasPrefix(n, ".debug") || strings.HasPrefix(n, ".zdebug") ||
			strings.HasPrefix(n, "__debug") || strings.HasPrefix(n, "__zdebug") || n == "__dwarf" {
			found = append(found, kind+" "+name)
		}
	}
	if f, err := elf.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		for _, s := range f.Sections {
			add("section", s.Name)
		}
		return found, nil
	}
	if f, err := macho.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		for _, l := range f.Loads {
			if seg, ok := l.(*macho.Segment); ok {
				add("segment", seg.Name)
			}
		}
		for _, s := range f.Sections {
			add("section", s.Name)
		}
		return found, nil
	}
	if f, err := pe.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		for _, s := range f.Sections {
			add("section", s.Name)
		}
		return found, nil
	}
	return nil, fmt.Errorf("%s is not an ELF, Mach-O or PE binary", path)
}
