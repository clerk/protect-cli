package guard

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// testTerms stands in for the list the release pipeline supplies. The real one
// is not in this repository — that is the point of LoadTerms — so these are
// invented names with the shapes a real list has: a bare word, a host, and a
// role string.
var testTerms = []string{"widgetworks", "internal.example", "acme:admin"}

// NEGATIVE CONTROL: every term is found, in any case, anywhere in the bytes.
// Without this, a scanner that matched nothing would pass the release check
// below and prove nothing.
func TestScan_findsEveryForbiddenTerm(t *testing.T) {
	for _, term := range testTerms {
		data := []byte("\x00\x01 some binary noise " + strings.ToUpper(term) + " \xff more noise")
		found := Scan(data, testTerms)
		if len(found) != 1 || found[0].Term != term {
			t.Errorf("Scan did not find %q: %v", term, found)
		}
	}
}

// NEGATIVE CONTROL on a real file, the way the release check reads one.
func TestScan_findsATermInAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-binary")
	if err := os.WriteFile(path, []byte("prefix\x00https://api.widgetworks.test/\x00suffix"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := Scan(data, testTerms); len(got) != 1 || got[0].Term != "widgetworks" {
		t.Fatalf("Scan = %v", got)
	}
}

// A binary is mostly invalid UTF-8. The offset and context must still point at
// the term, or a finding cannot be traced back to what put it there.
func TestScan_offsetsSurviveInvalidUTF8(t *testing.T) {
	data := []byte(strings.Repeat("\xff\xfe\x80", 40) + "WiDgEtWoRkS" + "\xc3")
	found := Scan(data, testTerms)
	if len(found) != 1 {
		t.Fatalf("Scan = %v", found)
	}
	if want := strings.Index(string(data), "WiDgEtWoRkS"); found[0].Offset != want {
		t.Fatalf("offset %d, want %d", found[0].Offset, want)
	}
	if !strings.Contains(found[0].Context, "WiDgEtWoRkS") {
		t.Fatalf("context %q does not show the term", found[0].Context)
	}
}

func TestScan_cleanInputFindsNothing(t *testing.T) {
	if got := Scan([]byte("https://dashboard.protect.clerk.com/labs/api/rulesets"), testTerms); len(got) != 0 {
		t.Fatalf("Scan = %v", got)
	}
}

// A public release log must not carry the list. Redacted is what it prints, so
// it must name neither the term nor the context — which contains the term.
func TestFindingRedacted_namesNeitherTheTermNorItsContext(t *testing.T) {
	found := Scan([]byte("noise widgetworks noise"), testTerms)
	if len(found) != 1 {
		t.Fatalf("Scan = %v", found)
	}
	redacted := found[0].Redacted()
	if strings.Contains(redacted, "widgetworks") || strings.Contains(redacted, found[0].Context) {
		t.Fatalf("Redacted = %q, which shows the term or its context", redacted)
	}
	if !strings.Contains(redacted, "6") { // the offset, which is what makes it findable
		t.Fatalf("Redacted = %q, which does not give the offset", redacted)
	}
	// CONTROL: String does show them, or a private run would be useless.
	if shown := found[0].String(); !strings.Contains(shown, "widgetworks") {
		t.Fatalf("String = %q, which does not name the term", shown)
	}
}

func TestLoadTerms_readsAListAndFoldsIt(t *testing.T) {
	terms, err := LoadTerms(strings.NewReader("# a comment\n\n  WidgetWorks \nwidgetworks\ninternal.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(terms) != 2 || terms[0] != "widgetworks" || terms[1] != "internal.example" {
		t.Fatalf("LoadTerms = %v, want the two terms once each, lower case", terms)
	}
}

// A list that matches nothing passes every binary, so an empty one is an error
// rather than a scan that quietly checks nothing.
func TestLoadTerms_refusesAnEmptyList(t *testing.T) {
	if _, err := LoadTerms(strings.NewReader("# only comments\n\n")); err == nil {
		t.Fatal("LoadTerms accepted a list with no terms")
	}
}

// NEGATIVE CONTROL for the module check: an unlisted module, a replacement and a
// foreign main module are each reported.
func TestCheckModules_reportsEveryViolation(t *testing.T) {
	m := Modules{
		Main:     "example.com/something-else",
		Deps:     []string{"github.com/spf13/cobra", "github.com/aws/aws-sdk-go-v2"},
		Replaced: []string{"../local/checkout"},
	}
	got := CheckModules(m, map[string]bool{"github.com/spf13/cobra": true})
	if len(got) != 3 {
		t.Fatalf("CheckModules = %v, want three violations", got)
	}
	if clean := CheckModules(Modules{Main: MainModule, Deps: []string{"github.com/spf13/cobra"}}, map[string]bool{"github.com/spf13/cobra": true}); len(clean) != 0 {
		t.Fatalf("control: a clean module list reported %v", clean)
	}
}

func TestParseModules(t *testing.T) {
	out := "/tmp/clerk-protect: go1.26.5\n" +
		"\tpath\tgithub.com/clerk/protect-cli/cmd/clerk-protect\n" +
		"\tmod\tgithub.com/clerk/protect-cli\t(devel)\t\n" +
		"\tdep\tgithub.com/spf13/cobra\tv1.10.2\th1:abc=\n" +
		"\tdep\tgithub.com/example/replaced\tv1.0.0\n" +
		"\t=>\t../replaced\t(devel)\n" +
		"\tbuild\t-trimpath=true\n"
	m, err := ParseModules(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Main != MainModule || len(m.Deps) != 2 || len(m.Replaced) != 1 {
		t.Fatalf("ParseModules = %+v", m)
	}
}

// NEGATIVE CONTROL for the build settings: every vcs stamp and a missing
// -trimpath are each reported, and a release build's settings are not.
func TestCheckBuildSettings_reportsVCSStampsAndUntrimmedPaths(t *testing.T) {
	stamped := []debug.BuildSetting{
		{Key: "-buildmode", Value: "exe"},
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: "ec6492459145f0bef65da1d0942f3e2a9fc58329"},
		{Key: "vcs.time", Value: "2026-08-24T08:02:28Z"},
		{Key: "vcs.modified", Value: "true"},
	}
	if got := CheckBuildSettings(stamped); len(got) != 5 {
		t.Fatalf("CheckBuildSettings = %v, want four vcs settings and the missing -trimpath", got)
	}
	release := []debug.BuildSetting{{Key: "-buildmode", Value: "exe"}, {Key: "-trimpath", Value: "true"}, {Key: "CGO_ENABLED", Value: "0"}}
	if got := CheckBuildSettings(release); len(got) != 0 {
		t.Fatalf("control: a release build's settings reported %v", got)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s", root)
	}
	return root
}

type target struct{ goos, goarch string }

// releaseTargets are the platforms the release check builds and scans.
//
// darwin is built for this Mac's own architecture only: its Secure Enclave shim
// is a Swift static library compiled for the host, so the other darwin
// architecture would need a cross-compiled shim this build does not make.
// darwin/amd64 is therefore not scanned on an Apple silicon Mac, nor
// darwin/arm64 on an Intel one.
func releaseTargets() []target {
	targets := []target{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}}
	if runtime.GOOS == "darwin" {
		targets = append(targets, target{"darwin", runtime.GOARCH})
	}
	return targets
}

// versionFlag stands in for the Makefile's version stamp.
const versionFlag = "-X github.com/clerk/protect-cli/internal/version.Version=guard-test"

// build compiles cmd/clerk-protect for a target. release adds -s -w, as the
// Makefile's RELEASE_FLAGS do; -trimpath and -buildvcs=false are always on, so a
// non-release build differs from a release one only in carrying debug
// information.
func build(t *testing.T, root string, tg target, release bool) string {
	t.Helper()
	ldflags := versionFlag
	if release {
		ldflags = "-s -w " + ldflags
	}
	out := filepath.Join(t.TempDir(), "clerk-protect")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags="+ldflags, "-o", out, "./cmd/clerk-protect")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+tg.goos, "GOARCH="+tg.goarch)
	if tg.goos != "darwin" {
		cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	}
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s/%s: %v\n%s", tg.goos, tg.goarch, err, msg)
	}
	return out
}

// The release check, on real binaries built the way the Makefile builds them.
// `make binary` runs the same checks on the artifact it installs.
func TestReleaseBinaries_areCleanOnEveryCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("builds release binaries")
	}
	root := moduleRoot(t)
	f, err := os.Open(filepath.Join(root, "allowed-modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	allow, err := LoadAllowlist(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	// The forbidden-term list is not part of this module's public source. Where
	// the release pipeline keeps it beside the module, scan for it too; where it
	// does not, say so rather than letting a silent skip read as a clean scan.
	var terms []string
	if tf, err := os.Open(filepath.Join(root, "forbidden-terms.txt")); err == nil {
		terms, err = LoadTerms(tf)
		_ = tf.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("scanning for %d forbidden terms", len(terms))
	} else {
		t.Log("no forbidden-terms.txt beside the module: the term scan did not run, only the artifact and module checks")
	}

	for _, tg := range releaseTargets() {
		t.Run(tg.goos+"-"+tg.goarch, func(t *testing.T) {
			bin := build(t, root, tg, true)
			data, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range Scan(data, terms) {
				t.Errorf("forbidden term: %s", f)
			}
			problems, err := CheckArtifact(bin)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				t.Errorf("artifact: %s", p)
			}
			version, err := exec.Command("go", "version", "-m", bin).CombinedOutput()
			if err != nil {
				t.Fatalf("go version -m: %v\n%s", err, version)
			}
			m, err := ParseModules(string(version))
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range CheckModules(m, allow) {
				t.Errorf("modules: %s", v)
			}
		})
	}
}

// NEGATIVE CONTROL for the debug-information check, on real builds in each
// binary format a release ships: a build without -w carries DWARF, and
// CheckArtifact says so. Without this, a DebugSections that recognised no
// format's section names would pass the release check above.
func TestCheckArtifact_findsDebugInformationInEveryFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	root := moduleRoot(t)
	targets := []target{{"linux", "amd64"}, {"windows", "amd64"}}
	if runtime.GOOS == "darwin" {
		targets = append(targets, target{"darwin", runtime.GOARCH})
	}
	for _, tg := range targets {
		t.Run(tg.goos, func(t *testing.T) {
			problems, err := CheckArtifact(build(t, root, tg, false))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, p := range problems {
				if strings.HasPrefix(p, "debug information:") {
					found = true
				} else {
					t.Errorf("unexpected finding: %s", p)
				}
			}
			if !found {
				t.Fatalf("a build without -w was not reported as carrying debug information: %v", problems)
			}
		})
	}
}
