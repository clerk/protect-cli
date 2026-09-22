// Command guardscan runs the release checks on built clerk-protect binaries: no
// forbidden term in the bytes, only reviewed modules linked, and no debug
// information, vcs build settings or builder paths in the artifact.
//
//	go run ./tools/guardscan -allowlist allowed-modules.txt -terms terms.txt clerk-protect
//
// -terms is optional: without it the forbidden-term scan does not run, and the
// result line says so rather than reading as a clean scan.
//
// A FINDING DOES NOT PRINT THE TERM unless -show-terms is passed. The list is
// private, and the loudest place this runs is a release: a public repository's
// Actions log showing "forbidden term \"<name>\" at offset N: …<name>…" would
// publish the roster and the context around it, which is the whole thing the
// list exists to keep out of what ships. Locally, with the list in hand, pass
// -show-terms to see which term and where.
//
// Exit 1 when any binary fails a check, 2 when a check could not run.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/clerk/protect-cli/internal/guard"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func main() {
	allowlist := flag.String("allowlist", "allowed-modules.txt", "reviewed module allowlist")
	termsFile := flag.String("terms", "", "forbidden-term list; without it that check does not run")
	showTerms := flag.Bool("show-terms", false, "print the term and its context in a finding; off by default so a public log cannot carry the list")
	flag.Parse()
	if flag.NArg() == 0 {
		fatal("usage: guardscan -allowlist FILE BINARY...")
	}
	f, err := os.Open(*allowlist)
	if err != nil {
		fatal("%v", err)
	}
	allow, err := guard.LoadAllowlist(f)
	_ = f.Close()
	if err != nil {
		fatal("%v", err)
	}

	var terms []string
	if *termsFile != "" {
		tf, err := os.Open(*termsFile)
		if err != nil {
			fatal("%v", err)
		}
		terms, err = guard.LoadTerms(tf)
		_ = tf.Close()
		if err != nil {
			fatal("%v", err)
		}
	}

	anyFailed := false
	for _, bin := range flag.Args() {
		var problems []string
		data, err := os.ReadFile(bin)
		if err != nil {
			fatal("%v", err)
		}
		for _, finding := range guard.Scan(data, terms) {
			if *showTerms {
				problems = append(problems, "forbidden term "+finding.String())
				continue
			}
			problems = append(problems, finding.Redacted()+" — rerun with -show-terms, and the list, to see which")
		}
		out, err := exec.Command("go", "version", "-m", bin).CombinedOutput()
		if err != nil {
			fatal("go version -m %s: %v\n%s", bin, err, out)
		}
		mods, err := guard.ParseModules(string(out))
		if err != nil {
			fatal("%v", err)
		}
		problems = append(problems, guard.CheckModules(mods, allow)...)
		artifact, err := guard.CheckArtifact(bin)
		if err != nil {
			fatal("%v", err)
		}
		problems = append(problems, artifact...)

		if len(problems) == 0 {
			termResult := fmt.Sprintf("no forbidden term of %d", len(terms))
			if len(terms) == 0 {
				termResult = "forbidden terms NOT SCANNED (no -terms list)"
			}
			fmt.Printf("%s: ok (%d modules linked, all reviewed; %s; no debug information or vcs stamp)\n", bin, len(mods.Deps), termResult)
			continue
		}
		anyFailed = true
		for _, p := range problems {
			fmt.Printf("%s: %s\n", bin, p)
		}
	}
	if anyFailed {
		os.Exit(1)
	}
}
