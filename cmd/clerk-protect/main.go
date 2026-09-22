// Command clerk-protect manages Clerk Protect for your instance from the
// command line.
package main

import (
	"os"

	"github.com/clerk/protect-cli/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
