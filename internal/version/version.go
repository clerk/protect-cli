// Package version carries the release version, stamped at build time with
// -ldflags "-X github.com/clerk/protect-cli/internal/version.Version=...".
package version

// Version is "dev" for a build that was not stamped.
var Version = "dev"
