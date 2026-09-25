// Package version carries the release version, stamped at build time with
// -ldflags "-X github.com/clerk/protect-cli/internal/version.Version=...".
package version

import "runtime"

// Version is "dev" for a build that was not stamped.
var Version = "dev"

// Product is the product token every request names.
const Product = "clerk-protect"

// UserAgent is the User-Agent header on every request the CLI makes:
//
//	clerk-protect/v0.3.2 (darwin/arm64)
//
// A product token, the exact version it was built as, and the platform in a
// comment (RFC 9110 §10.1.5). The server reads the version to tell a CLI that
// a newer release exists, so this shape is a contract: the version is the
// release tag as built, never rounded or decorated, and "dev" for a build that
// was not stamped.
func UserAgent() string {
	return Product + "/" + Version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
