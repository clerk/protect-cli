// Package termtest opens pseudo-terminals for tests on the platforms that have
// them, and skips the test elsewhere. Only tests import it, so none of it
// reaches the binary.
//
// It lives under internal/term because its platform files are darwin- and
// linux-constrained, and CI's darwin leg lints darwin-constrained code only
// under internal/keystore and internal/term — a darwin file anywhere else would
// be linted by no leg, and the Makefile's lint-darwin-ci refuses one.
package termtest
