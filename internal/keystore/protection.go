package keystore

import (
	"fmt"
	"strings"
)

// Protection is the Mac policy on a Secure Enclave key: whether the enclave
// itself demands Touch ID (or the device password) before signing.
type Protection string

const (
	// ProtectionSilent signs whenever the Mac is unlocked. Still
	// non-extractable. THE DEFAULT, because every request this CLI makes is
	// signed: a policy that prompts is a prompt per command, and one a script
	// or scheduled job cannot answer at all.
	ProtectionSilent Protection = "silent"

	// ProtectionPresence makes the enclave refuse to sign until you touch the
	// sensor or type the device password — once per command, because one
	// authentication covers the whole process. For people who want a physical
	// confirmation in front of every use of the credential.
	ProtectionPresence Protection = "presence"

	// ProtectionAuto is presence when Touch ID is enrolled, silent otherwise.
	ProtectionAuto Protection = "auto"
)

// ParseProtection validates a policy name. Empty is the default, silent.
func ParseProtection(s string) (Protection, error) {
	switch Protection(strings.ToLower(strings.TrimSpace(s))) {
	case "", ProtectionSilent:
		return ProtectionSilent, nil
	case ProtectionPresence:
		return ProtectionPresence, nil
	case ProtectionAuto:
		return ProtectionAuto, nil
	default:
		return "", fmt.Errorf("unknown key protection %q (want silent, presence or auto)", s)
	}
}
