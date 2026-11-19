package keystore

// The platform store, scoped to a directory of the caller's choosing.
//
// The device key lives in the configuration directory itself. A machine key
// kept in this computer's hardware store lives in a directory of its own under
// it, and both backends scope the key to the directory — macOS keeps the
// wrapped key's record there, Windows derives the key's name from it — so a
// machine key can neither alias the device key nor be deleted with it.

// PlatformName names this platform's non-extractable store, or "none".
func PlatformName() string { return platformBackendName }

// OpenPlatformAt loads the hardware-held key recorded in dir.
func OpenPlatformAt(dir string) (Device, error) { return platformOpen(dir) }

// CreatePlatformAt creates a hardware-held key recorded in dir. It refuses on a
// platform with no supported store: there is no fallback to a file here either.
func CreatePlatformAt(dir string) (Device, error) { return platformCreate(dir) }

// DeletePlatformAt destroys the hardware-held key recorded in dir.
func DeletePlatformAt(dir string) error { return platformDelete(dir) }
