// Package fsutil holds the one file-writing primitive every stored credential
// and key record goes through.
package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path through a temporary file in the same
// directory and a rename, creating the directory with mode 0700.
//
// ATOMIC BECAUSE A HALF-WRITTEN KEY RECORD IS UNRECOVERABLE. The Secure Enclave
// cannot re-derive a key whose wrapped blob was truncated by a crash mid-write,
// and a truncated credential file reads as corruption rather than as "sign in
// again". The rename either lands the whole file or leaves the previous one.
//
// The temporary file is created 0600 before any byte is written, so there is no
// window in which a secret sits in a world-readable file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
