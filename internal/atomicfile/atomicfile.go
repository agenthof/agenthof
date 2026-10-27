// Package atomicfile is the one atomic-replace recipe the ledger-adjacent
// writers share: a 0600 temp beside the destination, fsynced and closed,
// renamed over the destination, the directory fsynced.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Replace writes data to dest by temp+fsync+rename: a 0600 temp beside dest
// (named by pattern, as os.CreateTemp reads it) holding data, fsynced and
// closed, renamed over dest, the directory fsynced. On any failure before the
// rename the temp is removed.
func Replace(dest, pattern string, data []byte) error {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, dest); err != nil {
		_ = os.Remove(name)
		return err
	}
	SyncDir(dir)
	return nil
}

// SyncDir makes a rename or link in dir durable; best effort, as ledger.Open's.
func SyncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
