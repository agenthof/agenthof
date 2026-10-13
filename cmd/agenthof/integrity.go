package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/agenthof/agenthof/internal/config"
)

// integrityPath is the control ledger's integrity posture — sink and anchor —
// BESIDE the ledger exactly as installed.lock, signing.key and verify.pub are,
// because the posture belongs to the root the ledger lives in, not to any one
// process that writes it. Operator-written; Agenthof never writes it. Absent
// means the floor (sink local, anchor none). Derived here and nowhere else.
func integrityPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "integrity.yaml")
}

// loadIntegrity reads integrity.yaml beside controlLog. Absent is the one
// "floor" answer (zero Integrity, err nil); a present entry that cannot be
// read, does not parse, or does not validate is an error naming the file —
// never read as the floor (that would make deleting or corrupting the file a
// way to silently drop a posture) and never rewritten here. Existence is
// decided by Lstat on the entry itself, so a present-but-unreadable file —
// a dangling symlink, a bad mode — is a fault, not a missing file. Every
// control writer calls it before it touches the ledger and exits 2 on an
// error; the posture it returns is, after validation, always the floor in
// this build, so every caller discards it.
func loadIntegrity(controlLog string) (config.Integrity, error) {
	path := integrityPath(controlLog)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return config.Integrity{}, nil // no such entry (nor its whole root directory): the floor
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's *fs.PathError already names the path; keep only its
		// cause so the file is named exactly once.
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return config.Integrity{}, fmt.Errorf("integrity %s: %w", path, err)
	}
	in, err := config.ParseIntegrity(data)
	if err != nil {
		return config.Integrity{}, fmt.Errorf("integrity %s: %w", path, err)
	}
	return in, nil
}
