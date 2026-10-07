package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// InstalledPointer is the file under an installed-config store that names the
// installed snapshot: one line, "sha256:<hex>\n". Absent means nothing is
// installed — a fresh control root, or an operator who removed it on purpose
// to re-bootstrap. The store itself sits beside the control ledger; the CLI
// derives its path, this package only reads and writes it.
const InstalledPointer = "current"

// installedHashRE is the only pointer content ever honored. Anything else is
// a fault to fail closed on, never "nothing installed": a damaged pointer
// must not silently re-open the bootstrap permit.
var installedHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// InstalledHash reads the pointer. installed=false with a nil error means the
// pointer is absent; a present-but-malformed pointer is an error.
func InstalledHash(store string) (hash string, installed bool, err error) {
	p := filepath.Join(store, InstalledPointer)
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("installed config: %w", err)
	}
	hash = strings.TrimSpace(string(raw))
	if !installedHashRE.MatchString(hash) {
		return "", false, fmt.Errorf("installed config: %s: malformed pointer (want sha256:<hex>)", p)
	}
	return hash, true, nil
}

// snapshotDir is where the snapshot named by hash lives: the bare hex digest.
// The "sha256:" prefix is the pointer's typed form, not a directory name.
func snapshotDir(store, hash string) string {
	return filepath.Join(store, strings.TrimPrefix(hash, "sha256:"))
}

// InstalledRoles reads the installed snapshot's roles and nothing else — a
// lenient, roles-only read, never Build: agent and gateway files are not even
// parsed, so a snapshot written under older load rules still decides who may
// change it. A roles file that cannot be read or parsed, or a pointer naming
// a snapshot that is gone, fails closed with an error naming the snapshot;
// the caller states the escape hatch (remove the pointer; re-bootstrap).
func InstalledRoles(store string) (roles []RoleDef, hash string, installed bool, err error) {
	hash, installed, err = InstalledHash(store)
	if err != nil || !installed {
		return nil, "", installed, err
	}
	cfg, errs := loadFiles(snapshotDir(store, hash), func(rel string) bool { return path.Dir(rel) == "roles" })
	if len(errs) > 0 {
		return nil, hash, true, fmt.Errorf("installed config %s: %w", hash, errs[0])
	}
	return cfg.Roles, hash, true, nil
}

// StageSnapshot copies the configuration at src into a fresh temporary
// directory under store and returns that directory. The copy is by the
// configFiles enumeration — exactly the files LoadDir reads and HashDir
// hashes, at the same relative paths — so HashDir(copy) == HashDir(src) by
// construction, and a nested store, a README, or a yaml in an unknown
// subdirectory is never snapshotted. It is one read of the bytes: the caller
// validates, hashes, and installs the copy, never the live directory, so what
// is recorded is what was checked. On any failure the temp is removed and
// nothing under store changes; an unreadable source file errors as
// "<rel>: <cause>", the same shape LoadDir reports.
func StageSnapshot(store, src string) (temp string, err error) {
	files, err := configFiles(src)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(store, 0o700); err != nil {
		return "", fmt.Errorf("installed config: %w", err)
	}
	temp, err = os.MkdirTemp(store, ".staging-*")
	if err != nil {
		return "", fmt.Errorf("installed config: %w", err)
	}
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(rel)))
		if err != nil {
			_ = os.RemoveAll(temp)
			return "", fmt.Errorf("%s: %w", rel, err)
		}
		dst := filepath.Join(temp, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			_ = os.RemoveAll(temp)
			return "", fmt.Errorf("installed config: %w", err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			_ = os.RemoveAll(temp)
			return "", fmt.Errorf("installed config: %w", err)
		}
	}
	return temp, nil
}

// CommitSnapshot installs the staged copy at temp as the snapshot named by
// hash (which the caller computed over temp) and flips the pointer to it.
// The snapshot directory is content-addressed, so a rename that finds it
// already present (EEXIST or ENOTEMPTY — both satisfy errors.Is(err,
// fs.ErrExist)) means identical bytes are installed already; the temp is
// then simply discarded. The pointer is written to a sibling temp file,
// fsync'd, renamed over InstalledPointer, and the store directory is fsync'd
// — the same durability order the ledger uses. Invariant: an error return
// leaves the pointer exactly as it was; a snapshot directory left behind by
// a failure after the rename is inert (a prune is reserved).
func CommitSnapshot(store, temp, hash string) error {
	if !installedHashRE.MatchString(hash) {
		return fmt.Errorf("installed config: refusing to install under malformed hash %q", hash)
	}
	if err := os.Rename(temp, snapshotDir(store, hash)); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("installed config: %w", err)
		}
		if err := os.RemoveAll(temp); err != nil {
			return fmt.Errorf("installed config: %w", err)
		}
	}
	f, err := os.CreateTemp(store, ".current-*")
	if err != nil {
		return fmt.Errorf("installed config: %w", err)
	}
	tmpPath := f.Name()
	_, werr := f.WriteString(hash + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmpPath, filepath.Join(store, InstalledPointer))
	}
	if werr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("installed config: %w", werr)
	}
	if d, derr := os.Open(store); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
