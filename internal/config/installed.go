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
