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

// SnapshotDir is where the snapshot named by hash lives under store: the bare
// hex digest. The "sha256:" prefix is the pointer's typed form, not a
// directory name. Exported for the kill switch, which stages a copy of the
// installed snapshot; everything else in this package uses it internally.
func SnapshotDir(store, hash string) string {
	return filepath.Join(store, strings.TrimPrefix(hash, "sha256:"))
}

// VerifyInstalled checks that the enumerated config files of the snapshot
// named by hash under store hash as hash names: HashDir over the snapshot
// directory — the same files/v1 canon and the same configFiles enumeration
// the installer used — must equal hash. nil means the files the engine would
// read are the files the pointer claims (a foreign file dropped into <hex>/
// outside the enumeration is invisible to HashDir and to loadFiles alike,
// and is neither hashed nor read). It is the ONE definition of verify-on-
// read, called by LoadInstalled (the execution read: run, serve) before any
// file is parsed, and by the kill switch before it stages a copy to
// re-install — so tampered bytes are neither executed nor re-installed under
// a new, correct name. The distribution read (SnapshotBundle) makes the
// same judgment over the bytes it returns, with the same canon, the same
// enumeration and the same mismatch text. It is not called by
// InstalledRoles, the lenient
// authorization read (docs/control-plane-lifecycle.md, honest limits). An
// unreadable snapshot is that read error; a mismatch is
// "installed config <hash>: snapshot hashes as <got>, not as its pointer".
func VerifyInstalled(store, hash string) error {
	got, err := HashDir(SnapshotDir(store, hash))
	if err != nil {
		return fmt.Errorf("installed config %s: %w", hash, err)
	}
	if got != hash {
		return fmt.Errorf("installed config %s: snapshot hashes as %s, not as its pointer", hash, got)
	}
	return nil
}

// InstalledRoles reads the installed snapshot's roles and nothing else — a
// lenient, roles-only read, never Build: agent and gateway files are not even
// parsed, so a snapshot written under older load rules still decides who may
// change it. A roles file that cannot be read or parsed, or a pointer naming
// a snapshot that is gone, fails closed with an error naming the snapshot;
// the caller states the escape hatch (remove the pointer; re-bootstrap). This
// read is not verified against the pointer (VerifyInstalled) — it is the
// authorization read, and a snapshot whose other files were edited must still
// decide who may change it (docs/control-plane-lifecycle.md, honest limits).
func InstalledRoles(store string) (roles []RoleDef, hash string, installed bool, err error) {
	hash, installed, err = InstalledHash(store)
	if err != nil || !installed {
		return nil, "", installed, err
	}
	cfg, errs := loadFiles(SnapshotDir(store, hash), func(rel string) bool { return path.Dir(rel) == "roles" })
	if len(errs) > 0 {
		return nil, hash, true, fmt.Errorf("installed config %s: %w", hash, errs[0])
	}
	// A snapshot that parses but yields no roles is damage, not a valid
	// install: every snapshot an apply installs passed the no-apply-floor, so
	// it always has at least one role. A lost roles/ subdirectory (or a <hex>
	// entry that is a file, not a directory) otherwise reads back as an empty
	// role list and silently denies everyone with a generic message. Fail
	// closed naming the snapshot, so the caller sees the fault and the escape
	// hatch, not a mystery lockout.
	if len(cfg.Roles) == 0 {
		return nil, hash, true, fmt.Errorf("installed config %s: snapshot has no roles (remove the pointer %q to re-bootstrap)", hash, filepath.Join(store, InstalledPointer))
	}
	return cfg.Roles, hash, true, nil
}

// LoadInstalled reads the WHOLE installed snapshot — every file LoadDir would
// read — for execution. installed=false with no errors means nothing is
// installed (the pointer is absent). A pointer that is present but cannot be
// honored (malformed: installed=false WITH an error — callers must test errs
// before installed), or a snapshot that is gone or no longer loads, is an
// error: fail closed. Every load error is returned, each naming the snapshot,
// because a run's refusal prints them all. A snapshot that loads but holds no
// roles is damage, not a valid install (every installed snapshot passed the
// no-apply-floor), and fails closed the same way. hash is the pointer's value,
// verbatim — never a re-hash of the directory — and the bytes under it are
// verified against it by VerifyInstalled before any file is parsed: a
// mismatch is the one error returned, and nothing is parsed. It does
// not Build: internal/registry imports this package, so validation is the
// caller's (resolveRunConfig in cmd/agenthof).
func LoadInstalled(store string) (cfg Config, hash string, installed bool, errs []error) {
	hash, installed, err := InstalledHash(store)
	if err != nil {
		return Config{}, "", false, []error{err}
	}
	if !installed {
		return Config{}, "", false, nil
	}
	// Verify before parse: bytes that do not match the pointer are never fed
	// to the YAML parser — the mismatch is the fault, whatever parse errors
	// tampered bytes would produce are noise.
	if verr := VerifyInstalled(store, hash); verr != nil {
		return Config{}, hash, true, []error{verr}
	}
	cfg, loadErrs := loadFiles(SnapshotDir(store, hash), func(string) bool { return true })
	for _, e := range loadErrs {
		errs = append(errs, fmt.Errorf("installed config %s: %w", hash, e))
	}
	if len(errs) == 0 && len(cfg.Roles) == 0 {
		errs = append(errs, fmt.Errorf("installed config %s: snapshot has no roles", hash))
	}
	return cfg, hash, true, errs
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

// StageFiles is StageSnapshot for an in-memory proposal: every key is
// checked with ValidBundlePath (fail closed, whatever the caller checked —
// the error names no key, since on the server the key is the caller's),
// then written 0600 under a fresh .staging-* temp in store, in bundleOrder,
// each file opened O_WRONLY|O_CREATE|O_EXCL — so two keys the filesystem
// considers the same name ("agents/x.yaml" and "agents/X.yaml" on a
// case-insensitive volume; NFC and NFD spellings of one name on HFS+) fail
// loud on the second instead of one silently overwriting the other. On any
// failure the temp is removed and nothing under store changes. The temp is
// what the caller validates, hashes and installs — exactly as for
// StageSnapshot.
func StageFiles(store string, files map[string][]byte) (temp string, err error) {
	for rel := range files {
		if !ValidBundlePath(rel) {
			return "", errors.New("installed config: proposal holds an invalid config path")
		}
	}
	if err := os.MkdirAll(store, 0o700); err != nil {
		return "", fmt.Errorf("installed config: %w", err)
	}
	temp, err = os.MkdirTemp(store, ".staging-*")
	if err != nil {
		return "", fmt.Errorf("installed config: %w", err)
	}
	for _, rel := range bundleOrder(files) {
		if err := writeStaged(temp, rel, files[rel]); err != nil {
			_ = os.RemoveAll(temp)
			return "", err
		}
	}
	return temp, nil
}

// writeStaged writes one proposal file under temp, creating it exclusively.
// rel has passed ValidBundlePath, so naming it in the error is safe; the
// cause keeps the OS error (errors.Is(err, fs.ErrExist) on a collision).
func writeStaged(temp, rel string, data []byte) error {
	dst := filepath.Join(temp, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("installed config: %w", err)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("%s: %w", rel, werr)
	}
	return nil
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
	if err := os.Rename(temp, SnapshotDir(store, hash)); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("installed config: %w", err)
		}
		// The snapshot is already present by name. Content-addressing makes
		// that mean "identical bytes" only if the directory actually holds
		// them: verify the existing snapshot hashes to its own name before
		// trusting it and flipping the pointer onto it. A corrupt or
		// partially-restored <hex>/ (a lost roles/, a bad byte) must not be
		// silently blessed by a re-apply of the same config. This heals the
		// re-apply path with its own remedy-bearing message; LoadInstalled and
		// the kill switch verify a snapshot on read through VerifyInstalled,
		// and InstalledRoles does not.
		existing, herr := HashDir(SnapshotDir(store, hash))
		if herr != nil {
			return fmt.Errorf("installed config: existing snapshot %s: %w", hash, herr)
		}
		if existing != hash {
			return fmt.Errorf("installed config: existing snapshot %s is corrupt (its bytes hash as %s); remove %s and re-apply", hash, existing, SnapshotDir(store, hash))
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
