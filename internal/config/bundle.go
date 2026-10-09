package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// bundleGroups are the subdirectories configFiles enumerates, in the order
// it enumerates them. gateway.yaml follows them.
var bundleGroups = [...]string{"agents", "workflows", "roles"}

// maxBundleNameRunes caps a bundle file's name (the segment after the
// group, extension included) — the same cap the server puts on every other
// untrusted name.
const maxBundleNameRunes = 200

// ValidBundlePath reports whether rel is a path configFiles would
// enumerate: exactly "gateway.yaml", or "<agents|workflows|roles>/<name>"
// where name ends in .yaml or .yml, is non-empty, holds no further "/",
// no "\", no ".", "..", NUL or other non-printable rune, and is at most
// maxBundleNameRunes runes. A dot-prefixed name ("roles/.x.yaml") and an
// extension-only name ("agents/.yaml") are accepted: os.ReadDir lists them
// and configFiles tests only the extension, so LoadDir and HashDir would
// read them, and the rule here is "what the enumeration would read",
// nothing stricter. It is the enumeration rule restated for a path that
// does not exist yet: a key this rejects would either escape the staging
// directory or be written and then silently ignored by LoadDir/HashDir,
// and neither may happen.
func ValidBundlePath(rel string) bool {
	if rel == "gateway.yaml" {
		return true
	}
	group, name, ok := strings.Cut(rel, "/")
	if !ok {
		return false
	}
	known := false
	for _, g := range bundleGroups {
		if g == group {
			known = true
		}
	}
	if !known || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return false
	}
	if ext := path.Ext(name); ext != ".yaml" && ext != ".yml" {
		return false
	}
	if utf8.RuneCountInString(name) > maxBundleNameRunes {
		return false
	}
	for _, r := range name {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// bundleOrder returns files' keys in configFiles' enumeration order — the
// one place that order is restated for a proposal that is not on disk:
// within each group (agents/, then workflows/, then roles/) the keys are
// sort.Strings-sorted on the full key; gateway.yaml comes last. Keys must
// already have passed ValidBundlePath.
func bundleOrder(files map[string][]byte) []string {
	byGroup := map[string][]string{}
	gateway := false
	for rel := range files {
		if rel == "gateway.yaml" {
			gateway = true
			continue
		}
		g, _, _ := strings.Cut(rel, "/")
		byGroup[g] = append(byGroup[g], rel)
	}
	var out []string
	for _, g := range bundleGroups {
		names := byGroup[g]
		sort.Strings(names)
		out = append(out, names...)
	}
	if gateway {
		out = append(out, "gateway.yaml")
	}
	return out
}

// ReadBundle reads the configuration at root into a map by the configFiles
// enumeration — the client side of a bundle (apply --server --config). A
// name configFiles enumerates but ValidBundlePath rejects (non-printable
// runes, over maxBundleNameRunes) is a loud error naming the file: the
// client refuses rather than sending a bundle that could never hash as the
// directory does. Invariant (pinned by test): HashFiles(ReadBundle(d)) ==
// HashDir(d) for every d whose enumerated names pass ValidBundlePath.
func ReadBundle(root string) (map[string][]byte, error) {
	files, err := configFiles(root)
	if err != nil {
		return nil, err
	}
	bundle := make(map[string][]byte, len(files))
	for _, rel := range files {
		if !ValidBundlePath(rel) {
			return nil, fmt.Errorf("%q: %w (non-printable, or over %d characters)", rel, ErrNotBundleable, maxBundleNameRunes)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		bundle[rel] = data
	}
	return bundle, nil
}

// ErrNotBundleable is wrapped by ReadBundle's refusal of a name configFiles
// enumerates but ValidBundlePath rejects, so a caller can tell "this
// snapshot cannot be carried as a bundle" from a read failure with
// errors.Is. The printed text is unchanged.
var ErrNotBundleable = errors.New("file name cannot be bundled")

// BundleOrder is bundleOrder for callers outside this package — the order
// a bundle's keys are listed, hashed and written in. HashFiles keeps
// calling the unexported function so the canon's file does not change.
func BundleOrder(files map[string][]byte) []string { return bundleOrder(files) }

// SnapshotBundle reads the snapshot named by hash under store into a bundle
// — the configFiles enumeration, as ReadBundle reads a directory — and
// requires HashFiles(files) == hash before returning it. That check is the
// distribution read's verify-on-read: the same files/v1 canon over the same
// enumeration as HashDir (HashFiles(ReadBundle(d)) == HashDir(d) is pinned
// by test), computed over THE BYTES RETURNED, so a caller never serves
// bytes that do not hash as the pointer says — there is no second read
// between the check and the answer. Every error is wrapped
// "installed config <hash>: …" (as VerifyInstalled wraps): a snapshot that
// is gone wraps configFiles' "config root …" error; a name the enumeration
// lists but ValidBundlePath rejects wraps ReadBundle's ErrNotBundleable
// (errors.Is-distinguishable); a mismatch is VerifyInstalled's text,
// "installed config <hash>: snapshot hashes as <got>, not as its pointer".
// It is byte-transparent: a file that is not valid UTF-8 is returned as is,
// and a caller that must carry text checks that itself.
func SnapshotBundle(store, hash string) (map[string][]byte, error) {
	files, err := ReadBundle(SnapshotDir(store, hash))
	if err != nil {
		return nil, fmt.Errorf("installed config %s: %w", hash, err)
	}
	got, err := HashFiles(files)
	if err != nil {
		return nil, fmt.Errorf("installed config %s: %w", hash, err)
	}
	if got != hash {
		return nil, fmt.Errorf("installed config %s: snapshot hashes as %s, not as its pointer", hash, got)
	}
	return files, nil
}

// InstalledBundle is SnapshotBundle over the pointer: InstalledHash, then
// the snapshot it names. installed=false with a nil error means nothing is
// installed; a present-but-malformed pointer is an error (fail closed, as
// InstalledHash). The local reader uses it; the server authorizes from
// InstalledRoles' hash and calls SnapshotBundle with that hash, so the
// bytes it serves are the bytes whose roles authorized the caller.
func InstalledBundle(store string) (files map[string][]byte, hash string, installed bool, err error) {
	hash, installed, err = InstalledHash(store)
	if err != nil || !installed {
		return nil, "", installed, err
	}
	files, err = SnapshotBundle(store, hash)
	if err != nil {
		return nil, hash, true, err
	}
	return files, hash, true, nil
}

// WriteBundle materializes files as a configuration directory at root —
// the inverse of ReadBundle. root must not exist: it is created with
// os.Mkdir (never MkdirAll — the parent must already exist, so a failure
// leaves no freshly created parents behind, and a dangling symlink at root
// fails as "exists", which is the right answer), 0700; each file is written
// 0600 under its config-relative path (the group subdirectory created with
// os.Mkdir, the file opened O_EXCL, as the installer stages files), in
// BundleOrder; on any failure after root was created, root is removed
// whole, so a partial directory is never left for an operator to apply.
// Keys are checked with ValidBundlePath first (fail closed, before anything
// is created). It does not hash: the caller compares HashDir(root) to the
// hash it expects, which also catches a filesystem that normalizes names.
func WriteBundle(root string, files map[string][]byte) error {
	for rel := range files {
		if !ValidBundlePath(rel) {
			return errors.New("bundle holds an invalid config path")
		}
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return err
	}
	for _, rel := range bundleOrder(files) {
		if err := writeBundled(root, rel, files[rel]); err != nil {
			_ = os.RemoveAll(root)
			return err
		}
	}
	return nil
}

// writeBundled writes one bundle file under root, creating its group
// directory if this is the group's first file and the file exclusively.
// rel has passed ValidBundlePath, so naming it is safe.
func writeBundled(root, rel string, data []byte) error {
	dst := filepath.Join(root, filepath.FromSlash(rel))
	if dir := filepath.Dir(dst); dir != root {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", rel, err)
		}
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
