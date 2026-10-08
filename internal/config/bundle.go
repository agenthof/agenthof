package config

import (
	"fmt"
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
			return nil, fmt.Errorf("%q: file name cannot be bundled (non-printable, or over %d characters)", rel, maxBundleNameRunes)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		bundle[rel] = data
	}
	return bundle, nil
}
