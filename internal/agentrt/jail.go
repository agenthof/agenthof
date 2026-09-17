// Package agentrt provides a path-jailed filesystem surface for agent tool
// calls. Every operation confines its target path inside a fixed root
// directory: relative escapes ("..") and absolute-looking inputs are folded
// back under the root rather than rejected, symlinks that would carry an
// operation outside the root (or that are themselves the final target) are
// refused, and any path with a dot-prefixed component (".git", ".env",
// ".ssh", etc., relative to the jail root) is refused outright.
//
// This package must never import "os/exec" or otherwise shell out; every
// operation here is a plain filesystem read/write.
package agentrt

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxFileSize          = 512 * 1024 // List/Search skip files larger than this
	maxListEntries       = 300        // List caps results at this many entries
	readByteCap          = 16000      // Read's per-call output byte cap
	writeByteCap         = 16000      // Write refuses to overwrite files larger than this
	searchByteCap        = 16000      // Search's total formatted-output byte cap
	defaultSearchResults = 50
	maxSearchResults     = 200
)

// Jail confines file operations to a root directory on disk.
type Jail struct {
	root string
}

// NewJail creates a Jail rooted at root. The root is resolved to an
// absolute, symlink-free path so every later confinement check compares
// against the real filesystem location (macOS in particular puts temp
// directories behind a /var -> /private/var symlink).
func NewJail(root string) (*Jail, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("agentrt: resolve jail root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("agentrt: resolve jail root: %w", err)
	}
	return &Jail{root: resolved}, nil
}

// FileInfo describes one file returned by List or scanned by Search.
type FileInfo struct {
	Path string // slash-separated, relative to the jail root
	Size int64
}

// listAll walks the jail from its root, returning every eligible file
// sorted by relative path, with no result cap. A file is eligible unless:
// it (or an ancestor directory) has a dot-prefixed name (".git", ".env",
// ".ssh", etc.) or is named "node_modules" or "vendor"; it is larger than
// maxFileSize; or it is itself a symlink.
//
// Skipping symlinked files is not spelled out in the List contract, but it
// is load-bearing here: listAll backs Search too, and Search reads each
// listed file's content with os.ReadFile, which follows symlinks. Without
// this skip a symlinked file pointing outside the jail would have its
// real, external content read straight into Search results.
func (j *Jail) listAll() ([]FileInfo, error) {
	var out []FileInfo
	err := filepath.WalkDir(j.root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == j.root {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil // a dotfile (".git" worktree pointer, ".env", etc.) — skip
		}
		if d.IsDir() {
			if name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}
		rel, relErr := filepath.Rel(j.root, path)
		if relErr != nil {
			return nil
		}
		out = append(out, FileInfo{Path: filepath.ToSlash(rel), Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Path < out[b].Path })
	return out, nil
}

// List returns up to 300 files under the jail root, sorted by path.
// truncated is true when more eligible files exist beyond that cap.
func (j *Jail) List() ([]FileInfo, bool, error) {
	all, err := j.listAll()
	if err != nil {
		return nil, false, err
	}
	if len(all) > maxListEntries {
		return all[:maxListEntries], true, nil
	}
	return all, false, nil
}

func withinRoot(p, root string) bool {
	if p == root {
		return true
	}
	return strings.HasPrefix(p, root+string(filepath.Separator))
}

// containsDotComponent reports whether any "/"-separated component of a
// slash-style path (rooted, i.e. starting with "/") has a leading dot
// (".git", ".env", ".ssh", etc.). This is Constitution Art. I's dotfile
// denial: any dot-prefixed path component, relative to the jail root, is
// refused outright — never just ".git" — so secrets and tool config
// (".env", ".ssh/id_rsa", ".aws/credentials", ...) can't be read, written,
// or edited by a jailed agent any more than the repo's own VCS metadata
// can. The leading "/" this is always called with is not itself a
// dot-prefixed component, so it never false-positives on the root.
func containsDotComponent(slashPath string) bool {
	for _, part := range strings.Split(slashPath, "/") {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// resolve confines rel to the jail root and returns the real, symlink-free
// absolute path an operation should use.
//
// Confinement, in order:
//  1. rel is Cleaned against a synthetic leading "/" so ".." components and
//     absolute-looking input can never climb above the root — they fold
//     back under it instead of erroring.
//  2. any dot-prefixed path component in the (cleaned) input is refused
//     outright (".git", ".env", ".ssh", etc.).
//  3. the deepest EXISTING ancestor of the target's parent directory is
//     located and fully resolved with EvalSymlinks; the resolved location
//     plus the still-nonexistent remainder must stay under root, or the
//     call is refused as escaping the workspace. (A nonexistent path
//     segment cannot itself be a symlink, so only the existing prefix needs
//     resolving.)
//  4. the resolved location is re-checked for a dot-prefixed component, so
//     a symlink whose literal input name doesn't start with a dot can't be
//     used to alias into one (e.g. a symlink "alias" -> ".git").
//  5. the final path component itself must not be a symlink, even one that
//     resolves back inside the root — Read/Write/Edit only ever operate on
//     real files the jail placed there.
func (j *Jail) resolve(rel string) (string, error) {
	clean := filepath.Clean("/" + rel)
	if containsDotComponent(clean) {
		return "", fmt.Errorf("agentrt: path %q: dot-prefixed components are refused", rel)
	}

	full := filepath.Join(j.root, clean)
	if full == j.root {
		return j.root, nil
	}

	parent := filepath.Dir(full)
	base := filepath.Base(full)

	candidate := parent
	var remainder []string
	for i := 0; i < 1024; i++ {
		if _, statErr := os.Lstat(candidate); statErr == nil {
			break
		}
		if candidate == j.root {
			break
		}
		up := filepath.Dir(candidate)
		if up == candidate {
			break
		}
		remainder = append([]string{filepath.Base(candidate)}, remainder...)
		candidate = up
	}

	resolvedAncestor, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("agentrt: resolve %q: %w", rel, err)
	}
	rebuiltParent := filepath.Join(append([]string{resolvedAncestor}, remainder...)...)
	if !withinRoot(rebuiltParent, j.root) {
		return "", fmt.Errorf("agentrt: path %q escapes the workspace", rel)
	}

	finalPath := filepath.Join(rebuiltParent, base)

	relFinal, err := filepath.Rel(j.root, finalPath)
	if err != nil {
		return "", fmt.Errorf("agentrt: resolve %q: %w", rel, err)
	}
	if containsDotComponent(filepath.ToSlash(relFinal)) {
		return "", fmt.Errorf("agentrt: path %q: dot-prefixed components are refused", rel)
	}

	if fi, statErr := os.Lstat(finalPath); statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("agentrt: path %q is a symlink; refused", rel)
	}
	return finalPath, nil
}

// splitLines splits content into lines the way editors count them: a
// trailing "\n" ends the last line rather than introducing a phantom empty
// one after it.
func splitLines(content string) []string {
	lines := strings.Split(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// Read returns lines [startLine, endLine] (1-based, inclusive) of rel,
// along with the resolved start/end and the file's total line count.
//
// startLine <= 0 is treated as 1. endLine <= 0, or beyond the file's last
// line, is treated as the last line. startLine beyond the last line is an
// error. The returned content is capped at 16000 bytes, cut at the last
// whole line that fits (truncated=true, and end reflects the last line
// actually included); if even the first line in the window exceeds the
// cap, it is clipped to it (truncated=true, start==end).
func (j *Jail) Read(rel string, startLine, endLine int) (content string, start, end, total int, truncated bool, err error) {
	path, err := j.resolve(rel)
	if err != nil {
		return "", 0, 0, 0, false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, 0, 0, false, fmt.Errorf("agentrt: read %q: %w", rel, err)
	}

	lines := splitLines(string(data))
	total = len(lines)

	if total == 0 {
		// An empty file has no lines at all, not a single empty one — return
		// it as a clean, error-free empty read rather than making callers
		// special-case "start line 1 is beyond end of file (0 lines)".
		return "", 1, 0, 0, false, nil
	}

	if startLine <= 0 {
		startLine = 1
	}
	if endLine <= 0 || endLine > total {
		endLine = total
	}
	if startLine > total {
		return "", 0, 0, total, false, fmt.Errorf("agentrt: start line %d is beyond end of %q (%d lines)", startLine, rel, total)
	}
	if endLine < startLine {
		endLine = startLine
	}

	window := lines[startLine-1 : endLine]
	var b strings.Builder
	included := 0
	for i, line := range window {
		if i == 0 {
			if len(line) > readByteCap {
				b.WriteString(clipToByteBoundary(line, readByteCap))
				included = 1
				truncated = true
				break
			}
			b.WriteString(line)
			included = 1
			continue
		}
		if b.Len()+1+len(line) > readByteCap {
			truncated = true
			break
		}
		b.WriteByte('\n')
		b.WriteString(line)
		included++
	}

	return b.String(), startLine, startLine + included - 1, total, truncated, nil
}

// clipToByteBoundary truncates s to at most max bytes without splitting a
// UTF-8 rune.
func clipToByteBoundary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Write creates or overwrites rel with content, creating any missing
// parent directories (mode 0o755) inside the jail. New and small files are
// written at mode 0o644. To guard against accidental data loss on a
// same-named collision, Write refuses to overwrite an existing file larger
// than the 16000-byte read cap; callers must use Edit for those instead.
func (j *Jail) Write(rel, content string) error {
	path, err := j.resolve(rel)
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(path); statErr == nil {
		if info.IsDir() {
			return fmt.Errorf("agentrt: %q is a directory", rel)
		}
		if info.Size() > writeByteCap {
			return fmt.Errorf("agentrt: %q is %d bytes, over the %d-byte overwrite limit; use edit instead", rel, info.Size(), writeByteCap)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("agentrt: create parent directories for %q: %w", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("agentrt: write %q: %w", rel, err)
	}
	return nil
}

// Edit replaces old with new in rel and returns the number of replacements
// made. old must be non-empty and must differ from new. If old occurs more
// than once in the file, all must be true or Edit refuses rather than
// guess which occurrence was meant.
func (j *Jail) Edit(rel, old, new string, all bool) (int, error) {
	path, err := j.resolve(rel)
	if err != nil {
		return 0, err
	}
	if old == "" {
		return 0, fmt.Errorf("agentrt: old text must not be empty")
	}
	if old == new {
		return 0, fmt.Errorf("agentrt: old and new text are identical; nothing to edit")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("agentrt: read %q: %w", rel, err)
	}
	content := string(data)
	count := strings.Count(content, old)
	if count == 0 {
		return 0, fmt.Errorf("agentrt: text not found in %q; copy the exact text to replace", rel)
	}
	if count > 1 && !all {
		return 0, fmt.Errorf("agentrt: text occurs %d times in %q; pass all=true to replace every occurrence, or supply more surrounding context to make it unique", count, rel)
	}

	perm := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		perm = info.Mode().Perm()
	}

	var updated string
	replacements := 1
	if all {
		updated = strings.ReplaceAll(content, old, new)
		replacements = count
	} else {
		updated = strings.Replace(content, old, new, 1)
	}
	if err := os.WriteFile(path, []byte(updated), perm); err != nil {
		return 0, fmt.Errorf("agentrt: write %q: %w", rel, err)
	}
	return replacements, nil
}

// Search scans every file listAll would return for lines matching pattern
// (a Go regexp), returning formatted "path:line: text" rows (one file's
// content skipped if it contains a NUL byte in its first 8KB, treated as
// binary). Row text is trimmed of a trailing "\r" and clipped to 250
// runes. maxResults <= 0 defaults to 50; results are hard-capped at 200
// regardless. The formatted output is additionally capped at 16000 bytes,
// never splitting a row. It returns the formatted rows and the number of
// rows actually included.
func (j *Jail) Search(pattern string, maxResults int) (string, int, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", 0, fmt.Errorf("agentrt: invalid search pattern: %w", err)
	}
	if maxResults <= 0 {
		maxResults = defaultSearchResults
	}
	if maxResults > maxSearchResults {
		maxResults = maxSearchResults
	}

	files, err := j.listAll()
	if err != nil {
		return "", 0, err
	}

	var b strings.Builder
	count := 0
outer:
	for _, f := range files {
		abs := filepath.Join(j.root, filepath.FromSlash(f.Path))
		data, readErr := os.ReadFile(abs)
		if readErr != nil {
			continue
		}
		probeLen := len(data)
		if probeLen > 8192 {
			probeLen = 8192
		}
		if bytes.IndexByte(data[:probeLen], 0) != -1 {
			continue // binary file — skip
		}
		for i, line := range splitLines(string(data)) {
			if !re.MatchString(line) {
				continue
			}
			text := clipRunes(strings.TrimRight(line, "\r"), 250)
			row := fmt.Sprintf("%s:%d: %s\n", f.Path, i+1, text)
			if b.Len()+len(row) > searchByteCap {
				break outer
			}
			b.WriteString(row)
			count++
			if count >= maxResults {
				break outer
			}
		}
	}
	return b.String(), count, nil
}

// clipRunes truncates s to at most max runes.
func clipRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max])
}
