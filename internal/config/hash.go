package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
)

// canonHash is canon "files/v1", the ONE place the per-file framing lives:
// the hex sha256 of the concatenation, per file in configFiles order, of
// sha256(slashRelPath) || sha256(fileBytes). HashDir feeds it from a
// directory, HashFiles from a map; TestHashDirGoldenVector and
// TestHashFilesGoldenVector pin both to the same constant.
type canonHash struct{ outer hash.Hash }

func newCanonHash() canonHash { return canonHash{outer: sha256.New()} }

func (c canonHash) add(rel string, data []byte) {
	ph := sha256.Sum256([]byte(rel))
	bh := sha256.Sum256(data)
	c.outer.Write(ph[:])
	c.outer.Write(bh[:])
}

func (c canonHash) sum() string { return "sha256:" + hex.EncodeToString(c.outer.Sum(nil)) }

// HashDir computes a deterministic join-key hash of the config directory
// under root, using canon "files/v1" (canonHash). Files are read exactly as
// LoadDir reads them (symlinks followed). A readable-but-unparseable-YAML
// file is still included, since the hash is over bytes, not parsed content.
// An unreadable file returns a loud error. The result is returned as
// "sha256:" + hex.
func HashDir(root string) (string, error) {
	files, err := configFiles(root)
	if err != nil {
		return "", err
	}
	h := newCanonHash()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", fmt.Errorf("hash config: %s: %w", rel, err)
		}
		h.add(rel, data)
	}
	return h.sum(), nil
}

// HashFiles is HashDir over a proposal that is not on disk: the same
// files/v1 canon over the keys in the order configFiles would enumerate
// them (bundleOrder). Every key must pass ValidBundlePath; the error for
// one that does not never echoes the key (it is attacker-controlled on the
// server). An empty map hashes as an empty directory.
func HashFiles(files map[string][]byte) (string, error) {
	for rel := range files {
		if !ValidBundlePath(rel) {
			return "", errors.New("hash config: proposal holds an invalid config path")
		}
	}
	h := newCanonHash()
	for _, rel := range bundleOrder(files) {
		h.add(rel, files[rel])
	}
	return h.sum(), nil
}
