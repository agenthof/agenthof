package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// HashDir computes a deterministic join-key hash of the config directory
// under root, using canon "files/v1": the hex sha256 of the concatenation,
// per file in configFiles order, of sha256(slashRelPath) || sha256(fileBytes).
// Files are read exactly as LoadDir reads them (symlinks followed). A
// readable-but-unparseable-YAML file is still included, since the hash is
// over bytes, not parsed content. An unreadable file returns a loud error.
// The result is returned as "sha256:" + hex.
func HashDir(root string) (string, error) {
	files, err := configFiles(root)
	if err != nil {
		return "", err
	}
	outer := sha256.New()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", fmt.Errorf("hash config: %s: %w", rel, err)
		}
		ph := sha256.Sum256([]byte(rel))
		bh := sha256.Sum256(data)
		outer.Write(ph[:])
		outer.Write(bh[:])
	}
	return "sha256:" + hex.EncodeToString(outer.Sum(nil)), nil
}
