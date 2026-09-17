package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store keeps artifact BODIES out of the immutable ledger (constitution
// Art. III): the ledger carries sha + preview; bodies live here, prunable,
// so GDPR-style erasure never breaks chain integrity.
type Store struct{ dir string }

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Put(body string) (string, string, error) {
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])
	preview := strings.Join(strings.Fields(strings.ReplaceAll(body, "\n", " ")), " ")
	if r := []rune(preview); len(r) > 200 {
		preview = string(r[:200])
	}
	path := filepath.Join(s.dir, sha)
	if _, err := os.Stat(path); err == nil {
		return sha, preview, nil // idempotent
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", "", err
	}
	return sha, preview, nil
}

func (s *Store) Get(sha string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, sha))
	if err != nil {
		return "", fmt.Errorf("artifact %s: %w", sha, err)
	}
	return string(b), nil
}

func (s *Store) Prune(olderThan time.Duration) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-olderThan)
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(s.dir, e.Name())); err == nil {
				n++
			}
		}
	}
	return n, nil
}
