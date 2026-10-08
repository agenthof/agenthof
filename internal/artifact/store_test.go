package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPutGetRoundTrip(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "arts"))
	if err != nil {
		t.Fatal(err)
	}
	body := "line one\nline two with detail"
	sha, preview, err := s.Put(body)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(body))
	if sha != hex.EncodeToString(want[:]) {
		t.Fatalf("sha mismatch: %s", sha)
	}
	if strings.Contains(preview, "\n") || preview != "line one line two with detail" {
		t.Fatalf("preview: %q", preview)
	}
	got, err := s.Get(sha)
	if err != nil || got != body {
		t.Fatalf("get: %q %v", got, err)
	}
	info, err := os.Stat(filepath.Join(s.Dir(), sha))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("perm: %v %v", info, err)
	}
}

func TestPreviewCapsAt200Runes(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	_, preview, err := s.Put(strings.Repeat("ü", 500))
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(preview)) != 200 {
		t.Fatalf("preview runes: %d", len([]rune(preview)))
	}
}

func TestPutIdempotentAndPrune(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	sha1, _, _ := s.Put("same")
	sha2, _, _ := s.Put("same")
	if sha1 != sha2 {
		t.Fatal("idempotency")
	}
	old := filepath.Join(s.Dir(), sha1)
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put("fresh"); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(24 * time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("prune n=%d err=%v", n, err)
	}
	if _, err := s.Get(sha1); err == nil {
		t.Fatal("old body must be gone")
	}
}

// TestPruneRemovesOnlyContentAddressedBodies: Prune removes only the 64-hex
// sha256 names Put writes, so a non-artifact file left in a misconfigured
// artifact dir (a control ledger, a repair fragment, a lock) is never swept,
// however old it is.
func TestPruneRemovesOnlyContentAddressedBodies(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	past := time.Now().Add(-48 * time.Hour)
	// A real content-addressed body (must be pruned) and three intruders a
	// misconfigured --artifact-dir could contain (must survive).
	sha, _, _ := s.Put("body")
	for _, name := range []string{"control.jsonl", "control.jsonl.torn-1", "installed.lock"} {
		p := filepath.Join(s.Dir(), name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(s.Dir(), sha), past, past); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(24 * time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("prune n=%d err=%v; want exactly the one body", n, err)
	}
	if _, err := s.Get(sha); err == nil {
		t.Fatal("the content-addressed body must be pruned")
	}
	for _, name := range []string{"control.jsonl", "control.jsonl.torn-1", "installed.lock"} {
		if _, err := os.Stat(filepath.Join(s.Dir(), name)); err != nil {
			t.Fatalf("%s must survive: %v", name, err)
		}
	}
}
