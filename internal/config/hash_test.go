package config

import (
	"strings"
	"testing"
)

// writeFile is an alias for writeCfg (defined in load_test.go): it
// MkdirAll's the parent and writes the file.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	writeCfg(t, root, rel, content)
}

func TestHashDirDeterministicAndByteSensitive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "agents/a.yaml", "name: a\nmodel: m\n")
	writeFile(t, root, "roles/r.yaml", "name: r\nworkflows: [w]\n")
	h1, err := HashDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("want sha256: prefix, got %q", h1)
	}
	h2, _ := HashDir(root)
	if h1 != h2 {
		t.Fatal("HashDir must be deterministic")
	}
	writeFile(t, root, "agents/a.yaml", "name: a\nmodel: m2\n") // one byte-level change
	h3, _ := HashDir(root)
	if h3 == h1 {
		t.Fatal("HashDir must change when file bytes change")
	}
}

// TestHashDirGoldenVector pins canon files/v1 against a hardcoded digest so
// any accidental change to the hashing scheme (field order, separator,
// hash algorithm) is caught as a test failure rather than silently
// drifting. The digest was obtained by running this test once with a
// placeholder and copying the actual value from the failure.
func TestHashDirGoldenVector(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "agents/a.yaml", "name: a\nmodel: m\n")
	writeFile(t, root, "roles/r.yaml", "name: r\nworkflows: [w]\n")
	got, err := HashDir(root)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:3a2f6d0c0df4546527ad1ba5c5ae63cc803851f99614247fcbf38b16b4a5d885"
	if got != want {
		t.Fatalf("HashDir golden vector drifted: got %q, want %q", got, want)
	}
}

// TestHashDirPathSensitivity proves the relative path is part of what gets
// hashed, not just the file bytes: identical bytes at a different
// (enumerated) relative path must produce a different hash.
func TestHashDirPathSensitivity(t *testing.T) {
	rootA := t.TempDir()
	writeFile(t, rootA, "agents/x.yaml", "name: x\nmodel: m\n")
	hA, err := HashDir(rootA)
	if err != nil {
		t.Fatal(err)
	}

	rootB := t.TempDir()
	writeFile(t, rootB, "roles/x.yaml", "name: x\nmodel: m\n")
	hB, err := HashDir(rootB)
	if err != nil {
		t.Fatal(err)
	}

	if hA == hB {
		t.Fatalf("identical bytes at a different relative path must hash differently, both got %q", hA)
	}
}

func TestHashDirIncludesUnparseableYAML(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "agents/broken.yaml", "name: [unterminated\n")
	if _, err := HashDir(root); err != nil {
		t.Fatalf("unparseable YAML must still hash (bytes-based): %v", err)
	}
}
