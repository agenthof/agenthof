package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidBundlePath(t *testing.T) {
	accept := []string{
		"gateway.yaml",
		"agents/x.yaml", "workflows/w.yml", "roles/r.yaml",
		"roles/.x.yaml", // dot-prefixed: configFiles enumerates it (only the extension is tested)
		"agents/.yaml",  // empty name, extension only: filepath.Ext(".yaml") == ".yaml", so LoadDir reads it
		"agents/" + strings.Repeat("a", 195) + ".yaml", // 200 runes exactly
		"agents/ünïcode.yaml",
	}
	for _, rel := range accept {
		if !ValidBundlePath(rel) {
			t.Errorf("ValidBundlePath(%q) = false, want true", rel)
		}
	}
	reject := []string{
		"", ".", "..", "/", "x.yaml",
		"../x.yaml", "/abs/x.yaml", "agents/../x.yaml", "agents/./x.yaml",
		"agents/a/b.yaml", "agents/", "agents", "roles/x.txt", "roles/x.yaml.bak",
		"Agents/x.yaml", "agents/x.YAML", "gateway.yml", "Gateway.yaml", "gateway.yaml/",
		"agents\\x.yaml", "agents/x\\y.yaml",
		"agents/x\x00.yaml", "agents/x\n.yaml", "agents/x\x1b[2J.yaml", "agents/\xff.yaml",
		"agents/" + strings.Repeat("a", 196) + ".yaml", // 201 runes
	}
	for _, rel := range reject {
		if ValidBundlePath(rel) {
			t.Errorf("ValidBundlePath(%q) = true, want false", rel)
		}
	}
}

// TestValidBundlePathAcceptsEveryEnumeratedName: the rule is "what
// configFiles would read", so every name the enumeration returns for the
// in-repo example config and a kitchen-sink fixture passes.
func TestValidBundlePathAcceptsEveryEnumeratedName(t *testing.T) {
	for _, root := range []string{filepath.Join("..", "..", "examples", "config"), kitchenSinkConfig(t)} {
		files, err := configFiles(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, rel := range files {
			if !ValidBundlePath(rel) {
				t.Errorf("%s: enumerated name %q rejected by ValidBundlePath", root, rel)
			}
		}
	}
}

// kitchenSinkConfig is a directory exercising every enumeration corner:
// both extensions, a dot-prefixed name, an extension-only name, names that
// sort differently bytewise vs case-insensitively, a missing workflows/
// subdirectory, and strays configFiles must skip.
func kitchenSinkConfig(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeCfg(t, root, "agents/b.yaml", "name: b\n")
	writeCfg(t, root, "agents/A.yml", "name: A\n")
	writeCfg(t, root, "agents/.yaml", "name: dot\n")
	writeCfg(t, root, "agents/.hidden.yaml", "name: hidden\n")
	writeCfg(t, root, "agents/README.md", "not config\n")
	writeCfg(t, root, "agents/nested/deep.yaml", "name: deep\n")
	writeCfg(t, root, "roles/r.yaml", "name: r\n")
	writeCfg(t, root, "gateway.yaml", "models: {}\n")
	writeCfg(t, root, "extras/x.yaml", "name: x\n")
	return root
}

func TestBundleOrderIsTheEnumerationOrder(t *testing.T) {
	for _, root := range []string{filepath.Join("..", "..", "examples", "config"), kitchenSinkConfig(t), sampleConfig(t)} {
		want, err := configFiles(root)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := ReadBundle(root)
		if err != nil {
			t.Fatal(err)
		}
		if got := bundleOrder(bundle); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: bundleOrder = %v, configFiles = %v", root, got, want)
		}
	}
	// gateway.yaml is last even though "g" sorts before "r"/"w".
	got := bundleOrder(map[string][]byte{"gateway.yaml": nil, "roles/a.yaml": nil, "agents/z.yaml": nil, "workflows/m.yml": nil, "agents/A.yaml": nil})
	want := []string{"agents/A.yaml", "agents/z.yaml", "workflows/m.yml", "roles/a.yaml", "gateway.yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bundleOrder = %v, want %v", got, want)
	}
}

// TestHashFilesMatchesHashDir pins the canon invariant HashFiles(ReadBundle(d))
// == HashDir(d) over every in-repo and fixture config, and HashDir(StageFiles(m))
// == HashFiles(m).
func TestHashFilesMatchesHashDir(t *testing.T) {
	for _, root := range []string{filepath.Join("..", "..", "examples", "config"), kitchenSinkConfig(t), sampleConfig(t)} {
		want, err := HashDir(root)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := ReadBundle(root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := HashFiles(bundle)
		if err != nil || got != want {
			t.Fatalf("%s: HashFiles(ReadBundle) = %q err=%v, HashDir = %q", root, got, err, want)
		}
		store := filepath.Join(t.TempDir(), "installed")
		temp, err := StageFiles(store, bundle)
		if err != nil {
			t.Fatal(err)
		}
		staged, err := HashDir(temp)
		if err != nil || staged != want {
			t.Fatalf("%s: HashDir(StageFiles) = %q err=%v, want %q", root, staged, err, want)
		}
	}
}

func TestHashFilesRejectsInvalidKeyAndAcceptsEmpty(t *testing.T) {
	if _, err := HashFiles(map[string][]byte{"../x.yaml": []byte("x")}); err == nil {
		t.Fatal("an invalid key must be refused")
	}
	empty, err := HashFiles(map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := HashDir(t.TempDir())
	if err != nil || empty != dir {
		t.Fatalf("an empty bundle must hash as an empty directory: %q vs %q (err %v)", empty, dir, err)
	}
}

func TestReadBundleRefusesANameItCannotBundle(t *testing.T) {
	root := t.TempDir()
	writeCfg(t, root, "roles/r.yaml", "name: r\n")
	long := "agents/" + strings.Repeat("x", 196) + ".yaml"
	writeCfg(t, root, long, "name: x\n")
	if _, err := HashDir(root); err != nil {
		t.Fatalf("the directory itself still hashes locally: %v", err)
	}
	_, err := ReadBundle(root)
	if err == nil || !strings.Contains(err.Error(), "cannot be bundled") || !strings.Contains(err.Error(), strings.Repeat("x", 20)) {
		t.Fatalf("ReadBundle must refuse loudly, naming the file: %v", err)
	}
	if _, err := ReadBundle(filepath.Join(root, "nope")); err == nil {
		t.Fatal("a missing root is an error")
	}
}
