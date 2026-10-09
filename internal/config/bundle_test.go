package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
	if !errors.Is(err, ErrNotBundleable) {
		t.Fatalf("the refusal must wrap ErrNotBundleable: %v", err)
	}
	if _, err := ReadBundle(filepath.Join(root, "nope")); err == nil {
		t.Fatal("a missing root is an error")
	}
}

// TestBundleOrderIsExportedUnchanged: the exported order is bundleOrder's.
func TestBundleOrderIsExportedUnchanged(t *testing.T) {
	files := map[string][]byte{"gateway.yaml": nil, "roles/a.yaml": nil, "agents/z.yaml": nil, "workflows/m.yml": nil, "agents/A.yaml": nil}
	if got, want := BundleOrder(files), bundleOrder(files); !reflect.DeepEqual(got, want) {
		t.Fatalf("BundleOrder = %v, bundleOrder = %v", got, want)
	}
}

// snapshotFor installs src by hand under a fresh store and returns the store
// and the hash, so each snapshot-read case starts from a verified snapshot.
func snapshotFor(t *testing.T, src string) (store, hash string) {
	t.Helper()
	store = filepath.Join(t.TempDir(), "installed")
	return store, installByHand(t, store, src)
}

// TestSnapshotBundleVerifiesTheBytesItReturns: the map comes back only when
// it hashes as the pointer says — the same canon and enumeration as HashDir,
// over the bytes returned.
func TestSnapshotBundleVerifiesTheBytesItReturns(t *testing.T) {
	store, hash := snapshotFor(t, sampleConfig(t))
	files, err := SnapshotBundle(store, hash)
	if err != nil {
		t.Fatal(err)
	}
	got, err := HashFiles(files)
	if err != nil || got != hash {
		t.Fatalf("HashFiles(SnapshotBundle) = %q err=%v, want %q", got, err, hash)
	}
	want, err := ReadBundle(SnapshotDir(store, hash))
	if err != nil || !reflect.DeepEqual(files, want) {
		t.Fatalf("SnapshotBundle must return exactly ReadBundle's map: %v", err)
	}

	// Tampered file: the exact mismatch text, equality not Contains.
	p := filepath.Join(SnapshotDir(store, hash), "agents", "planner.yaml")
	if err := os.WriteFile(p, []byte("name: planner\nmodel: fast\ninstruction: plan HARDER\noutput: plan\nendpoint: http://127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	actual, err := HashDir(SnapshotDir(store, hash))
	if err != nil {
		t.Fatal(err)
	}
	_, err = SnapshotBundle(store, hash)
	if err == nil || err.Error() != "installed config "+hash+": snapshot hashes as "+actual+", not as its pointer" {
		t.Fatalf("tampered snapshot: %v", err)
	}

	// An added roles file and a deleted file are mismatches too.
	store, hash = snapshotFor(t, sampleConfig(t))
	writeCfg(t, SnapshotDir(store, hash), "roles/extra.yaml", "name: extra\nallowed_groups: [x]\ncontrol: [prune]\n")
	if _, err := SnapshotBundle(store, hash); err == nil || !strings.Contains(err.Error(), "snapshot hashes as") {
		t.Fatalf("added file: %v", err)
	}
	store, hash = snapshotFor(t, sampleConfig(t))
	if err := os.Remove(filepath.Join(SnapshotDir(store, hash), "gateway.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotBundle(store, hash); err == nil || !strings.Contains(err.Error(), "snapshot hashes as") {
		t.Fatalf("deleted file: %v", err)
	}

	// A snapshot that is gone wraps configFiles' error under the one prefix.
	store, hash = snapshotFor(t, sampleConfig(t))
	if err := os.RemoveAll(SnapshotDir(store, hash)); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotBundle(store, hash); err == nil || !strings.HasPrefix(err.Error(), "installed config "+hash+": config root ") {
		t.Fatalf("gone snapshot: %v", err)
	}

	// A name the enumeration lists but ValidBundlePath rejects: the sentinel,
	// wrapped under the same prefix.
	src := sampleConfig(t)
	writeCfg(t, src, "roles/"+strings.Repeat("x", 196)+".yaml", "name: long\nallowed_groups: [x]\ncontrol: [prune]\n")
	store, hash = snapshotFor(t, src)
	_, err = SnapshotBundle(store, hash)
	if err == nil || !errors.Is(err, ErrNotBundleable) || !strings.HasPrefix(err.Error(), "installed config "+hash+": ") {
		t.Fatalf("unbundleable name: %v", err)
	}
}

func TestInstalledBundle(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	files, hash, installed, err := InstalledBundle(store)
	if err != nil || installed || hash != "" || files != nil {
		t.Fatalf("no pointer: files=%v hash=%q installed=%v err=%v", files, hash, installed, err)
	}
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, InstalledPointer), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := InstalledBundle(store); err == nil || !strings.Contains(err.Error(), "malformed pointer") {
		t.Fatalf("malformed pointer must fail closed: %v", err)
	}
	store, want := snapshotFor(t, sampleConfig(t))
	files, hash, installed, err = InstalledBundle(store)
	if err != nil || !installed || hash != want {
		t.Fatalf("round trip: hash=%q installed=%v err=%v", hash, installed, err)
	}
	if got, _ := HashFiles(files); got != want {
		t.Fatalf("HashFiles = %q, want %q", got, want)
	}
}

// TestWriteBundleRoundTrips: WriteBundle is ReadBundle's inverse under the
// canon — HashDir(WriteBundle(root, ReadBundle(d))) == HashDir(d) — with the
// modes the installer uses (0700 directories, 0600 files).
func TestWriteBundleRoundTrips(t *testing.T) {
	for _, src := range []string{filepath.Join("..", "..", "examples", "config"), kitchenSinkConfig(t), sampleConfig(t)} {
		want, err := HashDir(src)
		if err != nil {
			t.Fatal(err)
		}
		files, err := ReadBundle(src)
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(t.TempDir(), "out")
		if err := WriteBundle(root, files); err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		got, err := HashDir(root)
		if err != nil || got != want {
			t.Fatalf("%s: HashDir(written) = %q err=%v, want %q", src, got, err, want)
		}
		if runtime.GOOS != "windows" {
			if st, _ := os.Stat(root); st.Mode().Perm() != 0o700 {
				t.Fatalf("root mode %v, want 0700", st.Mode().Perm())
			}
			for _, rel := range BundleOrder(files) {
				if st, _ := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); st.Mode().Perm() != 0o600 {
					t.Fatalf("%s mode %v, want 0600", rel, st.Mode().Perm())
				}
			}
		}
	}
}

// TestWriteBundleRefusesBadRoots: an existing root (even empty), a dangling
// symlink at root, and a missing parent are refused; an invalid key is refused
// before anything is created; nothing is left behind in any case.
func TestWriteBundleRefusesBadRoots(t *testing.T) {
	files, err := ReadBundle(sampleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(empty, files); err == nil || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing empty root must be refused as exists: %v", err)
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Fatalf("an existing root must be left untouched: %v", ents)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(dangling, files); err == nil || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a dangling symlink at root must read as exists: %v", err)
	}
	orphan := filepath.Join(dir, "missing-parent", "out")
	if err := WriteBundle(orphan, files); err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing parent must be refused (Mkdir, never MkdirAll): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "missing-parent")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no parent may be created")
	}
	bad := map[string][]byte{"../escape.yaml": []byte("x")}
	fresh := filepath.Join(dir, "fresh")
	if err := WriteBundle(fresh, bad); err == nil || !strings.Contains(err.Error(), "invalid config path") {
		t.Fatalf("invalid key: %v", err)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("an invalid key must be refused before the root is created")
	}
}

// TestWriteBundleRemovesRootOnMidwayFailure: two keys the filesystem folds
// into one name make the second O_EXCL open fail; the root is then removed
// whole. Only a case-insensitive volume can produce the collision, so the test
// skips elsewhere.
func TestWriteBundleRemovesRootOnMidwayFailure(t *testing.T) {
	probe := t.TempDir()
	if err := os.WriteFile(filepath.Join(probe, "case"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(probe, "CASE")); err != nil {
		t.Skip("needs a case-insensitive filesystem to produce a name collision")
	}
	root := filepath.Join(t.TempDir(), "out")
	err := WriteBundle(root, map[string][]byte{"agents/a.yaml": []byte("name: a\n"), "agents/A.yaml": []byte("name: A\n")})
	if err == nil || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("the second open must fail exclusively: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a failed write must leave no root behind")
	}
}
