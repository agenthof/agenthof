package registry

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBuildAndLookups(t *testing.T) {
	reg, errs := Build(baseCfg())
	if len(errs) != 0 || reg == nil {
		t.Fatalf("build: %v", errs)
	}
	if _, ok := reg.Agent("planner"); !ok {
		t.Fatal("planner missing")
	}
	if _, ok := reg.Agent("ghost"); ok {
		t.Fatal("ghost must not resolve")
	}
	if !reg.RoleOwnsWorkflow("se", "fix-bug") {
		t.Fatal("se owns fix-bug")
	}
	if reg.RoleOwnsWorkflow("se", "other") {
		t.Fatal("se must not own other")
	}
	lines := strings.Join(reg.List(), "\n")
	for _, want := range []string{"agent coder (enabled)", "workflow fix-bug (2 steps)", "role se (1 workflows)"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("List missing %q in:\n%s", want, lines)
		}
	}
}

func TestBuildRefusesInvalidConfig(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents[0].Endpoint = ""
	reg, errs := Build(cfg)
	if reg != nil || len(errs) == 0 {
		t.Fatal("invalid config must not produce a registry")
	}
}

func TestSetEnabledRewritesYAML(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "planner.yaml")
	if err := os.WriteFile(p, []byte("name: planner\nmodel: fast\ninstruction: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetEnabled(root, "planner", false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "enabled: false") {
		t.Fatalf("yaml not rewritten:\n%s", data)
	}
	if err := SetEnabled(root, "planner", true); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p)
	if !strings.Contains(string(data), "enabled: true") {
		t.Fatalf("yaml not re-enabled:\n%s", data)
	}
	if err := SetEnabled(root, "ghost", false); err == nil {
		t.Fatal("unknown agent must error")
	}
}

func TestSetEnabledAtomic(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "planner.yaml")
	if err := os.WriteFile(p, []byte("name: planner\nmodel: fast\ninstruction: x\nenabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Get inode before SetEnabled
	statBefore, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	stBefore := statBefore.Sys().(*syscall.Stat_t)
	inodeBefore := stBefore.Ino

	// Call SetEnabled
	if err := SetEnabled(root, "planner", false); err != nil {
		t.Fatal(err)
	}

	// (a) Content updated
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "enabled: false") {
		t.Fatalf("content not updated:\n%s", data)
	}

	// (b) File mode still 0644
	stat, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0o644 {
		t.Fatalf("file mode changed: got %o, want 0644", stat.Mode().Perm())
	}

	// (c) No leftover temp files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".enabled-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}

	// (d) Inode changed (proves rename, not truncate-write)
	statAfter, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	stAfter := statAfter.Sys().(*syscall.Stat_t)
	inodeAfter := stAfter.Ino

	if inodeBefore == inodeAfter {
		t.Fatalf("inode unchanged: %d == %d (expected rename to change inode, but got truncate-write)", inodeBefore, inodeAfter)
	}
}
