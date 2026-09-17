package registry

import (
	"os"
	"path/filepath"
	"strings"
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
	cfg.Agents[0].Model = "unknown"
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
