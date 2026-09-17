package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirHappyPath(t *testing.T) {
	root := t.TempDir()
	writeCfg(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan\noutput: plan\n")
	writeCfg(t, root, "agents/coder.yaml", "name: coder\nmodel: fast\ninstruction: code\noutput: patch\n")
	writeCfg(t, root, "workflows/fix-bug.yaml", "name: fix-bug\nsteps:\n  - name: plan\n    agent: planner\n  - name: code\n    agent: coder\n")
	writeCfg(t, root, "roles/se.yaml", "name: software-engineer\nworkflows: [fix-bug]\n")
	writeCfg(t, root, "gateway.yaml", "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m1\n    api_key_env: KEY\n")
	cfg, errs := LoadDir(root)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(cfg.Agents) != 2 || len(cfg.Workflows) != 1 || len(cfg.Roles) != 1 {
		t.Fatalf("counts: %+v", cfg)
	}
	if cfg.Agents[0].SourceFile == "" || !strings.HasPrefix(cfg.Agents[0].SourceFile, "agents/") {
		t.Fatalf("SourceFile not set: %q", cfg.Agents[0].SourceFile)
	}
	if cfg.Gateway.Models["fast"].APIKeyEnv != "KEY" {
		t.Fatalf("gateway: %+v", cfg.Gateway)
	}
}

func TestLoadDirCollectsAllErrors(t *testing.T) {
	root := t.TempDir()
	writeCfg(t, root, "agents/bad1.yaml", "name: [broken\n")
	writeCfg(t, root, "workflows/bad2.yaml", ":\n  - also broken: [\n")
	writeCfg(t, root, "agents/good.yaml", "name: ok\nmodel: fast\ninstruction: x\n")
	cfg, errs := LoadDir(root)
	if len(errs) != 2 {
		t.Fatalf("want 2 errors, got %d: %v", len(errs), errs)
	}
	for _, e := range errs {
		if !strings.Contains(e.Error(), ".yaml") {
			t.Fatalf("error must name the file: %v", e)
		}
	}
	if len(cfg.Agents) != 1 {
		t.Fatal("good files must still load")
	}
}

func TestLoadDirMissingRoot(t *testing.T) {
	_, errs := LoadDir(filepath.Join(t.TempDir(), "nope"))
	if len(errs) == 0 {
		t.Fatal("missing root must error")
	}
}
