package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const editGatewayFixture = `# Gateway config, hand-maintained.
models:
  m1:
    url: http://127.0.0.1:1/v1 # trailing note on url
tools:
  # the drive resource
  drive:
    kind: mcp
    url: unix:///run/drive.sock
    runtime: refbridge
  # the memory resource
  memory:
    kind: mcp
    url: unix:///run/memory.sock
    runtime: refbridge
`

func TestInsertToolResourcePreservesComments(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "gateway.yaml")
	if err := os.WriteFile(p, []byte(editGatewayFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	res := ToolResource{Kind: "mcp", URL: "unix:///run/new.sock", Runtime: "refbridge",
		Command: []string{"/usr/bin/new-mcp", "--stdio"}, EnvPassthrough: []string{"NEW_TOKEN"}}
	if err := InsertToolResource(p, "newres", res); err != nil {
		t.Fatalf("InsertToolResource: %v", err)
	}
	b, _ := os.ReadFile(p)
	out := string(b)
	for _, want := range []string{
		"# Gateway config, hand-maintained.",
		"# the drive resource",
		"# the memory resource",
		"# trailing note on url",
		"drive:", "memory:", "newres:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lost %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "drive:") > strings.Index(out, "memory:") ||
		strings.Index(out, "memory:") > strings.Index(out, "newres:") {
		t.Errorf("key order not preserved:\n%s", out)
	}
	cfg, errs := LoadDir(root)
	if len(errs) != 0 {
		t.Fatalf("LoadDir: %v", errs)
	}
	got, ok := cfg.Gateway.Tools["newres"]
	if !ok {
		t.Fatalf("newres missing: %v", cfg.Gateway.Tools)
	}
	if len(got.Command) != 2 || got.Command[0] != "/usr/bin/new-mcp" || got.EnvPassthrough[0] != "NEW_TOKEN" {
		t.Errorf("parsed resource = %+v", got)
	}
	if cfg.Gateway.Tools["drive"].URL != "unix:///run/drive.sock" {
		t.Errorf("existing resource damaged: %+v", cfg.Gateway.Tools["drive"])
	}
}

func TestInsertToolResourceMissingFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "gateway.yaml")
	res := ToolResource{Kind: "mcp", URL: "unix:///run/x.sock", Runtime: "refbridge", Command: []string{"/bin/x"}}
	if err := InsertToolResource(p, "x", res); err != nil {
		t.Fatalf("InsertToolResource: %v", err)
	}
	cfg, errs := LoadDir(root)
	if len(errs) != 0 {
		t.Fatalf("LoadDir: %v", errs)
	}
	if len(cfg.Gateway.Tools) != 1 || cfg.Gateway.Tools["x"].Command[0] != "/bin/x" {
		t.Errorf("tools = %+v", cfg.Gateway.Tools)
	}
}

func TestInsertToolResourceNoToolsKey(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "gateway.yaml")
	if err := os.WriteFile(p, []byte("# only models\nmodels:\n  m1:\n    url: http://x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InsertToolResource(p, "x", ToolResource{Kind: "mcp", URL: "unix:///a"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# only models") {
		t.Errorf("comment lost:\n%s", b)
	}
	cfg, errs := LoadDir(root)
	if len(errs) != 0 || cfg.Gateway.Tools["x"].URL != "unix:///a" {
		t.Errorf("errs=%v tools=%+v", errs, cfg.Gateway.Tools)
	}
}

func TestInsertToolResourceDuplicate(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "gateway.yaml")
	if err := os.WriteFile(p, []byte(editGatewayFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	err := InsertToolResource(p, "drive", ToolResource{Kind: "mcp", URL: "unix:///other"})
	if !errors.Is(err, ErrResourceExists) {
		t.Fatalf("err = %v, want ErrResourceExists", err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != editGatewayFixture {
		t.Errorf("file changed on duplicate")
	}
}

const editAgentFixture = `# agent file
name: a1
enabled: true
tools:
  # existing grant
  - resource: drive
    tools: ["*"]
    mode: read-only
`

func TestInsertGrant(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "a1.yaml")
	if err := os.WriteFile(p, []byte(editAgentFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InsertGrant(p, ToolGrant{Resource: "memory", Tools: []string{"*"}, Mode: "read-write"}); err != nil {
		t.Fatalf("InsertGrant: %v", err)
	}
	b, _ := os.ReadFile(p)
	out := string(b)
	for _, want := range []string{"# agent file", "# existing grant", "resource: drive", "resource: memory"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lost %q:\n%s", want, out)
		}
	}
	var a AgentDef
	if err := yaml.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Tools) != 2 || a.Tools[1].Resource != "memory" || a.Tools[1].Mode != "read-write" {
		t.Errorf("tools = %+v", a.Tools)
	}
	err := InsertGrant(p, ToolGrant{Resource: "drive", Tools: []string{"x"}, Mode: "read-write"})
	if !errors.Is(err, ErrGrantExists) {
		t.Fatalf("err = %v, want ErrGrantExists", err)
	}
	after, _ := os.ReadFile(p)
	if string(b) != string(after) {
		t.Errorf("file changed on duplicate grant")
	}
}

func TestInsertGrantNoToolsKey(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "a1.yaml")
	if err := os.WriteFile(p, []byte("# hi\nname: a1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InsertGrant(p, ToolGrant{Resource: "memory", Tools: []string{"*"}, Mode: "read-only"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var a AgentDef
	if err := yaml.Unmarshal(b, &a); err != nil || len(a.Tools) != 1 || !strings.Contains(string(b), "# hi") {
		t.Errorf("err=%v tools=%+v\n%s", err, a.Tools, b)
	}
}
