package agentcard

import (
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

var (
	knownTools  = map[string]bool{"tickets": true}
	knownModels = map[string]bool{"fast": true}
)

func goodExt() AgenthofExt {
	return AgenthofExt{
		Artifact: "ghcr.io/acme/triage@sha256:abc",
		Tools:    []config.ToolGrant{{Resource: "tickets", Tools: []string{"get"}, Mode: "read-only"}},
		Model:    "fast",
	}
}

func TestMapProposedAgentDef(t *testing.T) {
	def, req, err := Map(goodExt(), "triage", knownTools, knownModels)
	if err != nil {
		t.Fatal(err)
	}
	if def.Name != "triage" || def.Provenance == nil || def.Provenance.Image != "ghcr.io/acme/triage@sha256:abc" {
		t.Fatalf("bad def: %+v", def)
	}
	if !def.SpawnOnly() || def.Endpoint != "" || len(def.MaySpawn) != 0 {
		t.Fatalf("def must be spawn-only with no endpoint or may_spawn: %+v", def)
	}
	if len(def.Tools) != 1 || def.Tools[0].Resource != "tickets" || def.Model != "fast" {
		t.Fatalf("grants missing: %+v", def)
	}
	if len(req) != 3 {
		t.Fatalf("requested summary: %v", req)
	}
}

func TestMapRejectsWildcard(t *testing.T) {
	e := goodExt()
	e.Tools[0].Tools = []string{"*"}
	if _, _, err := Map(e, "a", knownTools, knownModels); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("got %v", err)
	}
}

func TestMapRejectsCardSpawn(t *testing.T) {
	e := goodExt()
	e.Spawn = []config.SpawnTarget{{Role: "r", Workflow: "w"}}
	if _, _, err := Map(e, "a", knownTools, knownModels); err == nil || !strings.Contains(err.Error(), "spawn") {
		t.Fatalf("got %v", err)
	}
}

func TestMapDisclosesButDoesNotGrantExec(t *testing.T) {
	e := goodExt()
	e.Exec = []string{"x"}
	def, req, err := Map(e, "a", knownTools, knownModels)
	if err != nil {
		t.Fatal(err)
	}
	if !def.SpawnOnly() || def.Exec.Declared() {
		t.Fatalf("exec was granted: %+v", def.Exec)
	}
	found := false
	for _, r := range req {
		found = found || strings.Contains(r, "not granted")
	}
	if !found {
		t.Fatalf("exec not disclosed: %v", req)
	}
}

func TestMapRejectsBadMode(t *testing.T) {
	for _, mode := range []string{"", "all", "write"} {
		e := goodExt()
		e.Tools[0].Mode = mode
		if _, _, err := Map(e, "a", knownTools, knownModels); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("mode %q: got %v", mode, err)
		}
	}
}

func TestMapRejectsEmptyTools(t *testing.T) {
	e := goodExt()
	e.Tools[0].Tools = nil
	if _, _, err := Map(e, "a", knownTools, knownModels); err == nil || !strings.Contains(err.Error(), "no tools") {
		t.Fatalf("got %v", err)
	}
}

func TestMapRejectsUnresolved(t *testing.T) {
	e := goodExt()
	e.Tools[0].Resource = "ghost-res"
	if _, _, err := Map(e, "a", knownTools, knownModels); err == nil || !strings.Contains(err.Error(), "ghost-res") {
		t.Fatalf("got %v", err)
	}
	e = goodExt()
	e.Model = "ghost-model"
	if _, _, err := Map(e, "a", knownTools, knownModels); err == nil || !strings.Contains(err.Error(), "ghost-model") {
		t.Fatalf("got %v", err)
	}
}

func hostExt() *HostProgram {
	return &HostProgram{Program: "acme-triage", Builds: []HostBuild{
		{OS: "darwin", Arch: "arm64", SHA256: "sha256:" + strings.Repeat("a", 64)},
		{OS: "linux", Arch: "amd64", SHA256: "sha256:" + strings.Repeat("b", 64)},
	}}
}

func TestMapProgramOnlyCard(t *testing.T) {
	e := goodExt()
	e.Artifact = ""
	e.HostProgram = hostExt()
	def, req, err := Map(e, "triage", knownTools, knownModels)
	if err != nil {
		t.Fatal(err)
	}
	p := def.Provenance
	if p == nil || p.Image != "" || p.Program != "acme-triage" || len(p.Builds) != 2 ||
		p.Builds[1] != (config.HostBuild{OS: "linux", Arch: "amd64", SHA256: "sha256:" + strings.Repeat("b", 64)}) {
		t.Fatalf("program-only provenance wrong: %+v", p)
	}
	for _, r := range req {
		if strings.HasPrefix(r, "image") {
			t.Fatalf("a program-only card must not disclose an image: %v", req)
		}
	}
	if req[0] != "host program acme-triage darwin/arm64 sha256:"+strings.Repeat("a", 64) ||
		req[1] != "host program acme-triage linux/amd64 sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("program disclosure wrong: %q", req)
	}
}

func TestMapBothForms(t *testing.T) {
	e := goodExt()
	e.HostProgram = hostExt()
	def, req, err := Map(e, "triage", knownTools, knownModels)
	if err != nil {
		t.Fatal(err)
	}
	p := def.Provenance
	if p.Image != e.Artifact || p.Program != "acme-triage" || len(p.Builds) != 2 {
		t.Fatalf("both forms must map: %+v", p)
	}
	if !strings.HasPrefix(req[0], "image ") || !strings.HasPrefix(req[1], "host program ") {
		t.Fatalf("both forms disclosed in order: %v", req)
	}
	e.HostProgram.Builds[0].OS = "mutated"
	if p.Builds[0].OS != "darwin" {
		t.Fatal("Map must copy the builds")
	}
}
