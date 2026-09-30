package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

// spawnTestConfig is a lead that may spawn worker/child-wf, a locked role
// nobody is in, and the spawn caps.
func spawnTestConfig() config.Config {
	ep := "https://example.test/run"
	return config.Config{
		Agents: []config.AgentDef{
			{Name: "lead", Endpoint: ep, SourceFile: "a", MaySpawn: []config.SpawnTarget{{Role: "worker", Workflow: "child-wf"}, {Role: "locked", Workflow: "locked-wf"}}},
			{Name: "child", Endpoint: ep, SourceFile: "a"},
		},
		Workflows: []config.WorkflowDef{
			{Name: "lead-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "lead"}}},
			{Name: "child-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "child"}}},
			{Name: "locked-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "child"}}},
		},
		Roles: []config.RoleDef{
			{Name: "lead-role", Workflows: []string{"lead-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"},
			{Name: "worker", Workflows: []string{"child-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"},
			{Name: "locked", Workflows: []string{"locked-wf"}, AllowedGroups: []string{"nobody"}, SourceFile: "r"},
		},
		Gateway: config.GatewayConfig{
			Models: map[string]config.ModelRoute{"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"}},
			Spawn:  config.SpawnPolicy{MaxDepth: 2, MaxParallel: 2, MaxTotalSpawns: 4},
		},
	}
}

func buildDeps(t *testing.T, cfg config.Config, dir string) *runDeps {
	t.Helper()
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	return newRunDeps(cfg, reg, broker.StaticEnv{}, nil, dir+"/runs", dir+"/arts", "sha256:test", "")
}

func TestRunDepsOneTimeoutKnob(t *testing.T) {
	cfg := spawnTestConfig()
	cfg.Gateway.StepTimeout = 7 * time.Minute
	deps := buildDeps(t, cfg, t.TempDir())
	if deps.executor().Timeout != 7*time.Minute {
		t.Fatalf("adapter timeout = %v, want the step_timeout knob (7m); otherwise the adapter's own default caps every step", deps.executor().Timeout)
	}
	if deps.options(nil).StepTimeout != 7*time.Minute {
		t.Fatalf("engine step timeout = %v, want 7m", deps.options(nil).StepTimeout)
	}
	parent := engine.Binding{RunID: "r-parent"}
	if deps.options(&parent).StepTimeout != 7*time.Minute || deps.options(&parent).Parent != &parent {
		t.Fatal("a child's options must carry the same knob and the parent linkage")
	}
	unset := buildDeps(t, spawnTestConfig(), t.TempDir())
	if unset.executor().Timeout != config.DefaultStepTimeout || unset.options(nil).StepTimeout != config.DefaultStepTimeout {
		t.Fatalf("an unset knob must mean %v on both sides, got adapter %v engine %v", config.DefaultStepTimeout, unset.executor().Timeout, unset.options(nil).StepTimeout)
	}
}

func TestPreRunRefusalReproducesTheOBOGate(t *testing.T) {
	cfg := oboTestConfig("obo")
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	if reason, refused := preRunRefusal(cfg, reg, "with-planner", identity.Static("dev@x")); !refused || reason != oboRefusalReason {
		t.Fatalf("a --as invoker on an OBO workflow must be refused with the fixed reason, got %q %v", reason, refused)
	}
	oidc := identity.Invoker{Subject: "u-dana", Issuer: "https://idp", Method: "oidc"}
	if _, refused := preRunRefusal(cfg, reg, "with-planner", oidc); refused {
		t.Fatal("a verified invoker passes the gate")
	}
	if _, refused := preRunRefusal(cfg, reg, "coder-only", identity.Static("dev@x")); refused {
		t.Fatal("a workflow without an OBO resource needs no token")
	}
}

func TestSpawnRefusedChildHasOwnLedgerLinkedToParent(t *testing.T) {
	dir := t.TempDir()
	deps := buildDeps(t, spawnTestConfig(), dir)
	parent := engine.Binding{Invoker: identity.Static("dev@x"), Role: "lead-role", Workflow: "lead-wf", RunID: "r-parent"}
	res, err := deps.Spawn(context.Background(), "locked", "locked-wf", "x", parent)
	if err != nil || res.Status != "refused" || res.ChildRunID == "" {
		t.Fatalf("res=%+v err=%v, want a refused child with its own run id and no error", res, err)
	}
	events, _, err := engine.ReadLog(dir+"/runs", res.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("child events = %+v", events)
	}
	b := events[0].Binding
	if b.ParentRunID != "r-parent" || b.Depth != 1 || b.Invoker.Subject != "dev@x" || b.Role != "locked" {
		t.Fatalf("child binding = %+v", b)
	}
	if res.Reason == "" {
		t.Fatal("the refusal reason must come back so the parent's spawn event can carry it")
	}
}

func TestSpawnOBOChildIsRefusedBeforeTheEngine(t *testing.T) {
	dir := t.TempDir()
	cfg := oboTestConfig("obo")
	// oboTestConfig: agent "planner" (index 0) grants the token_exchange
	// resource and steps in "with-planner"; role "se" owns every workflow.
	cfg.Agents[0].MaySpawn = []config.SpawnTarget{{Role: "se", Workflow: "with-planner"}}
	cfg.Gateway.Spawn = config.SpawnPolicy{MaxDepth: 2, MaxParallel: 2, MaxTotalSpawns: 4}
	deps := buildDeps(t, cfg, dir)
	parent := engine.Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "coder-only", RunID: "r-parent"}
	res, err := deps.Spawn(context.Background(), "se", "with-planner", "x", parent)
	if err != nil || res.Status != "refused" || res.Reason != oboRefusalReason || res.ChildRunID == "" {
		t.Fatalf("res=%+v err=%v, want the fixed OBO refusal with a child run id", res, err)
	}
	events, _, err := engine.ReadLog(dir+"/runs", res.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" || events[0].Reason != oboRefusalReason || events[0].Binding.ParentRunID != "r-parent" {
		t.Fatalf("child events = %+v", events)
	}
}

func TestSpawnLedgerFailureIsAnError(t *testing.T) {
	deps := buildDeps(t, spawnTestConfig(), t.TempDir())
	deps.logDir = "/dev/null/not-a-dir" // no ledger can be opened here
	parent := engine.Binding{Invoker: identity.Static("dev@x"), Role: "lead-role", Workflow: "lead-wf", RunID: "r-parent"}
	_, err := deps.Spawn(context.Background(), "worker", "child-wf", "x", parent)
	if err == nil {
		t.Fatal("a child whose ledger cannot be opened is an internal failure, not a quiet outcome")
	}
}

func writeSpawnSample(t *testing.T) string {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(echoCompatHandler))
	t.Cleanup(stub.Close)
	ep := "endpoint: " + stub.URL + "\n"
	root := t.TempDir()
	files := map[string]string{
		"agents/lead.yaml":        "name: lead\nmodel: fast\ninstruction: lead\noutput: out\n" + ep + "may_spawn:\n  - role: worker\n    workflow: child-wf\n  - role: locked\n    workflow: locked-wf\n",
		"agents/child.yaml":       "name: child\nmodel: fast\ninstruction: child\noutput: out\n" + ep + "may_spawn:\n  - role: worker\n    workflow: child-wf\n",
		"workflows/lead-wf.yaml":  "name: lead-wf\nsteps:\n  - name: s\n    agent: lead\n",
		"workflows/child-wf.yaml": "name: child-wf\nsteps:\n  - name: s\n    agent: child\n",
		"workflows/locked.yaml":   "name: locked-wf\nsteps:\n  - name: s\n    agent: child\n",
		"roles/lead.yaml":         "name: lead-role\nworkflows: [lead-wf]\nallowed_groups: [\"*\"]\n",
		"roles/worker.yaml":       "name: worker\nworkflows: [child-wf]\nallowed_groups: [\"*\"]\n",
		"roles/locked.yaml":       "name: locked\nworkflows: [locked-wf]\nallowed_groups: [nobody]\n",
		"gateway.yaml":            "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\nspawn:\n  max_depth: 2\n  max_parallel: 2\n  max_total_spawns: 4\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runLead(t *testing.T, root, input string) (string, string, []engine.Event) {
	t.Helper()
	logDir := filepath.Join(root, "runs")
	var out bytes.Buffer
	code := cmdRun([]string{"lead-role", "lead-wf", "--input", input, "--as", "dana@example.com", "--groups", "eng",
		"--config", root, "--log-dir", logDir, "--artifact-dir", filepath.Join(root, "arts")}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run exited %d:\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]+) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no run id in:\n%s", out.String())
	}
	events, _, err := engine.ReadLog(logDir, m[1])
	if err != nil {
		t.Fatal(err)
	}
	return m[1], logDir, events
}

func onlySpawn(t *testing.T, events []engine.Event) engine.Event {
	t.Helper()
	var spawns []engine.Event
	for _, e := range events {
		if e.Type == "spawn" {
			spawns = append(spawns, e)
		}
	}
	if len(spawns) != 1 {
		t.Fatalf("spawn events = %d, want 1: %+v", len(spawns), spawns)
	}
	return spawns[0]
}

func TestRunSpawnsGovernedChild(t *testing.T) {
	root := writeSpawnSample(t)
	parentID, logDir, events := runLead(t, root, "spawn:worker/child-wf:hello")
	sp := onlySpawn(t, events)
	if sp.Status != "succeeded" || sp.ChildRunID == "" || sp.ChildRole != "worker" || sp.ChildWorkflow != "child-wf" || sp.Depth != 1 || sp.OutputSHA == "" {
		t.Fatalf("spawn event = %+v", sp)
	}
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if child[0].Type != "workflow_started" || child[len(child)-1].Type != "workflow_finished" || child[len(child)-1].Status != "succeeded" {
		t.Fatalf("child events: %+v", child)
	}
	for _, e := range child {
		if e.Binding.ParentRunID != parentID || e.Binding.Depth != 1 || e.Binding.Invoker.Subject != "dana@example.com" || e.Binding.Role != "worker" {
			t.Fatalf("child %s binding = %+v", e.Type, e.Binding)
		}
	}
	var parentArtifact string
	for _, e := range events {
		if e.Type == "step_succeeded" {
			parentArtifact = e.Artifact
		}
	}
	if !strings.Contains(parentArtifact, "spawn succeeded "+sp.ChildRunID+" [child] hello") {
		t.Fatalf("parent artifact = %q, want the child's preview reported back", parentArtifact)
	}
}

func TestRunNestedSpawnStopsAtMaxDepth(t *testing.T) {
	root := writeSpawnSample(t)
	_, logDir, events := runLead(t, root, "spawn:worker/child-wf:spawn:worker/child-wf:spawn:worker/child-wf:deep")
	sp := onlySpawn(t, events) // depth 1, succeeded
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	gsp := onlySpawn(t, child) // depth 2, succeeded
	if gsp.Status != "succeeded" || gsp.Depth != 2 {
		t.Fatalf("grandchild spawn = %+v", gsp)
	}
	grandchild, _, err := engine.ReadLog(logDir, gsp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	ggsp := onlySpawn(t, grandchild) // depth 3 > max_depth 2: refused, no child
	if ggsp.Status != "refused" || ggsp.ChildRunID != "" || ggsp.Depth != 3 || ggsp.Reason != "spawn would exceed max_depth" {
		t.Fatalf("great-grandchild spawn = %+v", ggsp)
	}
	if grandchild[len(grandchild)-1].Status != "succeeded" {
		t.Fatalf("the grandchild reports the refusal and still succeeds: %+v", grandchild[len(grandchild)-1])
	}
}

func TestRunSpawnRefusals(t *testing.T) {
	root := writeSpawnSample(t)
	// Not on may_spawn: refused, nothing started.
	_, logDir, events := runLead(t, root, "spawn:lead-role/lead-wf:x")
	sp := onlySpawn(t, events)
	if sp.Status != "refused" || sp.ChildRunID != "" || sp.Reason != "spawn target is not on the agent's may_spawn list" {
		t.Fatalf("spawn event = %+v", sp)
	}
	// RBAC denies the child role: refused, and the child has its own
	// run_refused ledger linked to the parent.
	parentID, _, events := runLead(t, root, "spawn:locked/locked-wf:x")
	sp = onlySpawn(t, events)
	if sp.Status != "refused" || sp.ChildRunID == "" || !strings.Contains(sp.Reason, "allowed groups") {
		t.Fatalf("spawn event = %+v", sp)
	}
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(child) != 1 || child[0].Type != "run_refused" || child[0].Binding.ParentRunID != parentID {
		t.Fatalf("child events = %+v", child)
	}
}
