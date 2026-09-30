package registry

import (
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
)

// spawnCfg is a lead agent that may spawn worker/child-wf, whose child agent
// may spawn nothing, with a complete spawn policy.
func spawnCfg() config.Config {
	return config.Config{
		Agents: []config.AgentDef{
			{Name: "lead", Endpoint: "https://x", SourceFile: "a/lead.yaml",
				MaySpawn: []config.SpawnTarget{{Role: "worker", Workflow: "child-wf"}}},
			{Name: "child", Endpoint: "https://x", SourceFile: "a/child.yaml"},
		},
		Workflows: []config.WorkflowDef{
			{Name: "lead-wf", SourceFile: "w/lead.yaml", Steps: []config.Step{{Name: "s", Agent: "lead"}}},
			{Name: "child-wf", SourceFile: "w/child.yaml", Steps: []config.Step{{Name: "s", Agent: "child"}}},
		},
		Roles: []config.RoleDef{
			{Name: "lead-role", Workflows: []string{"lead-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r/lead.yaml"},
			{Name: "worker", Workflows: []string{"child-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r/worker.yaml"},
		},
		Gateway: config.GatewayConfig{Spawn: config.SpawnPolicy{MaxDepth: 2, MaxParallel: 2, MaxTotalSpawns: 4}},
	}
}

func errList(errs []ValidationError) []string {
	var out []string
	for _, e := range errs {
		out = append(out, e.Code+": "+e.Msg)
	}
	return out
}

func hasCodeMsg(errs []ValidationError, code, fragment string) bool {
	for _, e := range errs {
		if e.Code == code && strings.Contains(e.Msg, fragment) {
			return true
		}
	}
	return false
}

func TestValidateSpawnHappyPath(t *testing.T) {
	if errs := Validate(spawnCfg()); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errList(errs))
	}
}

func TestValidateSpawnTargets(t *testing.T) {
	cases := []struct {
		name     string
		targets  []config.SpawnTarget
		fragment string
	}{
		{"missing role", []config.SpawnTarget{{Workflow: "child-wf"}}, "both a role and a workflow"},
		{"missing workflow", []config.SpawnTarget{{Role: "worker"}}, "both a role and a workflow"},
		{"unknown role", []config.SpawnTarget{{Role: "ghost", Workflow: "child-wf"}}, `role "ghost", which does not exist`},
		{"unknown workflow", []config.SpawnTarget{{Role: "worker", Workflow: "ghost"}}, `workflow "ghost", which does not exist`},
		{"role does not own", []config.SpawnTarget{{Role: "worker", Workflow: "lead-wf"}}, `role "worker" does not own workflow "lead-wf"`},
		{"duplicate", []config.SpawnTarget{{Role: "worker", Workflow: "child-wf"}, {Role: "worker", Workflow: "child-wf"}}, "more than once"},
	}
	for _, c := range cases {
		cfg := spawnCfg()
		cfg.Agents[0].MaySpawn = c.targets
		errs := Validate(cfg)
		if !hasCodeMsg(errs, "bad-spawn-target", c.fragment) {
			t.Errorf("%s: want bad-spawn-target containing %q, got %v", c.name, c.fragment, errList(errs))
		}
	}
}

func TestValidateSpawnPolicyRequiredOnlyWhenDeclared(t *testing.T) {
	for _, key := range []string{"max_depth", "max_parallel", "max_total_spawns"} {
		cfg := spawnCfg()
		switch key {
		case "max_depth":
			cfg.Gateway.Spawn.MaxDepth = 0
		case "max_parallel":
			cfg.Gateway.Spawn.MaxParallel = 0
		case "max_total_spawns":
			cfg.Gateway.Spawn.MaxTotalSpawns = 0
		}
		if errs := Validate(cfg); !hasCodeMsg(errs, "spawn-policy-required", "spawn."+key) {
			t.Errorf("%s omitted while may_spawn is declared: want spawn-policy-required, got %v", key, errList(errs))
		}
	}
	// No gateway.yaml at all (a zero GatewayConfig) with may_spawn declared:
	// spawn declared, no policy to bound it.
	cfg := spawnCfg()
	cfg.Gateway = config.GatewayConfig{}
	if errs := Validate(cfg); !hasCodeMsg(errs, "spawn-policy-required", "spawn.max_depth") {
		t.Fatalf("may_spawn with no gateway.yaml must be rejected, got %v", errList(errs))
	}
	// No may_spawn anywhere: the block is not required and existing configs
	// stay valid.
	cfg = spawnCfg()
	cfg.Agents[0].MaySpawn = nil
	cfg.Gateway = config.GatewayConfig{}
	if errs := Validate(cfg); len(errs) != 0 {
		t.Fatalf("a config without may_spawn needs no spawn block, got %v", errList(errs))
	}
	// A negative cap is wrong whether or not spawn is in use.
	cfg.Gateway.Spawn.MaxParallel = -1
	if errs := Validate(cfg); !hasCodeMsg(errs, "bad-spawn-policy", "spawn.max_parallel") {
		t.Fatalf("a negative cap must be rejected, got %v", errList(errs))
	}
}

func TestValidateStepTimeout(t *testing.T) {
	cfg := spawnCfg()
	cfg.Gateway.StepTimeout = 500 * time.Millisecond
	if errs := Validate(cfg); !hasCodeMsg(errs, "bad-step-timeout", "at least 1s") {
		t.Fatalf("a sub-second step_timeout must be rejected, got %v", errList(errs))
	}
	cfg.Gateway.StepTimeout = time.Second
	if errs := Validate(cfg); len(errs) != 0 {
		t.Fatalf("1s is the floor, got %v", errList(errs))
	}
}

func TestValidateSpawnCycles(t *testing.T) {
	// child may re-spawn its own workflow: a self-loop at the type level.
	selfLoop := spawnCfg()
	selfLoop.Agents[1].MaySpawn = []config.SpawnTarget{{Role: "worker", Workflow: "child-wf"}}
	if errs := Validate(selfLoop); len(errs) != 0 {
		t.Fatalf("with reject_cycles off a type reused deeper is allowed (depth bounds it), got %v", errList(errs))
	}
	selfLoop.Gateway.Spawn.RejectCycles = true
	if errs := Validate(selfLoop); !hasCodeMsg(errs, "spawn-cycle", "child -> child") {
		t.Fatalf("a self-loop must be rejected with the path, got %v", errList(errs))
	}
	// A two-node cycle: lead -> child (via child-wf) and child -> lead (via lead-wf).
	twoCycle := spawnCfg()
	twoCycle.Roles[1].Workflows = []string{"child-wf", "lead-wf"}
	twoCycle.Agents[1].MaySpawn = []config.SpawnTarget{{Role: "worker", Workflow: "lead-wf"}}
	twoCycle.Gateway.Spawn.RejectCycles = true
	if errs := Validate(twoCycle); !hasCodeMsg(errs, "spawn-cycle", "child -> lead -> child") {
		t.Fatalf("a two-node cycle must be rejected with the path, got %v", errList(errs))
	}
	// A diamond is a DAG, never a cycle: lead -> a, lead -> b, a -> c, b -> c.
	diamond := config.Config{
		Agents: []config.AgentDef{
			{Name: "lead", Endpoint: "https://x", SourceFile: "a", MaySpawn: []config.SpawnTarget{{Role: "r", Workflow: "a-wf"}, {Role: "r", Workflow: "b-wf"}}},
			{Name: "a", Endpoint: "https://x", SourceFile: "a", MaySpawn: []config.SpawnTarget{{Role: "r", Workflow: "c-wf"}}},
			{Name: "b", Endpoint: "https://x", SourceFile: "a", MaySpawn: []config.SpawnTarget{{Role: "r", Workflow: "c-wf"}}},
			{Name: "c", Endpoint: "https://x", SourceFile: "a"},
		},
		Workflows: []config.WorkflowDef{
			{Name: "lead-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "lead"}}},
			{Name: "a-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "a"}}},
			{Name: "b-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "b"}}},
			{Name: "c-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "c"}}},
		},
		Roles:   []config.RoleDef{{Name: "r", Workflows: []string{"lead-wf", "a-wf", "b-wf", "c-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
		Gateway: config.GatewayConfig{Spawn: config.SpawnPolicy{MaxDepth: 3, MaxParallel: 2, MaxTotalSpawns: 4, RejectCycles: true}},
	}
	if errs := Validate(diamond); len(errs) != 0 {
		t.Fatalf("a diamond is acyclic, got %v", errList(errs))
	}
}
