package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestAgentDefMaySpawnParsesAndMatchesExactly(t *testing.T) {
	var a AgentDef
	src := "name: lead\nendpoint: https://x\nmay_spawn:\n  - role: worker\n    workflow: child-wf\n  - role: worker\n    workflow: other-wf\n"
	if err := yaml.Unmarshal([]byte(src), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.MaySpawn) != 2 || a.MaySpawn[0] != (SpawnTarget{Role: "worker", Workflow: "child-wf"}) {
		t.Fatalf("may_spawn = %+v", a.MaySpawn)
	}
	if !a.MaySpawnTarget("worker", "child-wf") || !a.MaySpawnTarget("worker", "other-wf") {
		t.Fatal("listed targets must be allowed")
	}
	if a.MaySpawnTarget("worker", "nope") || a.MaySpawnTarget("lead", "child-wf") || a.MaySpawnTarget("", "") {
		t.Fatal("an unlisted role/workflow pair must not be allowed")
	}
	if (AgentDef{}).MaySpawnTarget("worker", "child-wf") {
		t.Fatal("an agent with no may_spawn spawns nothing (default-deny)")
	}
}

func TestGatewaySpawnPolicyAndStepTimeoutParse(t *testing.T) {
	var g GatewayConfig
	src := "spawn:\n  max_depth: 3\n  max_parallel: 4\n  max_total_spawns: 8\n  reject_cycles: true\nstep_timeout: 7m\nspawn_supervisor: unix:///run/agenthof-spawn/refspawn.sock\n"
	if err := yaml.Unmarshal([]byte(src), &g); err != nil {
		t.Fatal(err)
	}
	want := SpawnPolicy{MaxDepth: 3, MaxParallel: 4, MaxTotalSpawns: 8, RejectCycles: true}
	if g.Spawn != want {
		t.Fatalf("spawn = %+v, want %+v", g.Spawn, want)
	}
	if g.StepTimeout != 7*time.Minute || g.EffectiveStepTimeout() != 7*time.Minute {
		t.Fatalf("step_timeout = %v (effective %v), want 7m", g.StepTimeout, g.EffectiveStepTimeout())
	}
	if g.SpawnSupervisor != "unix:///run/agenthof-spawn/refspawn.sock" {
		t.Fatalf("spawn_supervisor = %q", g.SpawnSupervisor)
	}
	if (GatewayConfig{}).EffectiveStepTimeout() != DefaultStepTimeout || DefaultStepTimeout != 5*time.Minute {
		t.Fatalf("an unset step_timeout must mean %v", 5*time.Minute)
	}
}
