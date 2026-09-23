package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAgentDefYAMLRoundTrip(t *testing.T) {
	src := `
name: planner
description: Plans the work
model: fast
instruction: You are a planner.
tools: [read_file, search_files]
output: plan
`
	var a AgentDef
	if err := yaml.Unmarshal([]byte(src), &a); err != nil {
		t.Fatal(err)
	}
	if a.Name != "planner" || a.Model != "fast" || len(a.Tools) != 2 || a.Output != "plan" {
		t.Fatalf("parsed: %+v", a)
	}
	if !a.IsEnabled() {
		t.Fatal("enabled must default to true when omitted")
	}
	f := false
	a.Enabled = &f
	if a.IsEnabled() {
		t.Fatal("explicit enabled: false must win")
	}
}

func TestAgentDefExecutionAndEndpoint(t *testing.T) {
	// Test YAML parsing with execution and endpoint
	src := `
name: api-agent
model: fast
instruction: Call external API
output: response
execution: fronted
endpoint: https://api.example.com/agent
`
	var a AgentDef
	if err := yaml.Unmarshal([]byte(src), &a); err != nil {
		t.Fatal(err)
	}
	if a.Execution != "fronted" || a.Endpoint != "https://api.example.com/agent" {
		t.Fatalf("parsed: %+v", a)
	}
	if a.EffectiveExecution() != "fronted" {
		t.Fatal("EffectiveExecution must return fronted")
	}

	// Test EffectiveExecution: empty Execution defaults to contained
	a.Execution = ""
	if a.EffectiveExecution() != "contained" {
		t.Fatal("EffectiveExecution must return contained when Execution is empty")
	}

	// Test explicit contained
	a.Execution = "contained"
	if a.EffectiveExecution() != "contained" {
		t.Fatal("EffectiveExecution must return contained")
	}
}

func TestWorkflowAndRoleParse(t *testing.T) {
	wsrc := `
name: fix-bug
steps:
  - name: plan
    agent: planner
  - name: code
    agent: coder
    on_failure: plan
    max_bounces: 2
`
	var w WorkflowDef
	if err := yaml.Unmarshal([]byte(wsrc), &w); err != nil {
		t.Fatal(err)
	}
	if len(w.Steps) != 2 || w.Steps[1].OnFailure != "plan" || w.Steps[1].MaxBounces != 2 {
		t.Fatalf("parsed: %+v", w)
	}
	rsrc := `
name: software-engineer
workflows: [fix-bug]
allowed_groups: [engineering]
budget_usd_month: 50
`
	var r RoleDef
	if err := yaml.Unmarshal([]byte(rsrc), &r); err != nil {
		t.Fatal(err)
	}
	if r.Workflows[0] != "fix-bug" || r.BudgetUSDMonth != 50 {
		t.Fatalf("parsed: %+v", r)
	}
}

func TestGatewayToolsParse(t *testing.T) {
	src := `
models:
  fast:
    endpoint: https://x/v1
    model: m
    api_key_env: K
tools:
  github:
    kind: mcp
    url: https://mcp.example.com/mcp
    credential_source: static_env
    token_env: GITHUB_MCP_TOKEN
defaults:
  model: fast
`
	var gw GatewayConfig
	if err := yaml.Unmarshal([]byte(src), &gw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	r, ok := gw.Tools["github"]
	if !ok {
		t.Fatalf("tools[github] missing; got %+v", gw.Tools)
	}
	if r.Kind != "mcp" || r.URL != "https://mcp.example.com/mcp" ||
		r.CredentialSource != "static_env" || r.TokenEnv != "GITHUB_MCP_TOKEN" {
		t.Fatalf("tool resource mismatch: %+v", r)
	}
}
