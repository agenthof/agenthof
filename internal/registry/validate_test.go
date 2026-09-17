package registry

import (
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

func baseCfg() config.Config {
	f := false
	_ = f
	return config.Config{
		Agents: []config.AgentDef{
			{Name: "planner", Model: "fast", SourceFile: "agents/planner.yaml"},
			{Name: "coder", Model: "fast", SourceFile: "agents/coder.yaml"},
		},
		Workflows: []config.WorkflowDef{{
			Name:       "fix-bug",
			SourceFile: "workflows/fix-bug.yaml",
			Steps: []config.Step{
				{Name: "plan", Agent: "planner"},
				{Name: "code", Agent: "coder", OnFailure: "plan"},
			},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"fix-bug"}, SourceFile: "roles/se.yaml"}},
		Gateway: config.GatewayConfig{Models: map[string]config.ModelRoute{
			"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"},
		}},
	}
}

func codes(errs []ValidationError) map[string]int {
	m := map[string]int{}
	for _, e := range errs {
		m[e.Code]++
	}
	return m
}

func TestValidateHappyPath(t *testing.T) {
	if errs := Validate(baseCfg()); len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
}

func TestValidateDanglingAndDisabledRefs(t *testing.T) {
	cfg := baseCfg()
	f := false
	cfg.Agents[1].Enabled = &f // disable coder
	cfg.Workflows[0].Steps = append(cfg.Workflows[0].Steps, config.Step{Name: "ghost", Agent: "reviewer", OnFailure: "code"})
	errs := Validate(cfg)
	c := codes(errs)
	if c["dangling-agent-ref"] != 1 || c["disabled-agent-ref"] != 1 {
		t.Fatalf("codes: %v (%v)", c, errs)
	}
	var disabledMsg string
	for _, e := range errs {
		if e.Code == "disabled-agent-ref" {
			disabledMsg = e.Msg
		}
	}
	if !strings.Contains(disabledMsg, "fix-bug") {
		t.Fatalf("disabled-agent error must name the dependent workflow: %q", disabledMsg)
	}
}

func TestValidateGraphRules(t *testing.T) {
	cfg := baseCfg()
	cfg.Workflows[0].Steps[0].OnFailure = "code" // forward fail-back: illegal
	if c := codes(Validate(cfg)); c["bad-graph"] != 1 {
		t.Fatalf("forward on_failure must be bad-graph: %v", c)
	}
	cfg = baseCfg()
	cfg.Workflows[0].Steps[0].OnSuccess = "plan" // self/backward success: illegal
	if c := codes(Validate(cfg)); c["bad-graph"] != 1 {
		t.Fatalf("non-linear on_success must be bad-graph: %v", c)
	}
	cfg = baseCfg()
	cfg.Workflows[0].Steps[1].OnSuccess = "finish" // allowed on last step
	if errs := Validate(cfg); len(errs) != 0 {
		t.Fatalf("finish on last step must be legal: %v", errs)
	}
}

func TestValidateModelsRolesBounces(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents[0].Model = "unknown"
	cfg.Roles[0].Workflows = []string{"nope"}
	cfg.Workflows[0].Steps[1].MaxBounces = 99
	c := codes(Validate(cfg))
	if c["unroutable-model"] != 1 || c["dangling-workflow-ref"] != 1 || c["bad-bounces"] != 1 {
		t.Fatalf("codes: %v", c)
	}
	cfg = baseCfg()
	cfg.Gateway.Defaults.Model = "fast"
	cfg.Agents[0].Model = "" // empty model falls back to gateway default: legal
	if errs := Validate(cfg); len(errs) != 0 {
		t.Fatalf("default-model fallback must be legal: %v", errs)
	}
}

func TestValidateDuplicatesAndEmptiness(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents = append(cfg.Agents, config.AgentDef{Name: "planner", Model: "fast", SourceFile: "agents/dup.yaml"})
	cfg.Workflows = append(cfg.Workflows, config.WorkflowDef{Name: "empty", SourceFile: "workflows/empty.yaml"})
	cfg.Roles = append(cfg.Roles, config.RoleDef{Name: "idle", SourceFile: "roles/idle.yaml"})
	c := codes(Validate(cfg))
	if c["duplicate-name"] != 1 || c["no-steps"] != 1 || c["no-workflows"] != 1 {
		t.Fatalf("codes: %v", c)
	}
}

func TestValidateExecutionTiers(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents[0].Execution = "invalid"
	c := codes(Validate(cfg))
	if c["bad-execution"] != 1 {
		t.Fatalf("invalid execution must be bad-execution: %v", c)
	}

	// Test fronted agent without endpoint
	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	c = codes(Validate(cfg))
	if c["fronted-needs-endpoint"] != 1 {
		t.Fatalf("fronted without endpoint must be fronted-needs-endpoint: %v", c)
	}

	// Test contained agent with endpoint
	cfg = baseCfg()
	cfg.Agents[0].Execution = "contained"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	c = codes(Validate(cfg))
	if c["contained-has-endpoint"] != 1 {
		t.Fatalf("contained with endpoint must be contained-has-endpoint: %v", c)
	}

	// Test fronted agent with tools
	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	cfg.Agents[0].Tools = []string{"read_file", "write_file"}
	c = codes(Validate(cfg))
	if c["bad-execution"] != 1 {
		t.Fatalf("fronted with tools must be bad-execution: %v", c)
	}

	// Test fronted agent with endpoint, no model, no tools - should pass
	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	cfg.Agents[0].Model = ""
	cfg.Agents[0].Tools = []string{}
	errs := Validate(cfg)
	// Filter to just agent-related errors
	agentErrs := []ValidationError{}
	for _, e := range errs {
		if e.Entity == "planner" {
			agentErrs = append(agentErrs, e)
		}
	}
	if len(agentErrs) != 0 {
		t.Fatalf("fronted agent with endpoint and no model should pass: %v", agentErrs)
	}

	// Test that empty execution defaults to contained (no endpoint needed)
	cfg = baseCfg()
	cfg.Agents[0].Execution = ""
	cfg.Agents[0].Endpoint = ""
	if errs := Validate(cfg); len(errs) != 0 {
		t.Fatalf("agent with empty execution should default to contained: %v", errs)
	}
}
