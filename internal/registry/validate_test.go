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
			{Name: "planner", Model: "fast", Endpoint: "https://example.test/run", SourceFile: "agents/planner.yaml"},
			{Name: "coder", Model: "fast", Endpoint: "https://example.test/run", SourceFile: "agents/coder.yaml"},
		},
		Workflows: []config.WorkflowDef{{
			Name:       "fix-bug",
			SourceFile: "workflows/fix-bug.yaml",
			Steps: []config.Step{
				{Name: "plan", Agent: "planner"},
				{Name: "code", Agent: "coder", OnFailure: "plan"},
			},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"fix-bug"}, AllowedGroups: []string{"*"}, SourceFile: "roles/se.yaml"}},
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

func hasCode(errs []ValidationError, code string) bool {
	for _, e := range errs {
		if e.Code == code {
			return true
		}
	}
	return false
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
	cfg.Roles[0].Workflows = []string{"nope"}
	cfg.Workflows[0].Steps[1].MaxBounces = 99
	c := codes(Validate(cfg))
	if c["dangling-workflow-ref"] != 1 || c["bad-bounces"] != 1 {
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
	cfg.Roles = append(cfg.Roles, config.RoleDef{Name: "idle", AllowedGroups: []string{"*"}, SourceFile: "roles/idle.yaml"})
	c := codes(Validate(cfg))
	if c["duplicate-name"] != 1 || c["no-steps"] != 1 || c["no-workflows"] != 1 {
		t.Fatalf("codes: %v", c)
	}
}

func TestValidateRejectsRoleWithNoAccessFloor(t *testing.T) {
	cfg := config.Config{
		Workflows: []config.WorkflowDef{{Name: "fix-bug", Steps: []config.Step{{Name: "s", Agent: "a"}}, SourceFile: "workflows/fix-bug.yaml"}},
		Agents:    []config.AgentDef{{Name: "a", Instruction: "x", Output: "o", SourceFile: "agents/a.yaml"}},
		Roles:     []config.RoleDef{{Name: "se", Workflows: []string{"fix-bug"}, SourceFile: "roles/se.yaml"}},
	}
	errs := Validate(cfg)
	if !hasCode(errs, "no-access-floor") {
		t.Fatalf("expected no-access-floor error, got %v", errs)
	}
}

func TestValidateAcceptsPublicMarker(t *testing.T) {
	cfg := config.Config{
		Workflows: []config.WorkflowDef{{Name: "fix-bug", Steps: []config.Step{{Name: "s", Agent: "a"}}, SourceFile: "workflows/fix-bug.yaml"}},
		Agents:    []config.AgentDef{{Name: "a", Instruction: "x", Output: "o", SourceFile: "agents/a.yaml"}},
		Roles:     []config.RoleDef{{Name: "se", Workflows: []string{"fix-bug"}, AllowedGroups: []string{"*"}, SourceFile: "roles/se.yaml"}},
	}
	if hasCode(Validate(cfg), "no-access-floor") {
		t.Fatalf("public role [\"*\"] must not trigger no-access-floor")
	}
}

func TestValidateExecutionTiers(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents[0].Execution = "invalid"
	c := codes(Validate(cfg))
	if c["bad-execution"] != 1 {
		t.Fatalf("invalid execution must be bad-execution: %v", c)
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = "contained"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	c = codes(Validate(cfg))
	if c["bad-execution"] != 1 || c["contained-has-endpoint"] != 0 {
		t.Fatalf("contained must be bad-execution: %v", c)
	}
	var containedMsg string
	for _, e := range Validate(cfg) {
		if e.Code == "bad-execution" {
			containedMsg = e.Msg
		}
	}
	if !strings.Contains(containedMsg, "was removed") {
		t.Fatalf("contained rejection must explain the migration: %q", containedMsg)
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = ""
	c = codes(Validate(cfg))
	if c["fronted-needs-endpoint"] != 1 {
		t.Fatalf("fronted without endpoint must be fronted-needs-endpoint: %v", c)
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = ""
	cfg.Agents[0].Endpoint = ""
	errs := Validate(cfg)
	if codes(errs)["fronted-needs-endpoint"] != 1 {
		t.Fatalf("empty execution without endpoint must be fronted-needs-endpoint: %v", errs)
	}
	var emptyMsg string
	for _, e := range errs {
		if e.Code == "fronted-needs-endpoint" && e.Entity == "planner" {
			emptyMsg = e.Msg
		}
	}
	if !strings.Contains(emptyMsg, "contained tier was removed") {
		t.Fatalf("omitted execution must explain the migration: %q", emptyMsg)
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = ""
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	if errs := Validate(cfg); len(errs) != 0 {
		t.Fatalf("empty execution with an endpoint is fronted and valid: %v", errs)
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "http://remote.example/run"
	if !hasCode(Validate(cfg), "bad-endpoint") {
		t.Fatal("plaintext remote endpoint must be bad-endpoint")
	}
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	if hasCode(Validate(cfg), "bad-endpoint") {
		t.Fatal("https endpoint must be accepted")
	}
	cfg.Agents[0].Endpoint = "http://127.0.0.1:8080/"
	if hasCode(Validate(cfg), "bad-endpoint") {
		t.Fatal("loopback http endpoint must be accepted")
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	cfg.Agents[0].Tools = []config.ToolGrant{{Resource: "github"}}
	cfg.Gateway.Tools = map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: "https://mcp/x", CredentialSource: "static_env", TokenEnv: "T"},
	}
	c = codes(Validate(cfg))
	if c["unknown-tool"] != 0 || c["bad-execution"] != 0 {
		t.Fatalf("fronted agent with declared gateway tool must be valid: %v", c)
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = "contained"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	cfg.Agents[0].Tools = []config.ToolGrant{{Resource: "nope"}}
	if codes(Validate(cfg))["unknown-tool"] != 1 {
		t.Fatal("unknown-tool must run for every agent, including one marked contained")
	}

	cfg = baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "https://example.com/agent"
	cfg.Agents[0].Model = ""
	cfg.Agents[0].Tools = nil
	agentErrs := []ValidationError{}
	for _, e := range Validate(cfg) {
		if e.Entity == "planner" {
			agentErrs = append(agentErrs, e)
		}
	}
	if len(agentErrs) != 0 {
		t.Fatalf("fronted agent with endpoint and no model should pass: %v", agentErrs)
	}
}

func TestFrontedAgentDeclaredToolValid(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "https://x"
	cfg.Agents[0].Tools = []config.ToolGrant{{Resource: "github"}}
	cfg.Gateway.Tools = map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: "https://mcp/x", CredentialSource: "static_env", TokenEnv: "T"},
	}
	if c := codes(Validate(cfg)); c["unknown-tool"] != 0 || c["bad-execution"] != 0 {
		t.Fatalf("declared fronted tool must be valid: %v", c)
	}
}

func TestFrontedAgentUndeclaredToolRejected(t *testing.T) {
	cfg := baseCfg()
	cfg.Agents[0].Execution = "fronted"
	cfg.Agents[0].Endpoint = "https://x"
	cfg.Agents[0].Tools = []config.ToolGrant{{Resource: "nope"}}
	if codes(Validate(cfg))["unknown-tool"] != 1 {
		t.Fatalf("undeclared tool must be unknown-tool")
	}
}

// TestValidateToolGrants covers the grant-level rules: a grant must name a
// declared resource and non-empty tool names; a resource may be granted more
// than once ONLY as bare grants (tolerated today, so still tolerated —
// Article VI additivity); any duplicate involving a restricted grant is
// ambiguous and rejected.
func TestValidateToolGrants(t *testing.T) {
	withGrants := func(grants []config.ToolGrant) config.Config {
		cfg := baseCfg()
		cfg.Agents[0].Tools = grants
		cfg.Gateway.Tools = map[string]config.ToolResource{
			"github": {Kind: "mcp", URL: "https://mcp/x", CredentialSource: "static_env", TokenEnv: "T"},
		}
		return cfg
	}
	cases := []struct {
		name   string
		grants []config.ToolGrant
		code   string // "" = the agent must validate clean
	}{
		{"bare grant", []config.ToolGrant{{Resource: "github"}}, ""},
		{"restricted grant", []config.ToolGrant{{Resource: "github", Tools: []string{"list_issues", "get_issue"}}}, ""},
		{"bare duplicates tolerated", []config.ToolGrant{{Resource: "github"}, {Resource: "github"}}, ""},
		{"unknown resource on a restricted grant", []config.ToolGrant{{Resource: "nope", Tools: []string{"x"}}}, "unknown-tool"},
		{"empty tool name", []config.ToolGrant{{Resource: "github", Tools: []string{"list_issues", ""}}}, "bad-tool-grant"},
		{"empty resource", []config.ToolGrant{{Resource: ""}}, "bad-tool-grant"},
		{"bare then restricted duplicate", []config.ToolGrant{{Resource: "github"}, {Resource: "github", Tools: []string{"x"}}}, "bad-tool-grant"},
		{"restricted then bare duplicate", []config.ToolGrant{{Resource: "github", Tools: []string{"x"}}, {Resource: "github"}}, "bad-tool-grant"},
		{"two restricted duplicates", []config.ToolGrant{{Resource: "github", Tools: []string{"x"}}, {Resource: "github", Tools: []string{"y"}}}, "bad-tool-grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var agentErrs []ValidationError
			for _, e := range Validate(withGrants(tc.grants)) {
				if e.Entity == "planner" {
					agentErrs = append(agentErrs, e)
				}
			}
			c := codes(agentErrs)
			if tc.code == "" {
				if len(agentErrs) != 0 {
					t.Fatalf("expected a clean agent, got %v", agentErrs)
				}
				return
			}
			if c[tc.code] != 1 {
				t.Fatalf("codes = %v, want exactly one %s (errs: %v)", c, tc.code, agentErrs)
			}
			if tc.name == "empty resource" && c["unknown-tool"] != 0 {
				t.Fatalf("an empty resource must be reported once, as bad-tool-grant, not also as unknown-tool: %v", agentErrs)
			}
		})
	}
}

func TestBadCredentialSourceRejected(t *testing.T) {
	cfg := baseCfg()
	cfg.Gateway.Tools = map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: "https://mcp/x", CredentialSource: "client_credentials", TokenEnv: "T"},
	}
	if codes(Validate(cfg))["bad-tool-resource"] != 1 {
		t.Fatalf("unimplemented credential_source must be bad-tool-resource")
	}
}

func TestValidateClientCredentialsToolResource(t *testing.T) {
	base := func(mut func(*config.ToolResource)) config.Config {
		r := config.ToolResource{
			Kind: "mcp", URL: "https://mcp.example.com/", CredentialSource: "static_env",
			GrantType: "client_credentials", ClientAuth: "client_secret_basic",
			Issuer: "https://id.example.com", TokenEndpoint: "https://id.example.com/token",
			ClientIDEnv: "CC_ID", ClientSecretEnv: "CC_SECRET",
		}
		mut(&r)
		return config.Config{Gateway: config.GatewayConfig{Tools: map[string]config.ToolResource{"t": r}}}
	}
	cases := []struct {
		name string
		mut  func(*config.ToolResource)
		want bool // want a bad-tool-resource finding
	}{
		{"valid", func(*config.ToolResource) {}, false},
		{"loopback http ok", func(r *config.ToolResource) { r.TokenEndpoint = "http://127.0.0.1:9/token" }, false},
		{"reserved grant", func(r *config.ToolResource) { r.GrantType = "token_exchange" }, true},
		{"reserved client_auth", func(r *config.ToolResource) { r.ClientAuth = "private_key_jwt" }, true},
		{"missing issuer", func(r *config.ToolResource) { r.Issuer = "" }, true},
		{"missing token_endpoint", func(r *config.ToolResource) { r.TokenEndpoint = "" }, true},
		{"missing client_id_env", func(r *config.ToolResource) { r.ClientIDEnv = "" }, true},
		{"missing client_secret_env", func(r *config.ToolResource) { r.ClientSecretEnv = "" }, true},
		{"plaintext non-loopback endpoint", func(r *config.ToolResource) { r.TokenEndpoint = "http://id.example.com/token" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := Validate(base(tc.mut))
			if got := hasCode(errs, "bad-tool-resource"); got != tc.want {
				t.Fatalf("bad-tool-resource finding = %v, want %v (errs: %v)", got, tc.want, errs)
			}
		})
	}
}

func TestValidateToolResourceURLMustBeSecure(t *testing.T) {
	cfg := func(u string) config.Config {
		return config.Config{Gateway: config.GatewayConfig{Tools: map[string]config.ToolResource{
			"t": {Kind: "mcp", URL: u, CredentialSource: "static_env", TokenEnv: "T"},
		}}}
	}
	cases := []struct {
		url string
		bad bool
	}{
		{"https://mcp.example.com/", false},
		{"http://127.0.0.1:8080/", false}, // loopback ok (tests/local)
		{"http://localhost:8080/", false},
		{"http://[::1]:8080/", false},     // ::1 is loopback too
		{"http://mcp.example.com/", true}, // plaintext remote → rejected
		{"", true},                        // empty → rejected (as today)
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			if got := hasCode(Validate(cfg(tc.url)), "bad-tool-resource"); got != tc.bad {
				t.Fatalf("url %q: bad-tool-resource = %v, want %v", tc.url, got, tc.bad)
			}
		})
	}
}

func TestValidateExecConfig(t *testing.T) {
	agent := func(mut func(*config.AgentDef)) config.Config {
		a := config.AgentDef{Name: "a", Execution: "fronted", Endpoint: "https://a.internal/run",
			Exec: config.ExecConfig{Mode: "attested", Allow: []config.ExecEntry{{Exe: "go", ArgsPrefix: []string{"test"}}}}}
		mut(&a)
		return config.Config{Agents: []config.AgentDef{a}}
	}
	cases := []struct {
		name string
		mut  func(*config.AgentDef)
		bad  bool
	}{
		{"valid", func(*config.AgentDef) {}, false},
		{"enforced reserved", func(a *config.AgentDef) { a.Exec.Mode = "enforced" }, true},
		{"empty mode", func(a *config.AgentDef) { a.Exec.Mode = "" }, true},
		{"empty allow", func(a *config.AgentDef) { a.Exec.Allow = nil }, true},
		{"empty exe", func(a *config.AgentDef) { a.Exec.Allow = []config.ExecEntry{{Exe: ""}} }, true},
		{"exec on contained", func(a *config.AgentDef) { a.Execution = "contained"; a.Endpoint = "" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasCode(Validate(agent(tc.mut)), "bad-exec-config"); got != tc.bad {
				t.Fatalf("bad-exec-config = %v, want %v", got, tc.bad)
			}
		})
	}
}

func TestValidAgentEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://agent.example/", true},
		{"http://127.0.0.1:8080/", true},
		{"http://evil.example/", false},
		{"unix:///run/agenthof/agent.sock", true},
		{"unix://run/agenthof/agent.sock", false}, // relative path (two slashes) rejected
		{"unix://", false},
		{"", false},
	}
	for _, c := range cases {
		if got := validAgentEndpoint(c.in); got != c.want {
			t.Errorf("validAgentEndpoint(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUnixEndpointRejectedForToolResource(t *testing.T) {
	if validSecureEndpoint("unix:///run/x.sock") {
		t.Fatal("validSecureEndpoint accepted unix:// — tool/token endpoints must stay https/loopback only")
	}
}
