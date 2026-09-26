package config

import (
	"reflect"
	"strings"
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

	// An omitted execution tier is fronted.
	a.Execution = ""
	if a.EffectiveExecution() != "fronted" {
		t.Fatal("EffectiveExecution must return fronted when Execution is empty")
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

func TestExecConfigAllows(t *testing.T) {
	ec := ExecConfig{Mode: "attested", Allow: []ExecEntry{
		{Exe: "go", ArgsPrefix: []string{"test"}},
		{Exe: "rg"},
	}}
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"go", "test", "./..."}, true},
		{[]string{"go", "test"}, true},
		{[]string{"go", "build"}, false},
		{[]string{"go"}, false}, // too short for the [test] prefix
		{[]string{"gofmt", "-w", "."}, false},
		{[]string{"rg"}, true},
		{[]string{"rg", "foo", "-n"}, true},
		{nil, false},
	}
	for _, c := range cases {
		if got := ec.Allows(c.argv); got != c.want {
			t.Errorf("Allows(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

func TestExecConfigDeclared(t *testing.T) {
	if (ExecConfig{}).Declared() {
		t.Error("zero ExecConfig should not be declared")
	}
	if !(ExecConfig{Mode: "attested", Allow: []ExecEntry{{Exe: "go"}}}).Declared() {
		t.Error("populated ExecConfig should be declared")
	}
}

func TestToolGrantScalarGrantsEveryTool(t *testing.T) {
	var got []ToolGrant
	if err := yaml.Unmarshal([]byte("[code-search, github]\n"), &got); err != nil {
		t.Fatal(err)
	}
	want := []ToolGrant{{Resource: "code-search"}, {Resource: "github"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	if got[0].Restricted() {
		t.Fatal("a bare grant must not be Restricted()")
	}
}

func TestToolGrantMappingRestrictsToNamedTools(t *testing.T) {
	src := `
- code-search
- resource: github
  tools: [list_issues, get_issue]
`
	var got []ToolGrant
	if err := yaml.Unmarshal([]byte(src), &got); err != nil {
		t.Fatal(err)
	}
	want := []ToolGrant{
		{Resource: "code-search"},
		{Resource: "github", Tools: []string{"list_issues", "get_issue"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	if got[0].Restricted() || !got[1].Restricted() {
		t.Fatalf("Restricted(): bare=%v restricted=%v", got[0].Restricted(), got[1].Restricted())
	}
}

// TestToolGrantFailsClosed: least privilege must never widen on a typo. Every
// malformed object grant is a load error carrying the bad-tool-grant code,
// never a silently-all-tools grant.
func TestToolGrantFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring of the error after the bad-tool-grant code
	}{
		{"singular tool: typo is an unknown key", "- resource: github\n  tool: [list_issues]\n", `unknown key "tool"`},
		{"future mode: typo is an unknown key", "- resource: github\n  tools: [x]\n  mod: read\n", `unknown key "mod"`},
		{"object with tools absent", "- resource: github\n", "at least one tool"},
		{"object with tools null", "- resource: github\n  tools: null\n", "at least one tool"},
		{"object with tools empty", "- resource: github\n  tools: []\n", "at least one tool"},
		{"object with empty resource", "- resource: \"\"\n  tools: [x]\n", "empty resource"},
		{"object with resource absent", "- tools: [x]\n", "empty resource"},
		{"empty scalar", "- \"\"\n", "empty resource"},
		{"sequence is neither form", "- [github]\n", "resource id string or a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []ToolGrant
			err := yaml.Unmarshal([]byte(tc.src), &got)
			if err == nil {
				t.Fatalf("expected an error, parsed %+v", got)
			}
			if !strings.Contains(err.Error(), "bad-tool-grant: line ") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want bad-tool-grant with %q", err.Error(), tc.want)
			}
		})
	}
}

// TestToolGrantNullElementIsDropped pins a yaml.v3 behavior the guards above
// rely on: a null sequence element whose target is a struct never reaches
// UnmarshalYAML (prepare() returns early on the null tag) and sequence()
// drops it. So `tools: [~]` grants nothing — it does not widen, and it does
// not produce a zero ToolGrant either.
func TestToolGrantNullElementIsDropped(t *testing.T) {
	var got []ToolGrant
	if err := yaml.Unmarshal([]byte("[~]\n"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a null element must be dropped, got %+v", got)
	}
}

func TestToolGrantErrorNamesTheLine(t *testing.T) {
	src := "- code-search\n- resource: github\n  tool: [x]\n"
	var got []ToolGrant
	err := yaml.Unmarshal([]byte(src), &got)
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("error should name the offending key's line (3): %v", err)
	}
}
