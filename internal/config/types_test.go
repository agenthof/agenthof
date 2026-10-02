package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestAgentDefYAMLRoundTrip(t *testing.T) {
	src := `
name: planner
description: Plans the work
model: fast
instruction: You are a planner.
tools:
  - resource: read_file
    mode: all
  - resource: search_files
    mode: all
output: plan
`
	var a AgentDef
	if err := yaml.Unmarshal([]byte(src), &a); err != nil {
		t.Fatal(err)
	}
	if a.Name != "planner" || a.Model != "fast" || len(a.Tools) != 2 || a.Output != "plan" {
		t.Fatalf("parsed: %+v", a)
	}
	// Each mode: all entry grants every tool that resource exposes.
	// (ToolGrant holds a slice, so it is not ==-comparable; compare the
	// fields.)
	if a.Tools[0].Resource != "read_file" || a.Tools[0].Scope() != ScopeAll ||
		a.Tools[1].Resource != "search_files" || a.Tools[1].Scope() != ScopeAll {
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
	ec := ExecConfig{Allow: []ExecEntry{
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
	cases := map[string]ExecConfig{
		"allow only":   {Allow: []ExecEntry{{Exe: "go"}}},
		"runtime only": {Runtime: "refexec"},
		"url only":     {URL: "unix:///run/agenthof-exec/refexec.sock"},
		"timeout only": {Timeout: time.Minute},
	}
	for name, ec := range cases {
		if !ec.Declared() {
			t.Errorf("%s: a {%+v}-only exec must count as declared, or apply never sees it", name, ec)
		}
	}
}

// TestToolGrantScalarRejected: a bare resource id is no longer a grant. The
// error names the line and both replacements. yaml.v3 stops at the first
// element whose UnmarshalYAML fails, so a list with two bare ids reports the
// first one and aborts that file's parse — it does not enumerate them.
func TestToolGrantScalarRejected(t *testing.T) {
	var got []ToolGrant
	err := yaml.Unmarshal([]byte("- resource: ok\n  mode: all\n- code-search\n- github\n"), &got)
	if err == nil {
		t.Fatalf("expected an error, parsed %+v", got)
	}
	msg := err.Error()
	for _, want := range []string{
		"bad-tool-grant: line 3: a bare tool grant is no longer accepted",
		`{resource: "code-search", tools: [...]}`,
		`{resource: "code-search", mode: all}`,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error = %q, want it to contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "github") {
		t.Fatalf("only the first offending element is reported, got %q", msg)
	}
}

func TestToolGrantMappingRestrictsToNamedTools(t *testing.T) {
	src := `
- resource: code-search
  mode: all
- resource: github
  tools: [list_issues, get_issue]
`
	var got []ToolGrant
	if err := yaml.Unmarshal([]byte(src), &got); err != nil {
		t.Fatal(err)
	}
	want := []ToolGrant{
		{Resource: "code-search", Mode: "all"},
		{Resource: "github", Tools: []string{"list_issues", "get_issue"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	if got[0].Scope() != ScopeAll || got[1].Scope() != ScopeNamed {
		t.Fatalf("Scope(): all=%v restricted=%v", got[0].Scope(), got[1].Scope())
	}
}

func TestToolGrantToolsAcceptsAlias(t *testing.T) {
	src := `
tools:
  - resource: a
    tools: &shared [list_issues, get_issue]
  - resource: b
    tools: *shared
`
	var got struct {
		Tools []ToolGrant `yaml:"tools"`
	}
	if err := yaml.Unmarshal([]byte(src), &got); err != nil {
		t.Fatal(err)
	}
	want := []string{"list_issues", "get_issue"}
	if len(got.Tools) != 2 || !reflect.DeepEqual(got.Tools[1].Tools, want) {
		t.Fatalf("parsed %+v, want second grant tools %v", got.Tools, want)
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
		{"object with tools absent", "- resource: github\n", "must set tools or mode"},
		{"object with tools absent names both remedies", "- resource: github\n", "or write mode: all to grant every tool"},
		{"object with tools null", "- resource: github\n  tools: null\n", "at least one tool"},
		{"object with tools empty", "- resource: github\n  tools: []\n", "at least one tool"},
		{"object with empty resource", "- resource: \"\"\n  tools: [x]\n", "empty resource"},
		{"object with resource absent", "- tools: [x]\n", "empty resource"},
		{"empty scalar", "- \"\"\n", "empty resource"},
		{"sequence is neither form", "- [github]\n", "must be a {resource, tools, mode} object"},
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

func TestToolGrantScope(t *testing.T) {
	cases := []struct {
		name string
		g    ToolGrant
		want GrantScope
	}{
		{"no mode and no tools", ToolGrant{Resource: "github"}, ScopeNamed},
		{"no mode, empty tools slice", ToolGrant{Resource: "github", Tools: []string{}}, ScopeNamed},
		{"mode all", ToolGrant{Resource: "github", Mode: "all"}, ScopeAll},
		{"named tools", ToolGrant{Resource: "github", Tools: []string{"echo"}}, ScopeNamed},
		{"read-only", ToolGrant{Resource: "github", Mode: "read-only"}, ScopeReadOnly},
		{"named and read-only", ToolGrant{Resource: "github", Mode: "read-only", Tools: []string{"echo"}}, ScopeReadOnly},
		{"bad mode is not all", ToolGrant{Resource: "github", Mode: "write"}, ScopeNamed},
	}
	for _, tc := range cases {
		if got := tc.g.Scope(); got != tc.want {
			t.Errorf("%s: Scope = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestToolGrantModeYAML(t *testing.T) {
	ok := []struct {
		name string
		src  string
		want ToolGrant
	}{
		{"mode all", "- resource: github\n  mode: all\n", ToolGrant{Resource: "github", Mode: "all"}},
		{"mode read-only", "- resource: github\n  mode: read-only\n", ToolGrant{Resource: "github", Mode: "read-only"}},
		{"tools plus read-only", "- resource: github\n  tools: [echo]\n  mode: read-only\n", ToolGrant{Resource: "github", Tools: []string{"echo"}, Mode: "read-only"}},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			var got []ToolGrant
			if err := yaml.Unmarshal([]byte(tc.src), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || !reflect.DeepEqual(got[0], tc.want) {
				t.Fatalf("parsed %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestToolGrantModeRejected(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"bad mode", "- resource: github\n  mode: write\n", `mode "write"`},
		{"neither tools nor mode", "- resource: github\n", "must set tools or mode"},
		{"mode empty string is neither", "- resource: github\n  mode: \"\"\n", "must set tools or mode"},
		{"mode null is neither", "- resource: github\n  mode: null\n", "must set tools or mode"},
		{"empty tools with read-only", "- resource: github\n  tools: []\n  mode: read-only\n", "at least one tool"},
		{"empty tools with all", "- resource: github\n  tools: []\n  mode: all\n", "at least one tool"},
		{"mode all plus tools", "- resource: github\n  mode: all\n  tools: [echo]\n", "mode all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []ToolGrant
			err := yaml.Unmarshal([]byte(tc.src), &got)
			if err == nil {
				t.Fatalf("expected an error, parsed %+v", got)
			}
			if !strings.Contains(err.Error(), "bad-tool-grant: line ") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.want)
			}
		})
	}
}

func TestToolGrantErrorNamesTheLine(t *testing.T) {
	src := "- resource: ok\n  mode: all\n- resource: github\n  tool: [x]\n"
	var got []ToolGrant
	err := yaml.Unmarshal([]byte(src), &got)
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("error should name the offending key's line (4): %v", err)
	}
}

func TestExecConfigRuntimeYAML(t *testing.T) {
	var a AgentDef
	err := yaml.Unmarshal([]byte(`name: builder
execution: fronted
endpoint: unix:///run/agenthof/agent.sock
exec:
  runtime: refexec
  url: unix:///run/agenthof-exec/refexec.sock
  timeout: 5m
  allow:
    - exe: go
      args_prefix: [test]
`), &a)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a.Exec.Runtime != "refexec" || a.Exec.URL != "unix:///run/agenthof-exec/refexec.sock" || a.Exec.Timeout != 5*time.Minute ||
		len(a.Exec.Allow) != 1 || a.Exec.Allow[0].Exe != "go" || !reflect.DeepEqual(a.Exec.Allow[0].ArgsPrefix, []string{"test"}) {
		t.Fatalf("exec = %+v", a.Exec)
	}
}

// TestExecConfigRejectsStaleModeKey: exec.mode is retired. A block that still
// carries it — on an otherwise valid first-hand shape, or the old
// agent-reported shape — is rejected at load, naming the key's line and the
// replacement, never read with the key silently dropped.
func TestExecConfigRejectsStaleModeKey(t *testing.T) {
	const want = "exec.mode is no longer supported; exec is always first-hand via a runtime (set runtime/url/timeout)"
	cases := map[string]string{
		"runtime shape with mode": "name: builder\nexecution: fronted\nendpoint: unix:///run/agenthof/agent.sock\nexec:\n  mode: runtime\n  runtime: refexec\n  url: unix:///run/agenthof-exec/refexec.sock\n  timeout: 5m\n  allow:\n    - exe: go\n",
		"old attested shape":      "name: builder\nexecution: fronted\nendpoint: unix:///run/agenthof/agent.sock\nexec:\n  mode: attested\n  allow:\n    - exe: go\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			var a AgentDef
			err := yaml.Unmarshal([]byte(src), &a)
			if err == nil {
				t.Fatalf("a stale exec.mode must be rejected, parsed %+v", a.Exec)
			}
			if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "bad-exec-config: line 5:") {
				t.Fatalf("error must name the key's line and the replacement: %v", err)
			}
		})
	}
}

// TestExecConfigNullBlockStaysUndeclared: a bare `exec:` with no value never
// reaches UnmarshalYAML (yaml.v3 skips it for a null node) and declares nothing.
func TestExecConfigNullBlockStaysUndeclared(t *testing.T) {
	var a AgentDef
	if err := yaml.Unmarshal([]byte("name: builder\nexec:\n"), &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a.Exec.Declared() {
		t.Fatalf("a bare exec: with no value must stay undeclared, got %+v", a.Exec)
	}
}
