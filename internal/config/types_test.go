package config

import (
	"reflect"
	"slices"
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
    tools: ["*"]
    mode: read-write
  - resource: search_files
    tools: ["*"]
    mode: read-write
output: plan
`
	var a AgentDef
	if err := yaml.Unmarshal([]byte(src), &a); err != nil {
		t.Fatal(err)
	}
	if a.Name != "planner" || a.Model != "fast" || len(a.Tools) != 2 || a.Output != "plan" {
		t.Fatalf("parsed: %+v", a)
	}
	// Each ["*"] + read-write entry grants every tool that resource exposes.
	// (ToolGrant holds a slice, so it is not ==-comparable; compare the
	// fields.)
	if a.Tools[0].Resource != "read_file" || !a.Tools[0].EveryToolReadWrite() ||
		a.Tools[1].Resource != "search_files" || !a.Tools[1].EveryToolReadWrite() {
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
	err := yaml.Unmarshal([]byte("- resource: ok\n  tools: [\"*\"]\n  mode: read-write\n- code-search\n- github\n"), &got)
	if err == nil {
		t.Fatalf("expected an error, parsed %+v", got)
	}
	msg := err.Error()
	for _, want := range []string{
		"bad-tool-grant: line 4: a bare tool grant is no longer accepted",
		`{resource: "code-search", tools: ["*"], mode: read-write}`,
		"or list tools and set mode",
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
  tools: ["*"]
  mode: read-write
- resource: github
  tools: [list_issues, get_issue]
  mode: read-write
`
	var got []ToolGrant
	if err := yaml.Unmarshal([]byte(src), &got); err != nil {
		t.Fatal(err)
	}
	want := []ToolGrant{
		{Resource: "code-search", Tools: []string{"*"}, Mode: "read-write"},
		{Resource: "github", Tools: []string{"list_issues", "get_issue"}, Mode: "read-write"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	if !got[0].EveryToolReadWrite() || got[1].AllTools() {
		t.Fatalf("predicates: every=%v named-is-all=%v", got[0].EveryToolReadWrite(), got[1].AllTools())
	}
}

func TestToolGrantToolsAcceptsAlias(t *testing.T) {
	src := `
tools:
  - resource: a
    tools: &shared [list_issues, get_issue]
    mode: read-write
  - resource: b
    tools: *shared
    mode: read-write
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
		{"singular tool: typo is an unknown key", "- resource: github\n  tool: [list_issues]\n  mode: read-write\n", `unknown key "tool"`},
		{"future mode: typo is an unknown key", "- resource: github\n  tools: [x]\n  mod: read\n", `unknown key "mod"`},
		{"object with tools and mode absent", "- resource: github\n", "needs tools and mode"},
		{"object with tools and mode absent names the every-tool remedy", "- resource: github\n", `{resource: "github", tools: ["*"], mode: read-write}`},
		{"object with tools absent", "- resource: github\n  mode: read-write\n", "has no tools"},
		{"object with tools null", "- resource: github\n  tools: null\n  mode: read-write\n", "has no tools"},
		{"object with tools empty", "- resource: github\n  tools: []\n  mode: read-write\n", "has no tools"},
		{"object with empty resource", "- resource: \"\"\n  tools: [x]\n  mode: read-write\n", "empty resource"},
		{"object with resource absent", "- tools: [x]\n  mode: read-write\n", "empty resource"},
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

// TestToolGrantFourShapesParse: breadth × read/write, every one explicit.
func TestToolGrantFourShapesParse(t *testing.T) {
	ok := []struct {
		name string
		src  string
		want ToolGrant
	}{
		{"every tool, read-write", "- resource: github\n  tools: [\"*\"]\n  mode: read-write\n", ToolGrant{Resource: "github", Tools: []string{"*"}, Mode: "read-write"}},
		{"every read-only tool", "- resource: github\n  tools: [\"*\"]\n  mode: read-only\n", ToolGrant{Resource: "github", Tools: []string{"*"}, Mode: "read-only"}},
		{"named, read-write", "- resource: github\n  tools: [echo, other]\n  mode: read-write\n", ToolGrant{Resource: "github", Tools: []string{"echo", "other"}, Mode: "read-write"}},
		{"named, read-only", "- resource: github\n  tools: [echo]\n  mode: read-only\n", ToolGrant{Resource: "github", Tools: []string{"echo"}, Mode: "read-only"}},
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

// TestToolGrantShapeRejected: every malformed shape is bad-tool-grant with
// the offending line and a remedy. The rule order matters because yaml.v3
// stops at the first error per file: the retired mode: all is named before
// "has no tools", so the most common old shape is told its replacement.
func TestToolGrantShapeRejected(t *testing.T) {
	cases := []struct{ name, src, line, want string }{
		{"mode all retired", "- resource: github\n  mode: all\n", "line 2", "mode: all is retired"},
		{"mode all retired names its replacement", "- resource: github\n  mode: all\n", "line 2", `write tools: ["*"], mode: read-write for every tool, or mode: read-only`},
		{"mode all with tools is still retired", "- resource: github\n  tools: [echo]\n  mode: all\n", "line 3", "mode: all is retired"},
		{"bad mode", "- resource: github\n  tools: [\"*\"]\n  mode: write\n", "line 3", `mode "write" (want read-only or read-write)`},
		{"bad mode without tools is still a bad mode", "- resource: github\n  mode: write\n", "line 2", `mode "write"`},
		{"tools absent with a mode", "- resource: github\n  mode: read-only\n", "line 1", "has no tools"},
		{"empty tools with read-only", "- resource: github\n  tools: []\n  mode: read-only\n", "line 2", "has no tools"},
		{"star not alone", "- resource: github\n  tools: [\"*\", echo]\n  mode: read-write\n", "line 2", `"*" must be the only entry`},
		{"star not alone, star last", "- resource: github\n  tools: [echo, \"*\"]\n  mode: read-only\n", "line 2", `"*" must be the only entry`},
		{"mode absent on a named grant", "- resource: github\n  tools: [echo]\n", "line 1", "has no mode: set mode: read-only or read-write"},
		{"mode absent on a star grant never widens", "- resource: github\n  tools: [\"*\"]\n", "line 1", "has no mode"},
		{"mode empty string", "- resource: github\n  tools: [echo]\n  mode: \"\"\n", "line 3", "has no mode"},
		{"mode null", "- resource: github\n  tools: [echo]\n  mode: null\n", "line 3", "has no mode"},
		{"neither tools nor mode", "- resource: github\n", "line 1", "needs tools and mode"},
		{"mode null and no tools is the bare shape", "- resource: github\n  mode: null\n", "line 1", "needs tools and mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []ToolGrant
			err := yaml.Unmarshal([]byte(tc.src), &got)
			if err == nil {
				t.Fatalf("expected an error, parsed %+v", got)
			}
			if !strings.Contains(err.Error(), "bad-tool-grant: "+tc.line+":") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want bad-tool-grant at %s with %q", err.Error(), tc.line, tc.want)
			}
		})
	}
}

// TestToolGrantUnquotedStarIsAYAMLError: `tools: [*]` is YAML alias syntax,
// so it is a syntax error from yaml.v3 before any grant rule runs — not a
// bad-tool-grant and never a grant. config.md tells operators to quote it.
func TestToolGrantUnquotedStarIsAYAMLError(t *testing.T) {
	var got []ToolGrant
	err := yaml.Unmarshal([]byte("- resource: github\n  tools: [*]\n  mode: read-write\n"), &got)
	if err == nil {
		t.Fatalf("an unquoted * must not parse, got %+v", got)
	}
	if strings.Contains(err.Error(), "bad-tool-grant") {
		t.Fatalf("an unquoted * is a YAML syntax error, not a grant rule: %v", err)
	}
}

func TestToolGrantErrorNamesTheLine(t *testing.T) {
	src := "- resource: ok\n  tools: [\"*\"]\n  mode: read-write\n- resource: github\n  tool: [x]\n"
	var got []ToolGrant
	err := yaml.Unmarshal([]byte(src), &got)
	if err == nil || !strings.Contains(err.Error(), "line 5") {
		t.Fatalf("error should name the offending key's line (5): %v", err)
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

// TestRoleControlParse pins the decoding the control-empty validation rule
// depends on: an absent key and an explicit null both leave Control nil (no
// control permission); a present-but-empty list is a non-nil empty slice
// (rejected at apply); a list decodes verbatim.
func TestRoleControlParse(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string // nil = absent
	}{
		{"absent", "name: r\nallowed_groups: [a]\n", nil},
		{"null", "name: r\nallowed_groups: [a]\ncontrol:\n", nil},
		{"present-empty", "name: r\nallowed_groups: [a]\ncontrol: []\n", []string{}},
		{"listed", "name: r\nallowed_groups: [a]\ncontrol: [apply, repair]\n", []string{"apply", "repair"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r RoleDef
			if err := yaml.Unmarshal([]byte(tc.src), &r); err != nil {
				t.Fatal(err)
			}
			if (r.Control == nil) != (tc.want == nil) {
				t.Fatalf("control nil-ness: got %#v, want %#v", r.Control, tc.want)
			}
			if !slices.Equal(r.Control, tc.want) {
				t.Fatalf("control: got %v, want %v", r.Control, tc.want)
			}
		})
	}
}

// TestToolGrantPredicates pins the three predicates Validate and Start branch
// on. EveryToolReadWrite is the one shape that resolves to the "every tool"
// (nil) set, and it is positive on the closed enum: a ["*"] grant whose mode
// is read-only, absent, retired, or unknown is AllTools but is never
// every-tool — fail-closed by construction, not by which check runs first.
func TestToolGrantPredicates(t *testing.T) {
	cases := []struct {
		name                        string
		g                           ToolGrant
		allTools, readOnly, everyRW bool
	}{
		{"star read-write", ToolGrant{Resource: "github", Tools: []string{"*"}, Mode: "read-write"}, true, false, true},
		{"star read-only", ToolGrant{Resource: "github", Tools: []string{"*"}, Mode: "read-only"}, true, true, false},
		{"named read-write", ToolGrant{Resource: "github", Tools: []string{"a", "b"}, Mode: "read-write"}, false, false, false},
		{"named read-only", ToolGrant{Resource: "github", Tools: []string{"a"}, Mode: "read-only"}, false, true, false},
		{"star with no mode never resolves to every tool", ToolGrant{Resource: "github", Tools: []string{"*"}}, true, false, false},
		{"star with unknown mode never resolves to every tool", ToolGrant{Resource: "github", Tools: []string{"*"}, Mode: "typo"}, true, false, false},
		{"star with retired mode all never resolves to every tool", ToolGrant{Resource: "github", Tools: []string{"*"}, Mode: "all"}, true, false, false},
		{"star not alone is not AllTools", ToolGrant{Resource: "github", Tools: []string{"*", "a"}, Mode: "read-write"}, false, false, false},
		{"star second is not AllTools", ToolGrant{Resource: "github", Tools: []string{"a", "*"}, Mode: "read-write"}, false, false, false},
		{"nil tools", ToolGrant{Resource: "github", Mode: "read-write"}, false, false, false},
		{"empty tools", ToolGrant{Resource: "github", Tools: []string{}, Mode: "read-write"}, false, false, false},
		{"bare grant", ToolGrant{Resource: "github"}, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.AllTools(); got != tc.allTools {
				t.Errorf("AllTools = %v, want %v", got, tc.allTools)
			}
			if got := tc.g.ReadOnly(); got != tc.readOnly {
				t.Errorf("ReadOnly = %v, want %v", got, tc.readOnly)
			}
			if got := tc.g.EveryToolReadWrite(); got != tc.everyRW {
				t.Errorf("EveryToolReadWrite = %v, want %v", got, tc.everyRW)
			}
		})
	}
}
