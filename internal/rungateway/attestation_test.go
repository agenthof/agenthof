package rungateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// goodAttestation is exactly what refbridge's attestationMeta produces (the
// pinned wire contract); numbers are float64 because that is how the SDK's
// client decodes _meta.
func goodAttestation() map[string]any {
	return map[string]any{
		"runtime": "refbridge", "session": "sess-1",
		"command": []any{"/stdio-tool", "-credential-env", "DEMO_TOKEN"},
		"pid":     float64(4242), "spawn": float64(1),
		"credential_env": "DEMO_TOKEN", "env_names": []any{"DEMO_TOKEN", "PATH"},
		"materialization": "env-at-spawn",
	}
}

func TestTakeRuntimeAttestation(t *testing.T) {
	withMeta := func(m map[string]any) *mcp.CallToolResult {
		res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}
		if m != nil {
			res.Meta = mcp.Meta{runtimeAttestationMetaKey: m}
		}
		return res
	}
	t.Run("declared and well-formed: decoded, stripped", func(t *testing.T) {
		res := withMeta(goodAttestation())
		att, dropped, err := takeRuntimeAttestation(res, "refbridge")
		if err != nil || dropped || att == nil {
			t.Fatalf("got att=%v dropped=%v err=%v", att, dropped, err)
		}
		if att.Runtime != "refbridge" || att.PID != 4242 || att.Spawn != 1 || len(att.Command) != 3 || len(att.EnvNames) != 2 || att.CredentialEnv != "DEMO_TOKEN" {
			t.Fatalf("decoded = %+v", att)
		}
		if res.Meta != nil {
			t.Fatalf("the key must be stripped and an emptied _meta nil-ed, got %v", res.Meta)
		}
	})
	t.Run("undeclared: stripped, dropped, no error", func(t *testing.T) {
		res := withMeta(goodAttestation())
		att, dropped, err := takeRuntimeAttestation(res, "")
		if err != nil || !dropped || att != nil || res.Meta != nil {
			t.Fatalf("got att=%v dropped=%v err=%v meta=%v", att, dropped, err, res.Meta)
		}
	})
	t.Run("undeclared and absent: nothing to do", func(t *testing.T) {
		res := withMeta(nil)
		if att, dropped, err := takeRuntimeAttestation(res, ""); att != nil || dropped || err != nil {
			t.Fatalf("got att=%v dropped=%v err=%v", att, dropped, err)
		}
	})
	t.Run("declared and absent: missing", func(t *testing.T) {
		if _, _, err := takeRuntimeAttestation(withMeta(nil), "refbridge"); err == nil || err.Error() != "runtime attestation missing" {
			t.Fatalf("err = %v", err)
		}
		if _, _, err := takeRuntimeAttestation(nil, "refbridge"); err == nil || err.Error() != "runtime attestation missing" {
			t.Fatalf("nil result err = %v", err)
		}
	})
	t.Run("other _meta keys survive stripping", func(t *testing.T) {
		res := withMeta(goodAttestation())
		res.Meta["other"] = "kept"
		if _, _, err := takeRuntimeAttestation(res, "refbridge"); err != nil {
			t.Fatal(err)
		}
		if res.Meta["other"] != "kept" || len(res.Meta) != 1 {
			t.Fatalf("meta = %v", res.Meta)
		}
	})
	malformed := map[string]func(map[string]any){
		"wrong runtime":             func(m map[string]any) { m["runtime"] = "refbox" },
		"not an object":             nil,
		"empty command":             func(m map[string]any) { m["command"] = []any{} },
		"oversized argv element":    func(m map[string]any) { m["command"] = []any{strings.Repeat("x", 201)} },
		"too many argv elements":    func(m map[string]any) { m["command"] = make([]any, 33) },
		"zero pid":                  func(m map[string]any) { m["pid"] = float64(0) },
		"fractional pid":            func(m map[string]any) { m["pid"] = 4242.5 },
		"zero spawn":                func(m map[string]any) { m["spawn"] = float64(0) },
		"credential_env not a name": func(m map[string]any) { m["credential_env"] = "not a name" },
		"env name not a name":       func(m map[string]any) { m["env_names"] = []any{"DEMO_TOKEN=value"} },
		"too many env names":        func(m map[string]any) { m["env_names"] = make([]any, 65) },
		"oversized env name":        func(m map[string]any) { m["env_names"] = []any{strings.Repeat("X", 201)} },
		"oversized credential_env":  func(m map[string]any) { m["credential_env"] = strings.Repeat("X", 201) },
		"unknown materialization":   func(m map[string]any) { m["materialization"] = "inherit" },
		"oversized session":         func(m map[string]any) { m["session"] = strings.Repeat("s", 201) },
		"control char in argv":      func(m map[string]any) { m["command"] = []any{"/bin/tool", "a\nforged: line"} },
		"escape in argv":            func(m map[string]any) { m["command"] = []any{"/bin/tool\x1b[2J"} },
		"control char in session":   func(m map[string]any) { m["session"] = "abc\r\ndef" },
		"C1 control in session":     func(m map[string]any) { m["session"] = "abc\u0085def" },
	}
	for name, mut := range malformed {
		t.Run("malformed: "+name, func(t *testing.T) {
			var res *mcp.CallToolResult
			if mut == nil {
				res = &mcp.CallToolResult{Meta: mcp.Meta{runtimeAttestationMetaKey: "a string, not an object"}}
			} else {
				m := goodAttestation()
				mut(m)
				res = withMeta(m)
			}
			_, _, err := takeRuntimeAttestation(res, "refbridge")
			if err == nil || err.Error() != "runtime attestation malformed" {
				t.Fatalf("err = %v, want runtime attestation malformed", err)
			}
			if res.Meta != nil {
				t.Fatal("a malformed attestation must still be stripped")
			}
		})
	}
}

// goodExecAttestation is exactly what refexec's Meta() produces: credential-less.
func goodExecAttestation() map[string]any {
	return map[string]any{
		"runtime": "refexec", "session": "refexec-0a1b2c3d",
		"command": []any{"cat", "/work/agent-note.txt"},
		"pid":     float64(4242), "spawn": float64(1),
		"credential_env": "", "env_names": []any{},
		"materialization": "",
	}
}

func TestDecodeAttestationPerRuntime(t *testing.T) {
	t.Run("refexec: credential-less is well-formed", func(t *testing.T) {
		att, err := decodeAttestation(goodExecAttestation(), "refexec")
		if err != nil || att == nil || att.Runtime != "refexec" || att.PID != 4242 || att.CredentialEnv != "" || att.Materialization != "" {
			t.Fatalf("att=%+v err=%v", att, err)
		}
	})
	t.Run("refbridge: still decodes through the same path", func(t *testing.T) {
		att, err := decodeAttestation(goodAttestation(), "refbridge")
		if err != nil || att == nil || att.CredentialEnv != "DEMO_TOKEN" {
			t.Fatalf("att=%+v err=%v", att, err)
		}
	})
	t.Run("nil raw is missing", func(t *testing.T) {
		if _, err := decodeAttestation(nil, "refexec"); err == nil || err.Error() != "runtime attestation missing" {
			t.Fatalf("err = %v", err)
		}
	})
	malformed := map[string]struct {
		raw      map[string]any
		declared string
	}{
		"refexec claiming a credential variable":    {mut(goodExecAttestation(), "credential_env", "DEMO_TOKEN"), "refexec"},
		"refexec claiming a materialization":        {mut(goodExecAttestation(), "materialization", "env-at-spawn"), "refexec"},
		"refexec answering a refbridge declaration": {goodExecAttestation(), "refbridge"},
		"refbridge answering a refexec declaration": {goodAttestation(), "refexec"},
		"refbridge without a credential variable":   {mut(goodAttestation(), "credential_env", ""), "refbridge"},
		"unknown runtime declared and spoken":       {mut(goodExecAttestation(), "runtime", "refbox"), "refbox"},
		"refexec zero pid":                          {mut(goodExecAttestation(), "pid", float64(0)), "refexec"},
		"refexec empty command":                     {mut(goodExecAttestation(), "command", []any{}), "refexec"},
	}
	for name, tc := range malformed {
		t.Run("malformed: "+name, func(t *testing.T) {
			if _, err := decodeAttestation(tc.raw, tc.declared); err == nil || err.Error() != "runtime attestation malformed" {
				t.Fatalf("err = %v, want runtime attestation malformed", err)
			}
		})
	}
}

// mut returns m with one key replaced.
func mut(m map[string]any, key string, value any) map[string]any {
	m[key] = value
	return m
}

// newAttestingUpstream serves one echo tool whose every result carries the
// given _meta value (nil = none), as a refbridge would; it also records the
// last result it returned so the test can hash what the tool itself said.
func newAttestingUpstream(t *testing.T, meta map[string]any, isError bool) *httptest.Server {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "attesting-stub", Version: "v0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, args EchoArgs) (*mcp.CallToolResult, any, error) {
		res := &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}
		if meta != nil {
			res.Meta = mcp.Meta{runtimeAttestationMetaKey: meta}
		}
		return res, nil, nil
	})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	t.Cleanup(ts.Close)
	return ts
}

// runOneCall starts a gateway over the given resource, makes one echo call as
// the agent, and returns the agent-side result and the recorded events.
func runOneCall(t *testing.T, res config.ToolResource) (*mcp.CallToolResult, []engine.Event, error) {
	t.Helper()
	t.Setenv("ATT_TOKEN", "upstream-secret")
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"bridge": res}}, "", broker.StaticEnv{}, nil)
	var mu sync.Mutex
	var events []engine.Event
	appendEvent := func(e engine.Event) { mu.Lock(); defer mu.Unlock(); events = append(events, e) }
	url, runToken, err := p.Start(testBinding(), testAgentDef("bridge"), appendEvent)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()
	sess, err := stubAgentSession(context.Background(), url, runToken)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer func() { _ = sess.Close() }()
	result, callErr := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	_ = sess.Close()
	p.Stop()
	mu.Lock()
	defer mu.Unlock()
	return result, events, callErr
}

func resource(url, runtime string) config.ToolResource {
	return config.ToolResource{Kind: "mcp", URL: url, CredentialSource: "static_env", TokenEnv: "ATT_TOKEN", Runtime: runtime}
}

func onlyToolCall(t *testing.T, events []engine.Event) engine.Event {
	t.Helper()
	var calls []engine.Event
	for _, e := range events {
		if e.Type == "tool_call" {
			calls = append(calls, e)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("recorded %d tool_call events, want 1: %+v", len(calls), calls)
	}
	return calls[0]
}

func TestDeclaredRuntimeAttestationIsRecordedAndStripped(t *testing.T) {
	ts := newAttestingUpstream(t, goodAttestation(), false)
	result, events, err := runOneCall(t, resource(ts.URL, "refbridge"))
	if err != nil || result.IsError {
		t.Fatalf("call failed: %v %+v", err, result)
	}
	if _, leaked := result.Meta[runtimeAttestationMetaKey]; leaked {
		t.Fatal("the agent must never see the attestation")
	}
	e := onlyToolCall(t, events)
	if e.Status != "succeeded" || e.RuntimeAttestation == nil || e.RuntimeAttestation.Runtime != "refbridge" || e.RuntimeAttestation.PID != 4242 {
		t.Fatalf("event = %+v", e)
	}
	// artifact_sha covers the tool's own result, exactly as without a bridge.
	plain := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi"}}}
	if sha, _ := hashResult(plain, nil); sha != e.ArtifactSHA {
		t.Fatalf("artifact_sha = %s, want the hash of the stripped result %s", e.ArtifactSHA, sha)
	}
	if b, _ := json.Marshal(e); !strings.Contains(string(b), `"runtime_attestation":{"runtime":"refbridge","session":"sess-1","command":["/stdio-tool","-credential-env","DEMO_TOKEN"],"pid":4242,"spawn":1,"credential_env":"DEMO_TOKEN","env_names":["DEMO_TOKEN","PATH"],"materialization":"env-at-spawn"}`) {
		t.Fatalf("ledger JSON shape:\n%s", b)
	}
}

func TestDeclaredRuntimeErrorResultStillRecordsAttestation(t *testing.T) {
	ts := newAttestingUpstream(t, goodAttestation(), true)
	result, events, err := runOneCall(t, resource(ts.URL, "refbridge"))
	if err != nil || !result.IsError {
		t.Fatalf("want the child's error result relayed, got %v %+v", err, result)
	}
	e := onlyToolCall(t, events)
	if e.Status != "failed" || e.RuntimeAttestation == nil {
		t.Fatalf("event = %+v", e)
	}
}

func TestDeclaredRuntimeMissingAttestationFailsCall(t *testing.T) {
	ts := newAttestingUpstream(t, nil, false)
	result, events, err := runOneCall(t, resource(ts.URL, "refbridge"))
	if err != nil || !result.IsError || resultErrorText(result) != "runtime attestation missing" {
		t.Fatalf("agent must get an error result naming the missing attestation, got %v %+v", err, result)
	}
	e := onlyToolCall(t, events)
	if e.Status != "failed" || e.Reason != "runtime attestation missing" || e.RuntimeAttestation != nil {
		t.Fatalf("event = %+v", e)
	}
}

func TestDeclaredRuntimeMalformedAttestationFailsCall(t *testing.T) {
	bad := goodAttestation()
	bad["runtime"] = "refbox"
	ts := newAttestingUpstream(t, bad, false)
	result, events, err := runOneCall(t, resource(ts.URL, "refbridge"))
	if err != nil || !result.IsError || resultErrorText(result) != "runtime attestation malformed" {
		t.Fatalf("got %v %+v", err, result)
	}
	if e := onlyToolCall(t, events); e.Status != "failed" || e.Reason != "runtime attestation malformed" || e.RuntimeAttestation != nil {
		t.Fatalf("event = %+v", e)
	}
}

func TestUndeclaredRuntimeAttestationIsStrippedNotRecorded(t *testing.T) {
	ts := newAttestingUpstream(t, goodAttestation(), false)
	result, events, err := runOneCall(t, resource(ts.URL, "")) // an ordinary resource claiming to be a runtime
	if err != nil || result.IsError {
		t.Fatalf("call failed: %v %+v", err, result)
	}
	if _, leaked := result.Meta[runtimeAttestationMetaKey]; leaked {
		t.Fatal("the agent must never see a claimed attestation")
	}
	e := onlyToolCall(t, events)
	if e.Status != "succeeded" || e.RuntimeAttestation != nil {
		t.Fatalf("an undeclared resource's claim must not enter the ledger: %+v", e)
	}
	if b, _ := json.Marshal(e); strings.Contains(string(b), "runtime_attestation") {
		t.Fatalf("ledger JSON must omit the field entirely:\n%s", b)
	}
}
