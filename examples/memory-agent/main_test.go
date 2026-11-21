package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type stubCalls struct {
	mu      sync.Mutex
	auth    string
	upserts []map[string]any
	search  []map[string]any
	fail    bool
}

// stubGateway serves stub memory_upsert / memory_search tools that return
// structured content (no text Content), like the real memory-store server.
func stubGateway(t *testing.T, calls *stubCalls) string {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "gateway-stub", Version: "v0"}, nil)
	server.AddTool(&mcp.Tool{Name: "memory_upsert", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a map[string]any
			_ = json.Unmarshal(req.Params.Arguments, &a)
			calls.mu.Lock()
			defer calls.mu.Unlock()
			calls.auth = req.Extra.Header.Get("Authorization")
			calls.upserts = append(calls.upserts, a)
			if calls.fail {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "SECRET-TOOL-ERROR"}}}, nil
			}
			return &mcp.CallToolResult{StructuredContent: json.RawMessage(`{"id":"abc123"}`)}, nil
		})
	server.AddTool(&mcp.Tool{Name: "memory_search", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a map[string]any
			_ = json.Unmarshal(req.Params.Arguments, &a)
			calls.mu.Lock()
			calls.search = append(calls.search, a)
			calls.mu.Unlock()
			return &mcp.CallToolResult{StructuredContent: json.RawMessage(
				`{"results":[{"id":"abc123","score":0.5,"text":"t","metadata":{}},{"id":"def456","score":0.25,"text":"u","metadata":{"a":1}}]}`)}, nil
		})
	dir, err := os.MkdirTemp("/tmp", "ma")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

const testScript = `{"upserts":[{"collection":"notes","text":"hello","vector":[1,0,0],"metadata":{"k":"v"},"id":"n1"}],` +
	`"searches":[{"collection":"notes","vector":[1,0,0],"k":2}]}`

func TestRunScriptUpsertsThenSearches(t *testing.T) {
	calls := &stubCalls{}
	sock := stubGateway(t, calls)
	sc, err := parseScript(testScript)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runScript(context.Background(), "unix://"+sock, "run-token-test", sc)
	if err != nil {
		t.Fatalf("runScript: %v", err)
	}
	want := "upserted abc123\nhit abc123 0.5000\nhit def456 0.2500"
	if out != want {
		t.Fatalf("artifact = %q, want %q", out, want)
	}
	if calls.auth != "Bearer run-token-test" {
		t.Fatalf("gateway saw %q", calls.auth)
	}
	wantUp := map[string]any{"collection": "notes", "text": "hello", "vector": []any{1.0, 0.0, 0.0},
		"metadata": map[string]any{"k": "v"}, "id": "n1"}
	if len(calls.upserts) != 1 || !reflect.DeepEqual(calls.upserts[0], wantUp) {
		t.Fatalf("upsert args = %v", calls.upserts)
	}
	wantSearch := map[string]any{"collection": "notes", "vector": []any{1.0, 0.0, 0.0}, "k": 2.0}
	if len(calls.search) != 1 || !reflect.DeepEqual(calls.search[0], wantSearch) {
		t.Fatalf("search args = %v", calls.search)
	}
}

func TestParseScriptRejects(t *testing.T) {
	for _, bad := range []string{"", "not json", "{}", `{"upserts":[]}`, `{"searches":[{"collection":"c","vector":[1],"k":1}]} trailing`} {
		if _, err := parseScript(bad); err == nil {
			t.Fatalf("parseScript(%q) accepted", bad)
		}
	}
}

func step(t *testing.T, input, proxy string) response {
	t.Helper()
	body, _ := json.Marshal(request{Input: input})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("X-Agenthof-Proxy-URL", proxy)
	r.Header.Set("X-Agenthof-Run-Token", "tok")
	w := httptest.NewRecorder()
	newMux().ServeHTTP(w, r)
	var out response
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response %q: %v", w.Body.String(), err)
	}
	return out
}

func TestStepFailureReasonsAreFixed(t *testing.T) {
	calls := &stubCalls{fail: true}
	sock := stubGateway(t, calls)
	proxy := "unix://" + sock

	out := step(t, testScript, proxy)
	if out.Success || out.Reason != reasonCallFailed {
		t.Fatalf("tool error: %+v", out)
	}
	for _, leak := range []string{"SECRET-TOOL-ERROR", sock, "unix://"} {
		if strings.Contains(out.Reason, leak) || strings.Contains(out.Artifact, leak) {
			t.Fatalf("response leaks %q: %+v", leak, out)
		}
	}

	out = step(t, `{"upserts": SECRET-BAD`, proxy)
	if out.Success || out.Reason != reasonBadScript || strings.Contains(out.Reason, "SECRET") {
		t.Fatalf("bad input: %+v", out)
	}

	out = step(t, testScript, "http://127.0.0.1:1/secret-path")
	if out.Success || out.Reason != reasonCallFailed || strings.Contains(out.Reason, "secret-path") {
		t.Fatalf("unreachable gateway: %+v", out)
	}

	out = step(t, testScript, "")
	if out.Success || out.Reason != reasonNoProxy {
		t.Fatalf("missing proxy: %+v", out)
	}
}
