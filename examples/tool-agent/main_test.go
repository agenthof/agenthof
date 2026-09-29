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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestParseScript(t *testing.T) {
	cmds, err := parseScript("call echo hello there; sleep 2 ;call credential;")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("got %d commands, want 3", len(cmds))
	}
	if cmds[0].tool != "echo" || cmds[0].args["text"] != "hello there" {
		t.Fatalf("cmd 0 = %+v", cmds[0])
	}
	if cmds[1].sleep != 2*time.Second {
		t.Fatalf("cmd 1 = %+v", cmds[1])
	}
	if cmds[2].tool != "credential" || len(cmds[2].args) != 0 {
		t.Fatalf("cmd 2 = %+v, want a call with empty arguments", cmds[2])
	}
	for _, bad := range []string{"", "call", "sleep", "sleep x", "sleep 999", "jump 3", "echo hi"} {
		if _, err := parseScript(bad); err == nil {
			t.Fatalf("parseScript(%q) accepted", bad)
		}
	}
}

// stubGateway is a stand-in for the per-run gateway's inbound MCP server on a
// Unix socket: one echo tool that records the bearer, and a count of sessions.
func stubGateway(t *testing.T) (sock string, sessions *atomic.Int32, lastAuth func() string) {
	t.Helper()
	var mu sync.Mutex
	var auth string
	var n atomic.Int32
	server := mcp.NewServer(&mcp.Implementation{Name: "gateway-stub", Version: "v0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo"},
		func(_ context.Context, req *mcp.CallToolRequest, args struct {
			Text string `json:"text,omitempty"`
		}) (*mcp.CallToolResult, any, error) {
			mu.Lock()
			auth = req.Extra.Header.Get("Authorization")
			mu.Unlock()
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + args.Text}}}, nil, nil
		})
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "initialize" {
				n.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	dir, err := os.MkdirTemp("/tmp", "ta")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, &n, func() string { mu.Lock(); defer mu.Unlock(); return auth }
}

func TestRunScriptIsOneSessionPerStep(t *testing.T) {
	sock, sessions, lastAuth := stubGateway(t)
	cmds, _ := parseScript("call echo one; call echo two")
	out, err := runScript(context.Background(), "unix://"+sock, "run-token-test", cmds)
	if err != nil {
		t.Fatalf("runScript: %v", err)
	}
	if out != "echo:one\necho:two" {
		t.Fatalf("artifact = %q", out)
	}
	if sessions.Load() != 1 {
		t.Fatalf("sessions = %d, want exactly one per step", sessions.Load())
	}
	if lastAuth() != "Bearer run-token-test" {
		t.Fatalf("gateway saw %q, want the run token", lastAuth())
	}
}

func post(t *testing.T, srv *httptest.Server, body []byte, headers map[string]string) (int, response) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestStepEndToEnd(t *testing.T) {
	sock, _, _ := stubGateway(t)
	srv := httptest.NewServer(newMux())
	defer srv.Close()
	body, _ := json.Marshal(request{Input: "call echo hi", Agent: "ta"})
	gw := map[string]string{"X-Agenthof-Proxy-URL": "unix://" + sock, "X-Agenthof-Run-Token": "run-token-test"}
	if status, out := post(t, srv, body, gw); status != 200 || !out.Success || out.Artifact != "echo:hi" {
		t.Fatalf("step = %d %+v", status, out)
	}
	if status, out := post(t, srv, body, nil); status != 200 || out.Success || out.Reason != "tool proxy coordinates missing" {
		t.Fatalf("no headers = %d %+v", status, out)
	}
	bad, _ := json.Marshal(request{Input: "jump 3"})
	if status, out := post(t, srv, bad, gw); status != 200 || out.Success || !strings.HasPrefix(out.Reason, "bad script: ") {
		t.Fatalf("bad script = %d %+v", status, out)
	}
	dead := map[string]string{"X-Agenthof-Proxy-URL": "unix:///tmp/nobody-listens-here.sock", "X-Agenthof-Run-Token": "run-token-test"}
	if status, out := post(t, srv, body, dead); status != 200 || out.Success || out.Reason != "tool call failed" {
		t.Fatalf("dead gateway = %d %+v (the reason must be fixed and carry no path)", status, out)
	}
	if status, _ := post(t, srv, []byte("not json"), gw); status != 400 {
		t.Fatalf("non-json = %d, want 400", status)
	}
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("GET = %d, want 405", resp.StatusCode)
	}
}

func TestServesOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "tas")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newMux()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	body, _ := json.Marshal(request{Input: "call echo x"})
	resp, err := client.Post("http://agenthof/", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 || out.Success || out.Reason != "tool proxy coordinates missing" {
		t.Fatalf("over unix = %d %+v", resp.StatusCode, out)
	}
}
