package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity/oidctest"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	// Lock-holder helper for the cross-process busy tests (apply_test.go,
	// registry_control_test.go): hold the named lock, say so, wait, exit.
	if p := os.Getenv("AGENTHOF_TEST_HOLD_LOCK"); p != "" {
		ms, _ := strconv.Atoi(os.Getenv("AGENTHOF_TEST_HOLD_MS"))
		var release func()
		switch os.Getenv("AGENTHOF_TEST_HOLD_KIND") {
		case "ledger":
			c, err := ledger.Open(p, ledger.Locked)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			release = func() { _ = c.Close() }
		default:
			unlock, err := ledger.LockFile(p)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			release = unlock
		}
		fmt.Println("held")
		time.Sleep(time.Duration(ms) * time.Millisecond)
		release()
		os.Exit(0)
	}
	testscript.Main(m, map[string]func(){
		"agenthof": func() {
			os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
		},
	})
}

func TestScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoCompatHandler))
	t.Cleanup(srv.Close)
	// Mock provider: proves Agenthof injected the provider key AND rewrote the
	// outbound body to the provider model name. Accept the call only when the
	// Authorization header is `Bearer dummy` (the value of AGENTHOF_GATEWAY_KEY
	// named by the route's api_key_env in door_model.txtar) AND the body carries
	// `"model":"upstream-model"` (the provider model the route resolves to). Any
	// other request → 401, no usage. A door that failed to inject would fail
	// this check, and the run would not render token counts.
	modelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer dummy" ||
			!strings.Contains(string(body), `"model":"upstream-model"`) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":11,"completion_tokens":5}}`))
	}))
	t.Cleanup(modelSrv.Close)
	// Mock MCP upstream: exposes `echo(text)->text`, which proves Agenthof
	// injected the resource credential on the upstream leg, and a second
	// tool, `other`, so a restricted grant has something to leave out. The
	// credential check lives INSIDE echo (via req.Extra.Header) rather than
	// around initialize/ListTools, so mirroring succeeds and the credential
	// enforcement is scoped to the actual tool call.
	type echoArgs struct {
		Text string `json:"text"`
	}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "mock-upstream", Version: "v0.1.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "echo", Description: "echo back text"},
		func(ctx context.Context, req *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
			// Prove Agenthof injected the resource credential on the upstream leg.
			var auth string
			if req.Extra != nil && req.Extra.Header != nil {
				auth = req.Extra.Header.Get("Authorization")
			}
			if auth != "Bearer tool-secret" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "unauthorized"}}}, nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil, nil
		})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "other", Description: "a second tool a restricted grant can leave out"},
		func(ctx context.Context, req *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "other: " + args.Text}}}, nil, nil
		})
	mcpSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil))
	t.Cleanup(mcpSrv.Close)
	execSock := refexecStub(t)
	// Hermetic OIDC issuer for serve_*.txtar: the URL and a minted token
	// travel under non-AGENTHOF_ names (Setup blanks the real ones) and a
	// script opts in with `env AGENTHOF_OIDC_ISSUER=$OIDC_ISSUER`.
	oidcKey := oidctest.NewKey(t)
	oidcSrv := oidctest.NewServer(t, oidcKey)
	oidcToken := oidctest.MintToken(t, oidcKey, map[string]any{
		"iss": oidcSrv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(),
		"sub": "u-123", "email": "dana@example.com", "groups": []string{"engineering"},
	})
	testscript.Run(t, testscript.Params{
		Dir: filepath.Join("testdata", "script"),
		Setup: func(e *testscript.Env) error {
			// Hermetic: never inherit the developer's identity/gateway env.
			e.Setenv("AGENTHOF_TOKEN", "")
			e.Setenv("AGENTHOF_OIDC_ISSUER", "")
			e.Setenv("AGENTHOF_OIDC_CLIENT_ID", "")
			e.Setenv("AGENTHOF_LOG_LEVEL", "")
			e.Setenv("AGENTHOF_LOG_FORMAT", "")
			// New reroute/auth knobs this increment adds: blank them like the
			// others, or a developer's exported AGENTHOF_SERVER would send
			// every script's `run` to a remote.
			e.Setenv("AGENTHOF_SERVER", "")
			e.Setenv("AGENTHOF_OIDC_AUDIENCE", "")
			e.Setenv("OIDC_ISSUER", oidcSrv.URL)
			e.Setenv("OIDC_TOKEN", oidcToken)
			if err := copyDir(filepath.Join("..", "..", "examples", "config"),
				filepath.Join(e.WorkDir, "examples", "config")); err != nil {
				return err
			}
			// Example agents and inline script configs declare either a placeholder
			// loopback endpoint or none. Point every agent at this process's
			// echo-compatible stub so a fronted run succeeds without a
			// separate server.
			if err := rewriteAgentEndpoints(e.WorkDir, srv.URL); err != nil {
				return err
			}
			if err := rewriteModelEndpoints(e.WorkDir, modelSrv.URL); err != nil {
				return err
			}
			if err := rewriteToolURLs(e.WorkDir, mcpSrv.URL); err != nil {
				return err
			}
			return rewriteExecURLs(e.WorkDir, execSock)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// lastrun <log-dir>: finds the single newest run log and exports
			// its run id (filename minus .jsonl) as $RUNID for later exec lines.
			"lastrun": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: lastrun <log-dir>")
				}
				entries, err := os.ReadDir(ts.MkAbs(args[0]))
				ts.Check(err)
				newest := ""
				var newestMod int64
				for _, ent := range entries {
					if ent.IsDir() || filepath.Ext(ent.Name()) != ".jsonl" {
						continue
					}
					info, err := ent.Info()
					ts.Check(err)
					if mod := info.ModTime().UnixNano(); mod >= newestMod {
						newestMod, newest = mod, ent.Name()
					}
				}
				if newest == "" {
					ts.Fatalf("no run logs in %s", args[0])
				}
				id := newest
				if ext := filepath.Ext(id); ext != "" {
					id = id[:len(id)-len(ext)]
				}
				ts.Setenv("RUNID", id)
			},
			// waitaddr <addr-file>: waits (bounded) for `serve --addr-file`
			// to write its host:port and exports http://host:port as $SERVER.
			"waitaddr": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: waitaddr <addr-file>")
				}
				path := ts.MkAbs(args[0])
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) != "" {
						ts.Setenv("SERVER", "http://"+strings.TrimSpace(string(b)))
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				ts.Fatalf("serve never wrote %s", args[0])
			},
		},
	})
}

// rewriteModelEndpoints repoints every `endpoint:` line in every gateway.yaml
// under root at the hermetic mock. This is safe because in today's gateway
// schema `endpoint:` is a model-route field only — ToolResource entries use
// `url:` and (for client_credentials) `token_endpoint:`, never `endpoint:` —
// so a bare-key rewrite cannot misfire on a tool. Revisit if that changes.
func rewriteModelEndpoints(root, endpoint string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "gateway.yaml" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "endpoint:") {
				indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
				lines[i] = indent + "endpoint: " + endpoint
			}
		}
		return os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644)
	})
}

func rewriteAgentEndpoints(root, endpoint string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Base(filepath.Dir(p)) != "agents" || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		found := false
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "endpoint:") {
				lines[i] = "endpoint: " + endpoint
				found = true
			}
		}
		out := strings.Join(lines, "\n")
		if !found {
			if out != "" && !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			out += "endpoint: " + endpoint + "\n"
		}
		return os.WriteFile(p, []byte(out), 0o644)
	})
}

// rewriteToolURLs repoints every `url:` line in every gateway.yaml under root
// at the hermetic mock MCP upstream. In today's gateway schema `url:` is a
// tool-resource-only field — model routes use `endpoint:` — so a bare-key
// rewrite cannot misfire on a model route. Revisit if that changes.
func rewriteToolURLs(root, url string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "gateway.yaml" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "url:") {
				indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
				lines[i] = indent + "url: " + url
			}
		}
		return os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644)
	})
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// refexecStub serves refexec's /run contract on a Unix socket in a private
// (0700) directory: it runs nothing, answering exit 0 (exit 1 for `false`)
// with an attestation naming the command it was asked for, so
// door_exec_runtime.txtar proves the gateway's first-hand door and audit's
// rendering — not podman. It returns the socket path.
func refexecStub(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rxt") // 0700 and short: the socket dir gate, and the socket path length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "exec.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command []string `json:"command"`
		}
		if r.URL.Path != "/run" || json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Command) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		exit := 0
		if req.Command[0] == "false" {
			exit = 1
		}
		output := "ok\n"
		sum := sha256.Sum256([]byte(output))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"exit_code": exit, "output": output, "output_sha": hex.EncodeToString(sum[:]),
			"truncated": false, "output_bytes": len(output),
			"runtime_attestation": map[string]any{
				"runtime": "refexec", "session": "refexec-stub", "command": req.Command,
				"pid": 4242, "spawn": 1, "credential_env": "", "env_names": []string{}, "materialization": "",
			},
		})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// rewriteExecURLs repoints the placeholder unix:///refexec-stub.sock in every
// agent file under root at the in-process stub's socket.
func rewriteExecURLs(root, sock string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(filepath.Dir(p)) != "agents" || !strings.HasSuffix(d.Name(), ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out := strings.ReplaceAll(string(b), "unix:///refexec-stub.sock", "unix://"+sock)
		return os.WriteFile(p, []byte(out), 0o644)
	})
}
