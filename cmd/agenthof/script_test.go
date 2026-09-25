package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
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
	// Mock MCP upstream: exposes a single `echo(text)->text` tool that proves
	// Agenthof injected the resource credential on the upstream leg. The
	// check lives INSIDE the tool function (via req.Extra.Header) rather
	// than around initialize/ListTools, so mirroring succeeds and the
	// credential enforcement is scoped to the actual tool call.
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
	mcpSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil))
	t.Cleanup(mcpSrv.Close)
	testscript.Run(t, testscript.Params{
		Dir: filepath.Join("testdata", "script"),
		Setup: func(e *testscript.Env) error {
			// Hermetic: never inherit the developer's identity/gateway env.
			e.Setenv("AGENTHOF_TOKEN", "")
			e.Setenv("AGENTHOF_OIDC_ISSUER", "")
			e.Setenv("AGENTHOF_OIDC_CLIENT_ID", "")
			// Demo scripts run the reviewer agent, which is granted the
			// example `code-search` tool resource in examples/config. Its
			// gateway declares `token_env: CODE_SEARCH_TOKEN`, and the broker
			// fails the connect if the variable is unset. Provide a
			// throw-away value for the hermetic mock upstream; the value is
			// intentionally kept out of the published YAML.
			e.Setenv("CODE_SEARCH_TOKEN", "example")
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
			return rewriteToolURLs(e.WorkDir, mcpSrv.URL)
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
