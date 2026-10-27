package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity/oidctest"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rogpeppe/go-internal/testscript"
)

// rekorKey keys a script's own Rekor fake in its testscript Env.
type rekorKey struct{}

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
			// New reroute/auth knobs: blank them like the
			// others, or a developer's exported AGENTHOF_SERVER would send
			// every script's `run` to a remote.
			e.Setenv("AGENTHOF_SERVER", "")
			e.Setenv("AGENTHOF_OIDC_AUDIENCE", "")
			e.Setenv("LITELLM_MASTER_KEY", "")
			e.Setenv("OIDC_ISSUER", oidcSrv.URL)
			e.Setenv("OIDC_TOKEN", oidcToken)
			// One Rekor fake per script, so a script's switches (stop, rotate,
			// fail) never race another script running in parallel. Its URL
			// travels as $REKOR_URL; the fake itself rides in e.Values for the
			// rekor command below.
			fake := anchortest.NewRekorV1()
			e.Defer(fake.Close)
			e.Values[rekorKey{}] = fake
			e.Setenv("REKOR_URL", fake.URL)
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
			// installedhash <control-log>: reads installed/current beside the
			// control log and exports it as $HASH for the next --if-installed.
			"installedhash": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: installedhash <control-log>")
				}
				hash, installed, err := config.InstalledHash(installedStore(ts.MkAbs(args[0])))
				ts.Check(err)
				if !installed {
					ts.Fatalf("nothing installed under %s", args[0])
				}
				ts.Setenv("HASH", hash)
			},
			// sigfile <control-log>: exports the path of installed/<hex>.sig
			// for the current pointer as $SIG, so a script can remove it.
			"sigfile": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: sigfile <control-log>")
				}
				store := installedStore(ts.MkAbs(args[0]))
				hash, installed, err := config.InstalledHash(store)
				ts.Check(err)
				if !installed {
					ts.Fatalf("nothing installed under %s", args[0])
				}
				ts.Setenv("SIG", config.SignaturePath(store, hash))
			},
			// tamper <control-log> <rel> <text>: appends text to the file at
			// <rel> inside the installed snapshot beside <control-log> — an
			// in-place edit under installed/<hex>/, the thing verify-on-read
			// exists to catch.
			"tamper": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 3 {
					ts.Fatalf("usage: tamper <control-log> <rel> <text>")
				}
				store := installedStore(ts.MkAbs(args[0]))
				hash, installed, err := config.InstalledHash(store)
				ts.Check(err)
				if !installed {
					ts.Fatalf("nothing installed under %s", args[0])
				}
				p := filepath.Join(config.SnapshotDir(store, hash), filepath.FromSlash(args[1]))
				f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
				ts.Check(err)
				_, werr := f.WriteString(args[2] + "\n")
				ts.Check(f.Close())
				ts.Check(werr)
			},
			// repoint <control-log> <hash>: writes installed/current beside the
			// control log by hand — the re-aim a hostile or careless hand makes,
			// with no lock and no record.
			"repoint": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: repoint <control-log> <hash>")
				}
				store := installedStore(ts.MkAbs(args[0]))
				ts.Check(os.WriteFile(filepath.Join(store, config.InstalledPointer), []byte(args[1]+"\n"), 0o600))
			},
			// badsig <control-log> otherkey|flip: replaces the live .sig of
			// the current pointer with one that is wrong in exactly one way —
			// otherkey: a VALID signature by a fresh pair over the same
			// (hash, log_id, version, installed_at), so the key is the only
			// difference ("unknown key", judged before any verify); flip: the
			// live file with one base64 character of its trailer changed
			// ("bad signature"). Neither can be written inline: the payload
			// changes with every install's seq.
			"badsig": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 || (args[1] != "otherkey" && args[1] != "flip") {
					ts.Fatalf("usage: badsig <control-log> otherkey|flip")
				}
				store := installedStore(ts.MkAbs(args[0]))
				hash, installed, err := config.InstalledHash(store)
				ts.Check(err)
				if !installed {
					ts.Fatalf("nothing installed under %s", args[0])
				}
				data, err := os.ReadFile(config.SignaturePath(store, hash))
				ts.Check(err)
				f, err := config.ParseSignatureFile(data)
				ts.Check(err)
				switch args[1] {
				case "otherkey":
					pub, priv, err := ed25519.GenerateKey(rand.Reader)
					ts.Check(err)
					at, err := time.Parse(time.RFC3339Nano, f.InstalledAt)
					ts.Check(err)
					payload, err := config.SignaturePayload(f.Hash, f.LogID, f.Version, at.UTC(), config.KeyID(pub))
					ts.Check(err)
					ts.Check(config.WriteSignatureFile(store, hash, payload, config.Sign(priv, payload)))
				case "flip":
					sig := []byte(f.Sig)
					if sig[0] == 'A' {
						sig[0] = 'B'
					} else {
						sig[0] = 'A'
					}
					ts.Check(config.WriteSignatureFile(store, hash, f.Payload, string(sig)))
				}
			},
			// holdlock <control-log> <ms>: a helper process (TestMain's
			// AGENTHOF_TEST_HOLD_LOCK) takes installed.lock beside the
			// control log exclusively and holds it for <ms> milliseconds, so
			// the next run or serve Prepare waits out lockTimeout and answers
			// busy. The holder is killed when the script ends.
			"holdlock": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: holdlock <control-log> <ms>")
				}
				cmd := exec.Command(os.Args[0], "-test.run=TestNothing")
				cmd.Env = append(os.Environ(), "AGENTHOF_TEST_HOLD_LOCK="+installedLock(ts.MkAbs(args[0])), "AGENTHOF_TEST_HOLD_KIND=file", "AGENTHOF_TEST_HOLD_MS="+args[1])
				stdout, err := cmd.StdoutPipe()
				ts.Check(err)
				ts.Check(cmd.Start())
				ts.Defer(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				var line [5]byte
				if _, err := io.ReadFull(stdout, line[:]); err != nil || string(line[:]) != "held\n" {
					ts.Fatalf("lock holder never reported held: %q %v", line[:], err)
				}
			},
			// holdfile <path> <ms>: holdlock for any lock file — a helper
			// process takes the exclusive flock on <path> itself (no
			// installed.lock derivation) and holds it for <ms> milliseconds,
			// so the next command that needs it waits out lockTimeout and
			// answers busy. The holder is killed when the script ends.
			"holdfile": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: holdfile <path> <ms>")
				}
				cmd := exec.Command(os.Args[0], "-test.run=TestNothing")
				cmd.Env = append(os.Environ(), "AGENTHOF_TEST_HOLD_LOCK="+ts.MkAbs(args[0]), "AGENTHOF_TEST_HOLD_KIND=file", "AGENTHOF_TEST_HOLD_MS="+args[1])
				stdout, err := cmd.StdoutPipe()
				ts.Check(err)
				ts.Check(cmd.Start())
				ts.Defer(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				var line [5]byte
				if _, err := io.ReadFull(stdout, line[:]); err != nil || string(line[:]) != "held\n" {
					ts.Fatalf("lock holder never reported held: %q %v", line[:], err)
				}
			},
			// rekor <switch> [arg]: drives this script's Rekor fake.
			//   fail <status> | corruptnext | drop | stop | start | rotate |
			//   corrupt <ref> | forget <ref> | cosign | hostname <s> | reset |
			//   requests <n> (asserts the fake saw exactly n requests) |
			//   pubkey <path> (writes the current key PEM for pinning) |
			//   posture <path> [clientcreds|runs] (writes a tlog integrity.yaml naming the fake; runs adds anchor_runs: on-demand)
			"rekor": func(ts *testscript.TestScript, neg bool, args []string) {
				fake, _ := ts.Value(rekorKey{}).(*anchortest.RekorV1)
				if fake == nil || len(args) == 0 {
					ts.Fatalf("usage: rekor <switch> [arg]")
				}
				arg := func() string {
					if len(args) != 2 {
						ts.Fatalf("rekor %s needs one argument", args[0])
					}
					return args[1]
				}
				switch args[0] {
				case "fail":
					n, err := strconv.Atoi(arg())
					ts.Check(err)
					fake.Fail(n)
				case "corruptnext":
					fake.CorruptNext()
				case "drop":
					fake.Drop()
				case "stop":
					fake.Stop()
				case "start":
					fake.Start()
				case "rotate":
					fake.RotateKey()
				case "corrupt":
					fake.Corrupt(arg())
				case "forget":
					fake.Forget(arg())
				case "cosign":
					fake.Cosign()
				case "hostname":
					fake.SetHostname(arg())
				case "reset":
					fake.Reset()
				case "requests":
					n, err := strconv.Atoi(arg())
					ts.Check(err)
					if got := fake.Requests(); len(got) != n {
						ts.Fatalf("fake saw %d requests, want %d: %v", len(got), n, got)
					}
				case "pubkey":
					ts.Check(os.WriteFile(ts.MkAbs(arg()), fake.PublicKeyPEM(), 0o600))
				case "posture":
					body := "anchor: tlog\nanchor_backend:\n  url: " + fake.URL + "\n"
					if len(args) == 3 && args[2] == "runs" {
						body += "anchor_runs: on-demand\n"
					}
					if len(args) == 3 && args[2] == "clientcreds" {
						body += "  credential:\n    grant_type: client_credentials\n    client_auth: client_secret_basic\n    token_endpoint: " + fake.URL + "/token\n    client_id_env: ANCHOR_CLIENT_ID\n    client_secret_env: ANCHOR_CLIENT_SECRET\n"
					}
					ts.Check(os.WriteFile(ts.MkAbs(args[1]), []byte(body), 0o600))
				default:
					ts.Fatalf("unknown rekor switch %q", args[0])
				}
			},
			// reforge <control-log> <seq>: rewrites records seq..N so the chain
			// stays valid but every head from seq on differs — the whole-root
			// rewrite anchoring exists to expose. The witness is replaced and
			// prev recomputed; seq and every other field are kept.
			"reforge": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: reforge <control-log> <seq>")
				}
				from, err := strconv.Atoi(args[1])
				ts.Check(err)
				path := ts.MkAbs(args[0])
				recs, _, err := ledger.ReadVerify(path, ledger.Unlocked)
				ts.Check(err)
				var out bytes.Buffer
				prev := ""
				for i, r := range recs {
					raw := r.Raw
					if i+1 >= from {
						var m map[string]any
						ts.Check(json.Unmarshal(raw, &m))
						m["prev"] = prev
						m["witness"] = map[string]any{"os_user": "forger", "hostname": "elsewhere"}
						raw, err = json.Marshal(m)
						ts.Check(err)
					}
					out.Write(raw)
					out.WriteByte('\n')
					sum := sha256.Sum256(raw)
					prev = hex.EncodeToString(sum[:])
				}
				ts.Check(os.WriteFile(path, out.Bytes(), 0o600))
			},
			// anchorref <control-log>: exports the last successful anchor's ref,
			// covered seq and hash as $REF, $ASEQ, $AHASH.
			"anchorref": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: anchorref <control-log>")
				}
				recs, _, err := ledger.ReadVerify(ts.MkAbs(args[0]), ledger.Unlocked)
				ts.Check(err)
				found := false
				for _, r := range recs {
					d, err := control.Decode(r.Raw)
					if err != nil || d.Action != "anchor" || d.Outcome != "success" || d.Anchor == nil {
						continue
					}
					ts.Setenv("REF", d.Anchor.Ref)
					ts.Setenv("ASEQ", strconv.Itoa(d.Anchor.Seq))
					ts.Setenv("AHASH", d.Anchor.Hash)
					found = true
				}
				if !found {
					ts.Fatalf("no successful anchor in %s", args[0])
				}
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
