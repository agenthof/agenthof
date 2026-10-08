package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity/oidctest"
	"github.com/agenthof/agenthof/internal/ledger"
)

func echoCompatHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Input string `json:"input"`
		Agent string `json:"agent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(req.Input, "FAIL:"+req.Agent) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"reason":  fmt.Sprintf("input requested a synthetic failure for %s", req.Agent),
		})
		return
	}
	if cmd, ok := strings.CutPrefix(req.Input, "exec:"); ok {
		if err := stubCallExec(r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token"), cmd); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "exec door: " + err.Error()})
			return
		}
	}
	if cmd, ok := strings.CutPrefix(req.Input, "exec-run:"); ok {
		if err := stubCallExecRun(r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token"), cmd); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "exec door: " + err.Error()})
			return
		}
	}
	if model, ok := strings.CutPrefix(req.Input, "model:"); ok {
		if err := stubCallModel(r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token"), model); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "model door: " + err.Error()})
			return
		}
	}
	if tool, ok := strings.CutPrefix(req.Input, "tool:"); ok {
		proxyURL := r.Header.Get("X-Agenthof-Proxy-URL")
		token := r.Header.Get("X-Agenthof-Run-Token")
		var pendingErr error
		callIndex := 0
		for _, name := range strings.Split(tool, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			err := stubCallTool(proxyURL, token, name)
			if err != nil {
				if callIndex == 0 {
					_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "tool door: " + err.Error()})
					return
				}
				if pendingErr == nil {
					pendingErr = err
				}
			}
			callIndex++
		}
		if pendingErr != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "tool door: " + pendingErr.Error()})
			return
		}
	}
	if spec, ok := strings.CutPrefix(req.Input, "spawn:"); ok {
		line, err := stubCallSpawn(r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token"), spec)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "spawn door: " + err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "artifact": line})
		return
	}
	if spec, ok := strings.CutPrefix(req.Input, "spawn-many:"); ok {
		// spawn-many:<n>:<role>/<workflow>:<input> — n sequential spawns of
		// the same child; the artifact is the lines joined.
		count, rest, _ := strings.Cut(spec, ":")
		n, err := strconv.Atoi(count)
		if err != nil || n < 1 {
			http.Error(w, "bad spawn-many", http.StatusBadRequest)
			return
		}
		var lines []string
		for range n {
			line, err := stubCallSpawn(r.Header.Get("X-Agenthof-Proxy-URL"), r.Header.Get("X-Agenthof-Run-Token"), rest)
			if err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "reason": "spawn door: " + err.Error()})
				return
			}
			lines = append(lines, line)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "artifact": strings.Join(lines, "\n")})
		return
	}
	line := req.Input
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	runes := []rune(line)
	if len(runes) > 80 {
		line = string(runes[:80])
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"artifact": "[" + req.Agent + "] " + line,
	})
}

// stubCallExec drives the retired agent-asserted route from the demo stub:
// one POST /exec/authorize. Exec is first-hand only, so the door answers
// every such call with a recorded 403; any non-2xx status is the error,
// which fails the step — what door_exec_runtime.txtar proves.
func stubCallExec(proxyURL, token, cmd string) error {
	if proxyURL == "" {
		return fmt.Errorf("no proxy url")
	}
	b, err := json.Marshal(map[string]any{"command": strings.Fields(cmd)})
	if err != nil {
		return err
	}
	client, base := doorClient(proxyURL)
	rq, err := http.NewRequest(http.MethodPost, base+"/exec/authorize", bytes.NewReader(b))
	if err != nil {
		return err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(rq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("/exec/authorize returned %d", resp.StatusCode)
	}
	return nil
}

// doorClient returns the client and base URL for a per-run gateway's proxy
// URL: a unix:// one — a spawned child's gateway under its socket dir — is
// dialed over that socket at the placeholder http://agenthof, as the
// reference agent does; anything else is the default client.
func doorClient(proxyURL string) (*http.Client, string) {
	if p, ok := strings.CutPrefix(proxyURL, "unix://"); ok {
		return &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", p)
			},
			DisableKeepAlives: true,
		}}, "http://agenthof"
	}
	return http.DefaultClient, strings.TrimRight(proxyURL, "/")
}

// stubCallExecRun drives the first-hand exec door: one POST /exec/run. A 200
// with exit 0 means the declared runtime ran the command and Agenthof
// recorded its account; anything else fails the step.
func stubCallExecRun(proxyURL, token, cmd string) error {
	if proxyURL == "" {
		return fmt.Errorf("no proxy url")
	}
	b, err := json.Marshal(map[string]any{"command": strings.Fields(cmd)})
	if err != nil {
		return err
	}
	client, base := doorClient(proxyURL)
	rq, err := http.NewRequest(http.MethodPost, base+"/exec/run", bytes.NewReader(b))
	if err != nil {
		return err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(rq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/exec/run returned %d", resp.StatusCode)
	}
	var out struct {
		Exit int `json:"exit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("/exec/run decode: %w", err)
	}
	if out.Exit != 0 {
		return fmt.Errorf("/exec/run exited %d", out.Exit)
	}
	return nil
}

// stubCallModel drives the model door: POST a chat completion through the proxy
// using the agent's logical model name (which modelHandler requires to match).
func stubCallModel(proxyURL, token, model string) error {
	if proxyURL == "" {
		return fmt.Errorf("no proxy url")
	}
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "demo"}},
	})
	if err != nil {
		return err
	}
	rq, err := http.NewRequest(http.MethodPost, strings.TrimRight(proxyURL, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("/v1/chat/completions returned %d", resp.StatusCode)
	}
	return nil
}

// bearerRT sets a fixed bearer token on every outbound request. The tool
// door's stub uses it to present ONLY the run token when dialing the
// proxy's inbound MCP server — Agenthof's injecting transport separately
// resolves and stamps the upstream resource credential on the outbound
// leg, so the run token never reaches the upstream.
type bearerRT struct {
	base  http.RoundTripper
	token string
}

func (t *bearerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// stubCallTool drives the tool door: connect to the proxy's inbound MCP server
// with ONLY the run token, and call the named tool. The agent never sees the
// upstream credential — Agenthof injects it on the upstream leg.
func stubCallTool(proxyURL, token, tool string) error {
	if proxyURL == "" {
		return fmt.Errorf("no proxy url")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpClient := &http.Client{Transport: &bearerRT{base: http.DefaultTransport, token: token}}
	client := mcp.NewClient(&mcp.Implementation{Name: "demo-stub", Version: "v0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: proxyURL, HTTPClient: httpClient}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"text": "demo"}})
	if err != nil {
		return err
	}
	if res.IsError {
		msg := "error result"
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok && tc.Text != "" {
				msg = tc.Text
				break
			}
		}
		return fmt.Errorf("tool %q returned an error: %s", tool, msg)
	}
	return nil
}

func writeSample(t *testing.T) string {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(echoCompatHandler))
	t.Cleanup(stub.Close)
	ep := "endpoint: " + stub.URL + "\n"
	root := t.TempDir()
	files := map[string]string{
		"agents/planner.yaml":    "name: planner\nmodel: fast\ninstruction: plan\noutput: plan\n" + ep,
		"agents/coder.yaml":      "name: coder\nmodel: fast\ninstruction: code\noutput: patch\n" + ep,
		"workflows/fix-bug.yaml": "name: fix-bug\nsteps:\n  - name: plan\n    agent: planner\n  - name: code\n    agent: coder\n    on_failure: plan\n",
		"roles/se.yaml":          "name: software-engineer\nworkflows: [fix-bug]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":         "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair, provision, prune]\n",
		"gateway.yaml":           "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// applied installs root under a fresh control root and returns that control
// log's path. run executes only the installed configuration, so every test
// that runs must apply first and pass this path as --control-log. Call it
// AFTER the last config file the test writes and BEFORE any t.Setenv of
// AGENTHOF_TOKEN (resolveInvoker takes the env token over --as). The first
// apply on a fresh control root bootstraps, so no grant is needed; the
// platform-eng group is asserted anyway for configs that carry
// writeSample's platform-admin role.
func applied(t *testing.T, root string) string {
	t.Helper()
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply %s: exit %d\n%s", root, code, out.String())
	}
	return controlLog
}

func TestApplyThenKillSwitchThenApplyReasserts(t *testing.T) {
	root := writeSample(t)
	// --control-log keeps this test's control ledger inside root rather
	// than the default relative ".agenthof/control.jsonl" (which would
	// otherwise be created next to the test binary, outside t.TempDir()).
	controlLog := filepath.Join(root, "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 2 roles") {
		t.Fatalf("out: %s", out.String())
	}
	// the kill switch re-snapshots the installed configuration: a run is
	// refused naming fix-bug, and apply from the unchanged directory
	// re-asserts the declared state (agent enabled) — recorded as an apply
	out.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %s", out.String())
	}
	out.Reset()
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--control-log", controlLog, "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir()}, &out, io.Discard)
	if code != 1 || !strings.Contains(out.String(), "fix-bug") || !strings.Contains(out.String(), "disabled") {
		t.Fatalf("a run must be refused naming the workflow: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out); code != 0 || !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 2 roles") {
		t.Fatalf("apply must re-assert the directory: %d\n%s", code, out.String())
	}
}

func TestApplyFailsOnFrontedAgentMissingEndpoint(t *testing.T) {
	root := writeSample(t)
	// Add a fronted agent without endpoint
	helperPath := filepath.Join(root, "agents", "helper.yaml")
	if err := os.WriteFile(helperPath, []byte("name: helper\nexecution: fronted\ninstruction: help\noutput: result\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	controlLog := filepath.Join(root, "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatalf("apply must fail with fronted agent missing endpoint, got code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "helper") {
		t.Fatalf("error must name the agent: %s", out.String())
	}
	if !strings.Contains(out.String(), "endpoint") {
		t.Fatalf("error must mention endpoint: %s", out.String())
	}
}

func TestRunAndAuditEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	ctl := applied(t, root)
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	for _, want := range []string{"invoked by dana@example.com (asserted", "status: succeeded", "step plan succeeded", "ledger integrity: verified"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("audit missing %q:\n%s", want, out.String())
		}
	}
}

// TestAuditCorruptedFirstLineReportsIntegrityFailureAndExitsNonZero is a
// regression test for a bug where a ledger torn/broken at its very first
// record (e.g. a crash right after the first write) — leaving ZERO
// verified records — was misreported by `audit` as a healthy, merely
// empty run ("no events for this run", exit 0) instead of surfacing the
// integrity failure and a non-zero exit.
func TestAuditCorruptedFirstLineReportsIntegrityFailureAndExitsNonZero(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	ctl := applied(t, root)
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	runID := m[1]

	// Simulate a crash right after the very first ledger write: truncate
	// the file down to just the first record's bytes minus its trailing
	// newline, leaving zero fully-verified (torn tail, at record 1) records.
	path := filepath.Join(logs, runID+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstNL := bytes.IndexByte(raw, '\n')
	if firstNL < 0 {
		t.Fatal("expected at least one newline in a multi-event log")
	}
	if err := os.WriteFile(path, raw[:firstNL], 0o600); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	code = cmdAudit([]string{runID, "--log-dir", logs}, &out)
	if code == 0 {
		t.Fatalf("a corrupted ledger with zero valid records must exit non-zero, got 0:\n%s", out.String())
	}
	if strings.Contains(out.String(), "no events for this run") {
		t.Fatalf("a corrupted ledger must never be reported as a healthy empty run:\n%s", out.String())
	}
	// This truncation leaves a single, unterminated final line — genuinely
	// torn, not chain-broken — so the integrity line must say TORN, which
	// carries its own banner distinct from the BROKEN case.
	if !strings.Contains(out.String(), "ledger integrity: TORN") {
		t.Fatalf("missing integrity failure line:\n%s", out.String())
	}
}

func TestAuditVerifyCleanAndExpectHead(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	ctl := applied(t, root)
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
		t.Fatalf("run: %s", out.String())
	}
	id := regexp.MustCompile(`run (r-[0-9a-f]+) finished`).FindStringSubmatch(out.String())[1]

	out.Reset()
	if code := cmdAudit([]string{"verify", id, "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("verify: %d %s", code, out.String())
	}
	m := regexp.MustCompile(`head: ([0-9a-f]{64}) \((\d+) events\)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no head line: %s", out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{"verify", id, "--log-dir", logs, "--expect-head", m[1]}, &out); code != 0 {
		t.Fatal("matching expect-head must pass")
	}
	out.Reset()
	if code := cmdAudit([]string{"verify", id, "--log-dir", logs, "--expect-head", strings.Repeat("0", 64)}, &out); code != 4 {
		t.Fatalf("mismatch must exit 4, got %d", code)
	}
}

func TestAuditTornExitsOne(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	ctl := applied(t, root)
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
		t.Fatalf("run: %s", out.String())
	}
	id := regexp.MustCompile(`run (r-[0-9a-f]+) finished`).FindStringSubmatch(out.String())[1]

	// Simulate a crash mid-write: append an incomplete trailing record with
	// no terminating newline — a torn tail, not a broken chain.
	path := filepath.Join(logs, id+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("{torn")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	code := cmdAudit([]string{id, "--log-dir", logs}, &out)
	if code != 1 {
		t.Fatalf("torn ledger must exit 1, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "TORN") {
		t.Fatalf("output must mention TORN: %s", out.String())
	}
	if !strings.Contains(out.String(), "workflow started") {
		t.Fatalf("output must still render the valid prefix: %s", out.String())
	}
}

func TestAuditDeletedTailPassesButExpectHeadFails(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	ctl := applied(t, root)
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
		t.Fatalf("run: %s", out.String())
	}
	id := regexp.MustCompile(`run (r-[0-9a-f]+) finished`).FindStringSubmatch(out.String())[1]

	out.Reset()
	if code := cmdAudit([]string{"verify", id, "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("verify: %d %s", code, out.String())
	}
	m := regexp.MustCompile(`head: ([0-9a-f]{64}) \((\d+) events\)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no head line: %s", out.String())
	}
	oldHead := m[1]

	// Truncate the last line and its trailing newline — an honest deletion
	// leaves the remaining chain internally consistent (documented
	// limitation: ReadVerify cannot detect a deleted tail on its own), so
	// verify without --expect-head must still pass.
	path := filepath.Join(logs, id+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimRight(string(raw), "\n")
	lastNL := strings.LastIndexByte(trimmed, '\n')
	if lastNL < 0 {
		t.Fatal("expected at least two lines in a multi-event log")
	}
	if err := os.WriteFile(path, []byte(trimmed[:lastNL+1]), 0o600); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if code := cmdAudit([]string{"verify", id, "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("verify on a deleted tail must still pass (documented limitation): %d %s", code, out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{"verify", id, "--log-dir", logs, "--expect-head", oldHead}, &out); code != 4 {
		t.Fatalf("expect-head against the pre-deletion head must catch the truncation, got %d\n%s", code, out.String())
	}
}

func TestRunFailBackOffline(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	ctl := applied(t, root)
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "do it FAIL:coder", "--as", "dev@x", "--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	_ = code // coder always fails on this input; bounces exhaust; run fails honestly
	if !strings.Contains(out.String(), "finished: failed") {
		t.Fatalf("out: %s", out.String())
	}
}

func TestRunRefusedUnknownRole(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	var out bytes.Buffer
	ctl := applied(t, root)
	code := cmdRun([]string{"ghost", "fix-bug", "--input", "x", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", t.TempDir()}, &out, io.Discard)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("code=%d out=%s", code, out.String())
	}
	if strings.Contains(out.String(), "no configuration installed") {
		t.Fatalf("the refusal must be the registry gate's, not a missing install: %s", out.String())
	}
}

// pruneArgs is a runs prune invocation by the platform-eng group against ctl.
func pruneArgs(ctl string, extra ...string) []string {
	return append([]string{"prune", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, extra...)
}

// appliedAt is applied with the control log at a path the test chooses —
// for the self-victim layouts, where the ledger must sit inside --log-dir.
func appliedAt(t *testing.T, root, ctl string) {
	t.Helper()
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply %s at %s: exit %d\n%s", root, ctl, code, out.String())
	}
}

// controlLogID reads the genesis record's log_id — the chain's identity,
// which a fresh genesis (the self-victim wound) would replace.
func controlLogID(t *testing.T, ctl string) string {
	t.Helper()
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil || len(recs) == 0 {
		t.Fatalf("read %s: %v (%d records)", ctl, err, len(recs))
	}
	var genesis struct {
		LogID string `json:"log_id"`
	}
	if err := json.Unmarshal(recs[0].Raw, &genesis); err != nil || genesis.LogID == "" {
		t.Fatalf("genesis log_id: %v %q", err, genesis.LogID)
	}
	return genesis.LogID
}

// agedRun writes a run-log-shaped file under logDir with an mtime 200 days
// in the past and returns its path.
func agedRun(t *testing.T, logDir, name string) string {
	t.Helper()
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(logDir, name)
	if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunsPruneDeletesOldRuns(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	dir := t.TempDir()
	oldPath := agedRun(t, dir, "r-old.jsonl")
	newPath := filepath.Join(dir, "r-new.jsonl")
	if err := os.WriteFile(newPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", dir), &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	const line = "pruned 1 run(s) and 0 artifact(s) older than 180d"
	if !strings.Contains(out.String(), line+"\n") || !strings.Contains(out.String(), "control head: seq=2 sha256=") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old run should be gone, err=%v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("new run should remain: %v", err)
	}
	e := lastControlEvent(t, ctl)
	if e.Action != "prune" || e.Outcome != "success" || e.Detail != line || e.ConfigHash != "" || e.Agent != "" || e.Invoker.Subject != "dana@example.com" {
		t.Fatalf("want success with detail == the printed line and no hash: %+v", e)
	}
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "runs pruned ("+line+") — dana@example.com (asserted)") {
		t.Fatalf("audit control: %d\n%s", code, out.String())
	}
}

func TestRunsPruneAlsoPrunesArtifactStore(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	logDir := t.TempDir()
	artifactDir := t.TempDir()
	// Artifact bodies are named by their 64-hex sha256; prune only ever removes
	// that content-addressed shape.
	oldArtifact := filepath.Join(artifactDir, "0000000000000000000000000000000000000000000000000000000000000001")
	newArtifact := filepath.Join(artifactDir, "0000000000000000000000000000000000000000000000000000000000000002")
	if err := os.WriteFile(oldArtifact, []byte("stale body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newArtifact, []byte("fresh body"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(oldArtifact, old, old); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", logDir, "--artifact-dir", artifactDir), &out)
	if code != 0 || !strings.Contains(out.String(), "pruned 0 run(s) and 1 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(oldArtifact); !os.IsNotExist(err) {
		t.Fatalf("old artifact should be gone, err=%v", err)
	}
	if _, err := os.Stat(newArtifact); err != nil {
		t.Fatalf("new artifact should remain: %v", err)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "success" || e.Detail != "pruned 0 run(s) and 1 artifact(s) older than 180d" {
		t.Fatalf("%+v", e)
	}
}

func TestRunsPruneMissingArtifactDirIsNotAnError(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	logDir := t.TempDir()
	artifactDir := filepath.Join(t.TempDir(), "does-not-exist")
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", logDir, "--artifact-dir", artifactDir), &out)
	if code != 0 || !strings.Contains(out.String(), "pruned 0 run(s) and 0 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(artifactDir); !os.IsNotExist(err) {
		t.Fatalf("a missing artifact-dir must not be created just to find nothing to prune: %v", err)
	}
}

// TestRunsPruneGarbageDuration stays flag-free on purpose: the usage check
// precedes identity and the ledger, so it needs no installed configuration.
func TestRunsPruneGarbageDuration(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "abc", "--log-dir", dir}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2 for garbage duration, got %d\n%s", code, out.String())
	}
}

func TestRunsPruneMissingLogDir(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", dir), &out)
	if code != 0 || !strings.Contains(out.String(), "pruned 0 run(s) and 0 artifact(s)") {
		t.Fatalf("expected exit 0 for missing log dir, got %d\n%s", code, out.String())
	}
}

// TestRunsPruneNonPositiveDuration stays flag-free: see TestRunsPruneGarbageDuration.
func TestRunsPruneNonPositiveDuration(t *testing.T) {
	// A non-positive duration would push the cutoff into the future,
	// deleting every run file. Guard against it instead.
	cases := []string{"-5d", "0d", "-3h", "0h"}
	for _, olderThan := range cases {
		t.Run(olderThan, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "r-x.jsonl")
			if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code := cmdRuns([]string{"prune", "--older-than", olderThan, "--log-dir", dir}, &out)
			if code != 2 || !strings.Contains(out.String(), "--older-than must be a positive duration") {
				t.Fatalf("expected exit 2 for %q, got %d\n%s", olderThan, code, out.String())
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("run file should be untouched for %q: %v", olderThan, err)
			}
		})
	}
}

// TestRunsPruneUsageErrorsTouchNoLedger: a bad --older-than — garbage,
// non-positive, or a day count that would overflow the duration and wrap
// to a positive value — exits 2 before identity and before the ledger is
// opened, so no control log is created and no run file is touched.
func TestRunsPruneUsageErrorsTouchNoLedger(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	for _, olderThan := range []string{"abc", "0d", "-3h", "99999999999d", "9223372036854775807d"} {
		t.Run(olderThan, func(t *testing.T) {
			dir := t.TempDir()
			aged := agedRun(t, dir, "r-old.jsonl")
			ctl := filepath.Join(t.TempDir(), "control.jsonl")
			var out bytes.Buffer
			code := cmdRuns(pruneArgs(ctl, "--older-than", olderThan, "--log-dir", dir), &out)
			if code != 2 {
				t.Fatalf("exit %d for %q\n%s", code, olderThan, out.String())
			}
			if _, err := os.Stat(ctl); !os.IsNotExist(err) {
				t.Fatalf("a usage fault must not create the control ledger: %v", err)
			}
			if _, err := os.Stat(aged); err != nil {
				t.Fatalf("nothing may be deleted on a usage fault: %v", err)
			}
		})
	}
}

func TestRunsPruneLogDirIsRegularFile(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	notADir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", notADir), &out)
	if code != 1 {
		t.Fatalf("expected exit 1 when --log-dir is a regular file, got %d\n%s", code, out.String())
	}
	if e := lastControlEvent(t, ctl); e.Action != "prune" || e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError || e.Detail != "" {
		t.Fatalf("want error/io_error with no detail (nothing was deleted): %+v", e)
	}
}

// TestRunsPruneSparesControlLogAndFragments proves the default layout is
// safe: a decoy control.jsonl and its .torn-* fragment — both outside
// --log-dir — survive while the aged run log under --log-dir is pruned. The
// decoy is spared by name; the ledger prune actually records to is a real,
// applied one elsewhere.
func TestRunsPruneSparesControlLogAndFragments(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	root := t.TempDir()
	agentDir := filepath.Join(root, ".agenthof")
	runsDir := filepath.Join(agentDir, "runs")
	oldRun := agedRun(t, runsDir, "r-old.jsonl")
	decoy := filepath.Join(agentDir, "control.jsonl")
	fragment := decoy + ".torn-1"
	for _, p := range []string{decoy, fragment} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "24h", "--log-dir", runsDir), &out); code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(oldRun); !os.IsNotExist(err) {
		t.Fatalf("old run log should be pruned, err=%v", err)
	}
	for _, p := range []string{decoy, fragment} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must survive prune: %v", p, err)
		}
	}
}

// TestRunsPruneNeverDeletesControlLogEvenIfLogDirPointsAtItsDir covers the
// misconfiguration: --log-dir points at a directory holding a control.jsonl
// and its fragment. Both survive by name while the aged run beside them is
// pruned — the guard is discriminating, not "prune did nothing".
func TestRunsPruneNeverDeletesControlLogEvenIfLogDirPointsAtItsDir(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	agentDir := t.TempDir()
	oldRun := agedRun(t, agentDir, "r-old.jsonl")
	decoy := filepath.Join(agentDir, "control.jsonl")
	fragment := decoy + ".torn-1"
	for _, p := range []string{decoy, fragment} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "24h", "--log-dir", agentDir), &out); code != 0 || !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(oldRun); !os.IsNotExist(err) {
		t.Fatalf("old run log should still be pruned, err=%v", err)
	}
	for _, p := range []string{decoy, fragment} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must survive prune even when --log-dir points at its directory: %v", p, err)
		}
	}
}

// TestRunsPruneNothingInstalledDeletesNothing: no roles, nobody is
// authorized — the refusal is the ledger's genesis record and the aged run
// survives. Prune has no --config fallback: it reads no directory.
func TestRunsPruneNothingInstalledDeletesNothing(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	dir := t.TempDir()
	aged := agedRun(t, dir, "r-old.jsonl")
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", dir), &out)
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	for _, want := range []string{
		"runs prune: " + msgNothingInstalled + "\n",
		"no configuration installed under " + installedStore(ctl) + "; run: agenthof apply --config <dir> --control-log " + ctl + "\n",
		"control head: seq=1 sha256=",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	if e := lastControlEvent(t, ctl); e.Action != "prune" || e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeNotAuthorized || e.Reason.Message != msgNothingInstalled || e.ConfigHash != "" || e.Detail != "" {
		t.Fatalf("%+v", e)
	}
	if _, err := os.Stat(aged); err != nil {
		t.Fatalf("nothing may be deleted: %v", err)
	}
}

func TestRunsPruneUngrantedDeletesNothing(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	dir := t.TempDir()
	aged := agedRun(t, dir, "r-old.jsonl")
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--control-log", ctl, "--as", "mallory@example.com", "--groups", "finance", "--older-than", "180d", "--log-dir", dir}, &out)
	if code != 1 || !strings.Contains(out.String(), "runs prune: not authorized: no role grants prune to the invoker") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeNotAuthorized || e.ConfigHash != "" {
		t.Fatalf("%+v", e)
	}
	if _, err := os.Stat(aged); err != nil {
		t.Fatalf("nothing may be deleted: %v", err)
	}
}

// TestRunsPruneArtifactStoreErrorRecordsPartialDetail: the runs WERE
// deleted before the artifact store failed, and the error record says so.
func TestRunsPruneArtifactStoreErrorRecordsPartialDetail(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	dir := t.TempDir()
	aged := agedRun(t, dir, "r-old.jsonl")
	notADir := filepath.Join(t.TempDir(), "artifacts")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", dir, "--artifact-dir", notADir), &out)
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatalf("the run was pruned before the artifact step: %v", err)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError || e.Detail != "pruned 1 run(s) and 0 artifact(s) older than 180d" {
		t.Fatalf("want error with the partial detail: %+v", e)
	}
}

// TestRunsPruneSparesTheLedgerItRecordsTo is the self-victim guard: the
// ledger prune records to sits INSIDE --log-dir under a non-default name,
// aged past the cutoff. Without the identity skip the sweep would delete it
// and the final append would re-create a fresh genesis chain. The ledger
// survives with one more record and the same log_id; the aged run beside it
// is gone; the store and its lock file beside the ledger survive too.
func TestRunsPruneSparesTheLedgerItRecordsTo(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	logDir := t.TempDir()
	ctl := filepath.Join(logDir, "ledger.jsonl")
	appliedAt(t, writeSample(t), ctl)
	before, id := len(controlEvents(t, ctl)), controlLogID(t, ctl)
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(ctl, old, old); err != nil {
		t.Fatal(err)
	}
	aged := agedRun(t, logDir, "r-old.jsonl")
	var out bytes.Buffer
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", logDir), &out); code != 0 || !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatalf("the aged run must be gone: %v", err)
	}
	if n, after := len(controlEvents(t, ctl)), controlLogID(t, ctl); n != before+1 || after != id {
		t.Fatalf("the ledger must survive as the same chain: records %d→%d, log_id %s→%s", before, n, id, after)
	}
	for _, p := range []string{installedStore(ctl), installedLock(ctl)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must survive a prune of its directory: %v", p, err)
		}
	}
}

// TestRunsPruneArtifactSweepSparesTheControlLedger: the artifact sweep removes
// only content-addressed bodies (the 64-hex sha256 Put writes), so a
// misconfigured --artifact-dir pointing at the control ledger's own directory
// never deletes the ledger, a repair fragment, or the installed-config lock —
// and the prune's own success append does not re-genesis a fresh ledger. The
// companion to the --log-dir guard above, on the other sweep.
func TestRunsPruneArtifactSweepSparesTheControlLedger(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	logDir := t.TempDir()
	ctl := filepath.Join(logDir, "control.jsonl")
	appliedAt(t, writeSample(t), ctl)
	before, id := len(controlEvents(t, ctl)), controlLogID(t, ctl)
	torn := ctl + ".torn-123"
	if err := os.WriteFile(torn, []byte("fragment"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real content-addressed body that MUST be pruned (proves the sweep works).
	body := filepath.Join(logDir, "0000000000000000000000000000000000000000000000000000000000000001")
	if err := os.WriteFile(body, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	for _, p := range []string{ctl, torn, body} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	// --artifact-dir is the ledger's OWN directory — the misconfiguration.
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", t.TempDir(), "--artifact-dir", logDir), &out); code != 0 ||
		!strings.Contains(out.String(), "pruned 0 run(s) and 1 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(body); !os.IsNotExist(err) {
		t.Fatalf("the content-addressed body must be pruned: %v", err)
	}
	for _, p := range []string{ctl, torn, installedLock(ctl), installedStore(ctl)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must survive the artifact sweep: %v", p, err)
		}
	}
	if n, after := len(controlEvents(t, ctl)), controlLogID(t, ctl); n != before+1 || after != id {
		t.Fatalf("the ledger must survive as the same chain: records %d→%d, log_id %s→%s", before, n, id, after)
	}
}

// TestRunsPruneSparesTheLedgerThroughASymlinkedControlLog: --control-log is
// a symlink OUTSIDE --log-dir pointing at the real, aged ledger INSIDE it.
// Both sides of the identity check follow links, so the real file is
// spared.
func TestRunsPruneSparesTheLedgerThroughASymlinkedControlLog(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	logDir := t.TempDir()
	real := filepath.Join(logDir, "ledger.jsonl")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "control.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	appliedAt(t, writeSample(t), link)
	before, id := len(controlEvents(t, link)), controlLogID(t, link)
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(real, old, old); err != nil {
		t.Fatal(err)
	}
	aged := agedRun(t, logDir, "r-old.jsonl")
	var out bytes.Buffer
	if code := cmdRuns(pruneArgs(link, "--older-than", "180d", "--log-dir", logDir), &out); code != 0 || !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatalf("the aged run must be gone: %v", err)
	}
	if _, err := os.Stat(real); err != nil {
		t.Fatalf("the real ledger must survive: %v", err)
	}
	if n, after := len(controlEvents(t, link)), controlLogID(t, link); n != before+1 || after != id {
		t.Fatalf("same chain: records %d→%d, log_id %s→%s", before, n, id, after)
	}
}

// TestRunsPruneSparesTheLedgerBehindASymlinkedEntry: the entry INSIDE
// --log-dir is a symlink to the real ledger elsewhere, which --control-log
// names directly. DirEntry.Info is an lstat and would describe the link, so
// an entry-side lstat would compare unequal and remove the link; the
// follow-stat compares equal. os.Chtimes follows links and cannot age the
// link itself, so the cutoff is made tiny instead: after the sleep every
// entry is older than it, and only the identity skip can spare the link.
func TestRunsPruneSparesTheLedgerBehindASymlinkedEntry(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	before, id := len(controlEvents(t, ctl)), controlLogID(t, ctl)
	logDir := t.TempDir()
	link := filepath.Join(logDir, "link.jsonl")
	if err := os.Symlink(ctl, link); err != nil {
		t.Fatal(err)
	}
	aged := agedRun(t, logDir, "r-old.jsonl")
	time.Sleep(1100 * time.Millisecond) // past a 1 s mtime granularity, so the link is older than a 10 ms cutoff
	var out bytes.Buffer
	// --artifact-dir is explicit: a 10 ms cutoff must never meet the default
	// cwd-relative artifact store.
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "10ms", "--log-dir", logDir, "--artifact-dir", t.TempDir()), &out); code != 0 || !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatalf("the aged run must be gone: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the symlink to the ledger must survive: %v", err)
	}
	if n, after := len(controlEvents(t, ctl)), controlLogID(t, ctl); n != before+1 || after != id {
		t.Fatalf("same chain: records %d→%d, log_id %s→%s", before, n, id, after)
	}
}

// TestRunsPruneSparesAHardLinkToTheLedger: a hard link shares the inode,
// so it is the ledger by identity whatever it is called.
func TestRunsPruneSparesAHardLinkToTheLedger(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	before, id := len(controlEvents(t, ctl)), controlLogID(t, ctl)
	logDir := t.TempDir()
	hard := filepath.Join(logDir, "hard.jsonl")
	if err := os.Link(ctl, hard); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(ctl, old, old); err != nil { // one inode: ages the hard link too
		t.Fatal(err)
	}
	aged := agedRun(t, logDir, "r-old.jsonl")
	var out bytes.Buffer
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", logDir), &out); code != 0 || !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatalf("the aged run must be gone: %v", err)
	}
	if _, err := os.Stat(hard); err != nil {
		t.Fatalf("the hard link must survive: %v", err)
	}
	if n, after := len(controlEvents(t, ctl)), controlLogID(t, ctl); n != before+1 || after != id {
		t.Fatalf("same chain: records %d→%d, log_id %s→%s", before, n, id, after)
	}
}

// TestPruneRunsFailsHardWhenTheControlLogCannotBeStatted: a guard that
// cannot establish the ledger's identity deletes nothing — the error is
// returned before the directory is even read.
func TestPruneRunsFailsHardWhenTheControlLogCannotBeStatted(t *testing.T) {
	logDir := t.TempDir()
	aged := agedRun(t, logDir, "r-old.jsonl")
	missing := filepath.Join(t.TempDir(), "gone", "control.jsonl")
	n, err := pruneRuns(logDir, time.Hour, missing)
	if err == nil || n != 0 || !strings.Contains(err.Error(), "control log "+missing) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := os.Stat(aged); err != nil {
		t.Fatalf("nothing may be deleted: %v", err)
	}
}

// TestRunsPruneDeletesNothingWhenTheControlLogVanishesBeforeTheSweep is the
// command-level twin: the ledger was writable at the precheck and cannot be
// stat'd by the time the sweep starts (unlinked or made unreadable by
// another process in between). The filesystem alone cannot stage that in a
// test — the same path was just opened — so the stat goes through the
// statControlLog seam. Exit 1, the printed line names the control log, the
// aged run survives, and the error is recorded.
func TestRunsPruneDeletesNothingWhenTheControlLogVanishesBeforeTheSweep(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	logDir := t.TempDir()
	aged := agedRun(t, logDir, "r-old.jsonl")
	orig := statControlLog
	statControlLog = func(name string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	t.Cleanup(func() { statControlLog = orig })
	var out bytes.Buffer
	code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", logDir), &out)
	if code != 1 || !strings.Contains(out.String(), "control log "+ctl) {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if _, err := os.Stat(aged); err != nil {
		t.Fatalf("nothing may be deleted: %v", err)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError || e.Detail != "" {
		t.Fatalf("%+v", e)
	}
}

// adminMock is a LiteLLM-shaped admin API for the provision tests: it
// answers /key/generate with a fresh key and counts the generations; when
// failAt > 0 the failAt-th generation answers 500 with sentinel in its body,
// so a test can prove the body never reaches stdout or the ledger. Every
// other path is 500 (provision never calls /key/info for a role with no key
// file yet).
func adminMock(t *testing.T, failAt int, sentinel string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var generated atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/key/generate" {
			n := generated.Add(1)
			if int(n) == failAt {
				http.Error(w, sentinel, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key":"sk-test"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv, &generated
}

// provisionArgs is a gateway provision invocation by the platform-eng
// group against ctl and the mock admin API.
func provisionArgs(ctl, adminBase string) []string {
	return []string{"provision", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng", "--admin-base", adminBase}
}

// budgetedSample is writeSample plus a $50 budget on software-engineer, so
// the provisioner has something to mint; it must be applied AFTER this
// rewrite, since provision reads the installed roles, budget included.
func budgetedSample(t *testing.T) string {
	t.Helper()
	root := writeSample(t)
	writeFileIn(t, root, "roles/se.yaml", "name: software-engineer\nworkflows: [fix-bug]\nbudget_usd_month: 50\nallowed_groups: [\"*\"]\n")
	return root
}

// TestGatewayProvisionMissingMasterKey: the master key is a usage fault of
// the same class as a bad flag — checked before identity and the ledger, so
// nothing is recorded and no ledger is created.
func TestGatewayProvisionMissingMasterKey(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--control-log", ctl}, &out)
	if code != 2 || !strings.Contains(out.String(), "LITELLM_MASTER_KEY") {
		t.Fatalf("expected exit 2 naming LITELLM_MASTER_KEY, got %d\n%s", code, out.String())
	}
	if _, err := os.Stat(ctl); !os.IsNotExist(err) {
		t.Fatalf("a usage fault must not create the control ledger: %v", err)
	}
}

// TestGatewayProvisionConfigFlagIsRetired: provision mints for the
// INSTALLED roles and takes no directory; the old flag is a loud usage
// error, never silently ignored.
func TestGatewayProvisionConfigFlagIsRetired(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--config", t.TempDir(), "--control-log", ctl}, &out)
	if code != 2 || !strings.Contains(out.String(), "flag provided but not defined: -config") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if _, err := os.Stat(ctl); !os.IsNotExist(err) {
		t.Fatalf("a usage fault must not create the control ledger: %v", err)
	}
}

// TestGatewayProvisionNothingInstalledIsARecordedRefusal: no roles, nobody
// is authorized — recorded not_authorized with the fixed path-free message
// and no config_hash, the remedy printed, no admin-API call.
func TestGatewayProvisionNothingInstalledIsARecordedRefusal(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	srv, generated := adminMock(t, 0, "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	code := cmdGateway(provisionArgs(ctl, srv.URL), &out)
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	for _, want := range []string{
		"gateway provision: " + msgNothingInstalled + "\n",
		"no configuration installed under " + installedStore(ctl) + "; run: agenthof apply --config <dir> --control-log " + ctl + "\n",
		"control head: seq=1 sha256=",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	e := lastControlEvent(t, ctl)
	if e.Action != "provision" || e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeNotAuthorized || e.Reason.Message != msgNothingInstalled || e.ConfigHash != "" {
		t.Fatalf("want refused/not_authorized without a hash: %+v", e)
	}
	if generated.Load() != 0 {
		t.Fatal("a refusal must not touch the admin API")
	}
}

// TestGatewayProvisionUngrantedIsRefusedWithTheInstalledHash: the invoker's
// group is granted nothing — recorded refused/not_authorized with the hash
// of the configuration they were refused against, no API call, no key.
func TestGatewayProvisionUngrantedIsRefusedWithTheInstalledHash(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	ctl := applied(t, budgetedSample(t))
	srv, generated := adminMock(t, 0, "")
	t.Chdir(t.TempDir())
	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--control-log", ctl, "--as", "mallory@example.com", "--groups", "finance", "--admin-base", srv.URL}, &out)
	if code != 1 || !strings.Contains(out.String(), "gateway provision: not authorized: no role grants provision to the invoker") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	e := lastControlEvent(t, ctl)
	if e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeNotAuthorized || e.ConfigHash != readPointer(t, ctl) {
		t.Fatalf("want refused with the installed hash: %+v", e)
	}
	if generated.Load() != 0 {
		t.Fatal("a refusal must not touch the admin API")
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); !os.IsNotExist(err) {
		t.Fatalf("no key may be written: %v", err)
	}
}

// TestGatewayProvisionEndToEnd: an authorized provision mints for the
// installed roles, records success with the installed hash, renders
// "provision ok", and is never an install — audit verify control stays 0
// and a run under the same hash still joins to the apply.
func TestGatewayProvisionEndToEnd(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	ctl := applied(t, root)
	srv, generated := adminMock(t, 0, "")
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	code := cmdGateway(provisionArgs(ctl, srv.URL), &out)
	if code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	for _, want := range []string{"provisioned key for role software-engineer (budget $50)", "control head: seq=2 sha256="} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); err != nil {
		t.Fatalf("key file not written under ./.agenthof/keys/: %v", err)
	}
	if generated.Load() != 1 {
		t.Fatalf("key generations = %d, want 1", generated.Load())
	}
	pointer := readPointer(t, ctl)
	e := lastControlEvent(t, ctl)
	if e.Action != "provision" || e.Outcome != "success" || e.ConfigHash != pointer || e.Agent != "" || e.Detail != "" || e.Invoker.Subject != "dana@example.com" || e.Bootstrap {
		t.Fatalf("want a success record carrying the installed hash and nothing else: %+v", e)
	}
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", ctl}, &out); code != 0 {
		t.Fatalf("audit control: %d\n%s", code, out.String())
	}
	for _, want := range []string{"provision ok — dana@example.com (asserted)", "matches the last recorded install (apply)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &out); code != 0 {
		t.Fatalf("a provision record is not an install: %d\n%s", code, out.String())
	}
	// The run config-join ignores the provision: a run under the same hash
	// names the apply.
	logDir := t.TempDir()
	out.Reset()
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logDir, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	entries, err := os.ReadDir(logDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("one run log: %v %d", err, len(entries))
	}
	runID := strings.TrimSuffix(entries[0].Name(), ".jsonl")
	out.Reset()
	if code := cmdAudit([]string{runID, "--log-dir", logDir, "--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "config "+pointer+" — applied by dana@example.com") {
		t.Fatalf("audit %s: %d\n%s", runID, code, out.String())
	}
	out.Reset()
	if code := cmdInvestigate([]string{"--config-hash", pointer, "--log-dir", logDir, "--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "control provision — dana@example.com (asserted)") || !strings.Contains(out.String(), "control apply — dana@example.com (asserted)") {
		t.Fatalf("investigate must list the provision beside the apply: %d\n%s", code, out.String())
	}
}

// TestGatewayProvisionSkipsWorkflowLessRole: a control-only role runs nothing,
// so provision mints it no provider key — a key with budget $0 would be a
// credential nothing consumes. The mock counts key generations.
func TestGatewayProvisionSkipsWorkflowLessRole(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	writeFileIn(t, root, "roles/ops.yaml", "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair, provision, prune]\n")
	ctl := applied(t, root)
	srv, generated := adminMock(t, 0, "")
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	if code := cmdGateway(provisionArgs(ctl, srv.URL), &out); code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "role platform-admin: owns no workflows; no key provisioned") {
		t.Fatalf("missing skip line: %s", out.String())
	}
	if generated.Load() != 1 {
		t.Fatalf("key generations = %d, want 1 (software-engineer only)", generated.Load())
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "platform-admin.key")); !os.IsNotExist(err) {
		t.Fatalf("a control-only role must get no key file; stat err = %v", err)
	}
}

// TestGatewayProvisionEveryRoleControlOnlyIsStillSuccess: nothing to mint is
// still a completed, recorded provision — "provision ok", never a label
// claiming keys were minted.
func TestGatewayProvisionEveryRoleControlOnlyIsStillSuccess(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := t.TempDir()
	writeFileIn(t, root, "roles/ops.yaml", "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair, provision, prune]\n")
	ctl := applied(t, root)
	srv, generated := adminMock(t, 0, "")
	t.Chdir(t.TempDir())
	var out bytes.Buffer
	if code := cmdGateway(provisionArgs(ctl, srv.URL), &out); code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	if generated.Load() != 0 {
		t.Fatal("nothing to mint")
	}
	if e := lastControlEvent(t, ctl); e.Action != "provision" || e.Outcome != "success" || e.ConfigHash != readPointer(t, ctl) {
		t.Fatalf("%+v", e)
	}
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "provision ok") || strings.Contains(out.String(), "keys provisioned") {
		t.Fatalf("%d\n%s", code, out.String())
	}
}

// TestGatewayProvisionMintFailureIsPartialAndFixedInTheLedger: the first
// failing role stops the loop; keys minted before it persist; stdout carries
// the status text (generateKey never reads the body); the ledger carries the
// fixed message naming the role and the installed hash; and a sentinel the
// mock puts in its 500 body appears nowhere — not on stdout, not in the
// ledger.
func TestGatewayProvisionMintFailureIsPartialAndFixedInTheLedger(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	// roles/ sorts ops, qa, se: ops is skipped, qa mints first, se second.
	writeFileIn(t, root, "roles/qa.yaml", "name: qa-engineer\nworkflows: [fix-bug]\nbudget_usd_month: 10\nallowed_groups: [\"*\"]\n")
	ctl := applied(t, root)
	const sentinel = "SENTINEL-BODY-5c0ffee"
	srv, generated := adminMock(t, 2, sentinel)
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	code := cmdGateway(provisionArgs(ctl, srv.URL), &out)
	if code != 1 || generated.Load() != 2 {
		t.Fatalf("exit %d generations %d\n%s", code, generated.Load(), out.String())
	}
	if !strings.Contains(out.String(), "role software-engineer: gateway: key generate returned status 500") {
		t.Fatalf("stdout must carry the status text:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "qa-engineer.key")); err != nil {
		t.Fatalf("the key minted before the failure persists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); !os.IsNotExist(err) {
		t.Fatalf("the failing role gets no key: %v", err)
	}
	e := lastControlEvent(t, ctl)
	if e.Action != "provision" || e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError || e.Reason.Message != "provisioning failed for role software-engineer" || e.ConfigHash != readPointer(t, ctl) {
		t.Fatalf("want error/io_error with the fixed message and the installed hash: %+v", e)
	}
	raw, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), sentinel) || strings.Contains(string(raw), sentinel) {
		t.Fatal("the admin API's response body must never be read, printed or ledgered")
	}
}

// TestGatewayProvisionIsNotBlockedByAKillSwitchFlip: after `registry disable
// coder` the installed snapshot fails Build (disabled-agent-ref), which is
// irrelevant to whether a role gets a key — provision reads roles only and
// records the flip's pointer.
func TestGatewayProvisionIsNotBlockedByAKillSwitchFlip(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	ctl := applied(t, root)
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	flipPointer := readPointer(t, ctl)
	srv, _ := adminMock(t, 0, "")
	t.Chdir(t.TempDir())
	out.Reset()
	if code := cmdGateway(provisionArgs(ctl, srv.URL), &out); code != 0 {
		t.Fatalf("provision after a flip: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); err != nil {
		t.Fatalf("key: %v", err)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "success" || e.ConfigHash != flipPointer {
		t.Fatalf("want success with the flip's pointer %s: %+v", flipPointer, e)
	}
}

// TestGatewayProvisionMintsFromTheUnverifiedRolesRead pins the boundary:
// provision reads through the lenient authorization read, which is not
// verified against the pointer, so a snapshot edited in place still mints —
// while a run on the same root is refused with the mismatch text. The two
// outcomes side by side are the boundary; a later change to it is
// deliberate.
func TestGatewayProvisionMintsFromTheUnverifiedRolesRead(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	ctl := applied(t, root)
	pointer := readPointer(t, ctl)
	coder := filepath.Join(config.SnapshotDir(installedStore(ctl), pointer), "agents", "coder.yaml")
	data, err := os.ReadFile(coder)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coder, append(data, []byte("# edited in place\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, _ := adminMock(t, 0, "")
	t.Chdir(t.TempDir())
	var out bytes.Buffer
	if code := cmdGateway(provisionArgs(ctl, srv.URL), &out); code != 0 {
		t.Fatalf("provision must mint from the lenient read: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); err != nil {
		t.Fatalf("key: %v", err)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "success" || e.ConfigHash != pointer {
		t.Fatalf("%+v", e)
	}
	if code, runOut := runFixBug(t, root, ctl); code != 1 || !strings.Contains(runOut, "snapshot hashes as") {
		t.Fatalf("the execution read must refuse the same root: %d\n%s", code, runOut)
	}
}

// TestGatewayProvisionBadTokenRecordsRefusal: a token that fails
// verification is a recorded refusal with the fixed reason — never the OIDC
// error text — and no API call.
func TestGatewayProvisionBadTokenRecordsRefusal(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	ctl := applied(t, budgetedSample(t))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := cmdTestOIDCServer(t, key)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := cmdMintToken(t, otherKey, map[string]any{"iss": issuer.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	t.Setenv("AGENTHOF_OIDC_ISSUER", issuer.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	srv, generated := adminMock(t, 0, "")
	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--control-log", ctl, "--token", bad, "--admin-base", srv.URL}, &out)
	if code != 1 || !strings.Contains(out.String(), "gateway provision: token authentication failed:") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	e := lastControlEvent(t, ctl)
	if e.Action != "provision" || e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeTokenVerificationFailed || e.Reason.Message != "token verification failed" || e.ConfigHash != "" {
		t.Fatalf("%+v", e)
	}
	if generated.Load() != 0 {
		t.Fatal("a refusal must not touch the admin API")
	}
}

// TestGatewayProvisionDamagedLedgerPrintsHintWithoutConfig: a torn ledger is
// unwritable, so nothing is recorded, nothing is minted, and the repair hint
// names no --config — provision no longer has one.
func TestGatewayProvisionDamagedLedgerPrintsHintWithoutConfig(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	const torn = `{"v":"control/1","seq":1,"prev":""`
	if err := os.WriteFile(ctl, []byte(torn), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, generated := adminMock(t, 0, "")
	var out bytes.Buffer
	code := cmdGateway(provisionArgs(ctl, srv.URL), &out)
	if code != 1 || out.String() != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl+"\n" {
		t.Fatalf("exit %d out %q", code, out.String())
	}
	if after, _ := os.ReadFile(ctl); string(after) != torn {
		t.Fatalf("a damaged ledger must not be written to:\n%s", after)
	}
	if generated.Load() != 0 {
		t.Fatal("nothing may be minted")
	}
}

// TestControlAdjacentCommandsBusyWhenAnotherProcessHoldsTheLedger waits the
// real lockTimeout once: the parent blanks the env (t.Setenv is forbidden in
// a parallel subtest), a helper process holds the ledger flock, and each
// command prints its busy line, exits 1 and records nothing — contention on
// a healthy ledger is busy, never the repair hint.
func TestControlAdjacentCommandsBusyWhenAnotherProcessHoldsTheLedger(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	cases := []struct {
		name   string
		args   func(t *testing.T, ctl string) []string // takes the SUBTEST's t: a parallel subtest must not use the parent's
		prefix string
	}{
		{"gateway provision", func(_ *testing.T, ctl string) []string { return provisionArgs(ctl, "http://127.0.0.1:1") }, "gateway provision"},
		{"runs prune", func(t *testing.T, ctl string) []string {
			return pruneArgs(ctl, "--older-than", "180d", "--log-dir", t.TempDir())
		}, "runs prune"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctl := applied(t, writeSample(t))
			before := len(controlEvents(t, ctl))
			holdLock(t, "ledger", ctl, 9000)
			var out bytes.Buffer
			var code int
			switch c.prefix {
			case "gateway provision":
				code = cmdGateway(c.args(t, ctl), &out)
			default:
				code = cmdRuns(c.args(t, ctl), &out)
			}
			if code != 1 || out.String() != c.prefix+": "+msgLockBusy+"\n" {
				t.Fatalf("code %d out %q", code, out.String())
			}
			if len(controlEvents(t, ctl)) != before {
				t.Fatal("busy must record nothing")
			}
		})
	}
}

// --- OIDC wiring, ledgered validation refusals, and mux dispatch ---

// cmdTestOIDCServer and cmdMintToken delegate to the exported oidctest
// package — one hermetic issuer for every test suite. The names stay so
// the call sites read as before.
func cmdTestOIDCServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	return oidctest.NewServer(t, key)
}

func cmdMintToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	return oidctest.MintToken(t, key, claims)
}

func TestRunTokenRequiresIssuerEnv(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "x", "--token", "some-raw-jwt-value",
		"--config", root, "--control-log", ctl, "--log-dir", t.TempDir()}, &out, io.Discard)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "AGENTHOF_OIDC_ISSUER") {
		t.Fatalf("error must name AGENTHOF_OIDC_ISSUER: %s", out.String())
	}
	if strings.Contains(out.String(), "some-raw-jwt-value") {
		t.Fatalf("error must not echo the raw token: %s", out.String())
	}
}

func TestRunStaticRBAC(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "") // a token exported in the ambient shell must not divert this static-path test onto OIDC
	root := writeSample(t)
	rolePath := filepath.Join(root, "roles", "se.yaml")
	if err := os.WriteFile(rolePath, []byte("name: software-engineer\nworkflows: [fix-bug]\nallowed_groups: [finance]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	ctl := applied(t, root)

	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com", "--groups", "finance",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run with allowed group: %d\n%s", code, out.String())
	}

	out.Reset()
	code = cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com", "--groups", "engineering",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("expected refusal for wrong group: code=%d out=%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out must contain run id: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("expected single run_refused event, got %+v", events)
	}
}

// TestRunValidationFailureIsLedgered: an installed configuration that cannot
// be used — here the pointer names a snapshot directory that is gone — is a
// recorded refusal "configuration invalid: …" that names the snapshot, with
// no "run apply first" hint: a damaged store must never invite a bootstrap.
func TestRunValidationFailureIsLedgered(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	hash := readPointer(t, ctl)
	if err := os.RemoveAll(config.SnapshotDir(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "x", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "installed config "+hash+":") {
		t.Fatalf("the error must name the snapshot: %s", out.String())
	}
	if strings.Contains(out.String(), "agenthof apply --config") {
		t.Fatalf("a damaged store must not print the bootstrap hint: %s", out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused: configuration invalid`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out must contain run id and refusal message: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("expected single run_refused event, got %+v", events)
	}
	if !strings.HasPrefix(events[0].Reason, "configuration invalid: installed config "+hash+":") {
		t.Fatalf("reason must name the snapshot: %s", events[0].Reason)
	}
}

// TestRunRefusesWhenNothingInstalled: branch 1 — a recorded refusal with the
// fixed reason, and a hint naming --config's value verbatim (run never reads
// that directory; it is the thing to apply) and --control-log's.
func TestRunRefusesWhenNothingInstalled(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	cfgDir := "./does-not-exist"
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", cfgDir, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out.String())
	}
	hint := "run: no configuration installed under " + installedStore(ctl) + "; run: agenthof apply --config " + cfgDir + " --control-log " + ctl + "\n"
	if !strings.Contains(out.String(), hint) {
		t.Fatalf("missing hint %q in:\n%s", hint, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused: no configuration installed`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" || events[0].Reason != "no configuration installed" || events[0].ConfigHash != "" {
		t.Fatalf("ledger = %+v", events)
	}
}

// TestRunMalformedPointerIsConfigurationInvalidNotBootstrap: errors are
// checked before the installed flag, so a malformed pointer is branch 2.
func TestRunMalformedPointerIsConfigurationInvalidNotBootstrap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	if err := os.WriteFile(filepath.Join(installedStore(ctl), config.InstalledPointer), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--control-log", ctl, "--log-dir", t.TempDir()}, &out, io.Discard)
	if code != 1 || !strings.Contains(out.String(), "malformed pointer") || !strings.Contains(out.String(), "refused: configuration invalid") {
		t.Fatalf("code=%d out=%s", code, out.String())
	}
	if strings.Contains(out.String(), "no configuration installed") {
		t.Fatalf("a malformed pointer must never read as nothing installed: %s", out.String())
	}
}

// TestRunExecutesTheInstalledSnapshotNotTheDirectory: after apply, breaking
// the directory changes nothing about the next run, and the run stamps the
// pointer's hash.
func TestRunExecutesTheInstalledSnapshotNotTheDirectory(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	want := readPointer(t, ctl)
	if err := os.WriteFile(filepath.Join(root, "gateway.yaml"), []byte("models: {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--control-log", ctl, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Type != "workflow_started" || events[0].ConfigHash != want {
		t.Fatalf("workflow_started must carry the pointer's hash %s: %+v", want, events[0])
	}
}

func TestRunOIDCHappyPathEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	ctl := applied(t, root)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	token := cmdMintToken(t, key, map[string]any{
		"iss":   srv.URL,
		"aud":   "agenthof",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u-123",
		"email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof") // pin: the minted token's aud is fixed to "agenthof"

	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--token", token,
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), token) {
		t.Fatalf("output must not echo the raw token: %s", out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	want := fmt.Sprintf("invoked by dana@example.com (oidc, issuer %s)", srv.URL)
	if !strings.Contains(out.String(), want) {
		t.Fatalf("audit missing %q:\n%s", want, out.String())
	}
}

// TestRunBadTokenIsRejectedWithoutEcho is the CLI-layer token-non-echo
// regression test: a real OIDC issuer is configured (so the failure is a
// genuine signature-verification failure, not a missing-issuer short
// circuit), the --token is cryptographically invalid, and the assertion
// covers both a non-zero exit with a clear error AND that the raw token
// string never appears anywhere in the combined CLI output.
func TestRunBadTokenIsRejectedWithoutEcho(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	ctl := applied(t, root)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	// A well-formed JWT (valid header/claims, correct issuer/audience) but
	// signed with a different key than the one the issuer's JWKS publishes —
	// so verification fails on the signature, not on shape or discovery.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	badToken := cmdMintToken(t, otherKey, map[string]any{
		"iss":   srv.URL,
		"aud":   "agenthof",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u-123",
		"email": "dana@example.com",
	})

	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--token", badToken,
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code == 0 {
		t.Fatalf("expected non-zero exit for a bad token, got 0:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "token authentication failed") {
		t.Fatalf("error must mention authentication failure: %s", out.String())
	}
	if strings.Contains(out.String(), badToken) {
		t.Fatalf("output must not echo the raw token: %s", out.String())
	}

	// The rejection must still be ledgered, like any other refusal, but
	// under a distinct method ("oidc-rejected") that can never be confused
	// with a genuinely verified "oidc" invoker, and with a fixed reason
	// string rather than the raw go-oidc error text (which can echo claim
	// values).
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused: token verification failed`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("expected a ledgered refusal with a run id: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("expected single run_refused event, got %+v", events)
	}
	if events[0].Binding.Invoker.Method != "oidc-rejected" {
		t.Errorf("Method = %q, want %q", events[0].Binding.Invoker.Method, "oidc-rejected")
	}
	if events[0].Reason != "token verification failed" {
		t.Errorf("Reason = %q, want %q", events[0].Reason, "token verification failed")
	}
	if strings.Contains(events[0].Reason, badToken) {
		t.Fatalf("ledgered reason must not echo the raw token: %s", events[0].Reason)
	}
}

func TestRunFrontedAgentEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "") // a token exported in the ambient shell must not divert this static-path test onto OIDC
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"front result"}`))
	}))
	defer stub.Close()

	root := t.TempDir()
	files := map[string]string{
		"agents/helper.yaml":    "name: helper\nexecution: fronted\nendpoint: " + stub.URL + "\ninstruction: help\noutput: result\n",
		"workflows/single.yaml": "name: single\nsteps:\n  - name: step1\n    agent: helper\n",
		"roles/fr.yaml":         "name: fronted-role\nworkflows: [single]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":        "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logs := t.TempDir()
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	if !strings.Contains(out.String(), "invoked by dev@x") {
		t.Fatalf("audit missing invoker: %s", out.String())
	}

	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Type == "step_succeeded" && e.Execution == "fronted" {
			found = true
			// The artifact must be the stub adapter's response, proof this
			// step was handed to the fronted agent.
			if e.Artifact != "front result" {
				t.Fatalf("expected artifact from the fronted stub, got %q", e.Artifact)
			}
		}
	}
	if !found {
		t.Fatalf("expected step_succeeded event with Execution=fronted, got %+v", events)
	}
}

// TestRunStartsListenerForFrontedExecWithoutTools proves a fronted agent
// that declares exec and no tools still gets the per-run listener: the
// stub sees the proxy coordinates, asks the exec door to run a command
// through the declared runtime (an in-process refexec stand-in), and the
// ledger records that exec first-hand. Without the widened gate the stub is
// dispatched with no coordinates and no exec event is written.
func TestRunStartsListenerForFrontedExecWithoutTools(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "")
	execSock := refexecStub(t)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyURL := r.Header.Get("X-Agenthof-Proxy-URL")
		token := r.Header.Get("X-Agenthof-Run-Token")
		if proxyURL != "" && token != "" {
			if err := stubCallExecRun(proxyURL, token, "go test"); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"front result"}`))
	}))
	defer stub.Close()

	root := t.TempDir()
	files := map[string]string{
		"agents/helper.yaml": "name: helper\nexecution: fronted\nendpoint: " + stub.URL +
			"\ninstruction: help\noutput: result\nexec:\n  runtime: refexec\n  url: unix://" + execSock +
			"\n  timeout: 30s\n  allow:\n    - exe: go\n      args_prefix: [test]\n",
		"workflows/single.yaml": "name: single\nsteps:\n  - name: step1\n    agent: helper\n",
		"roles/fr.yaml":         "name: fronted-role\nworkflows: [single]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":        "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logs := t.TempDir()
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	var execEvent *engine.Event
	for i := range events {
		if events[i].Type == "exec" {
			execEvent = &events[i]
		}
	}
	if execEvent == nil || execEvent.Status != "succeeded" || execEvent.Mode != "runtime" || execEvent.RuntimeAttestation == nil {
		t.Fatalf("expected a first-hand exec event, got %+v", events)
	}
}

// TestRunWiresToolProxyForFrontedToolAgent proves `run` actually constructs
// and wires a real rungateway.Gateway into engine.Options when the config
// declares a gateway tool resource that a fronted agent references: the
// resource's credential env var is deliberately left unset, so the wired
// proxy's Start call fails fast at the broker (no network involved), and
// that failure — recorded with the fixed reason "tool proxy start failed"
// by the engine's own bracketing code (no error text, so no resource URL
// or credential reaches the ledger) — can only appear if Options.NewGateway
// was actually set. Before
// the proxy is wired, this same config runs the fronted step directly
// through the adapter (bypassing the tool proxy entirely) and succeeds
// instead — the regression this test guards against.
func TestRunWiresToolProxyForFrontedToolAgent(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "")
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"front result"}`))
	}))
	defer stub.Close()

	root := t.TempDir()
	files := map[string]string{
		"agents/helper.yaml":    "name: helper\nexecution: fronted\nendpoint: " + stub.URL + "\ninstruction: help\noutput: result\ntools:\n  - resource: github\n    tools: [\"*\"]\n    mode: read-write\n",
		"workflows/single.yaml": "name: single\nsteps:\n  - name: step1\n    agent: helper\n",
		"roles/fr.yaml":         "name: fronted-role\nworkflows: [single]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":        "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
		"gateway.yaml": "tools:\n  github:\n    kind: mcp\n    url: https://mcp.example.test/\n" +
			"    credential_source: static_env\n    token_env: AGENTHOF_TEST_UNSET_TOOL_TOKEN\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately left unset (test-scoped, not process-global) so the wired
	// proxy's broker resolve fails fast, without any network call.
	t.Setenv("AGENTHOF_TEST_UNSET_TOOL_TOKEN", "")

	logs := t.TempDir()
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", logs, "--tool-proxy-addr", "127.0.0.1:0"}, &out, io.Discard)
	if code != 1 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "finished: failed") {
		t.Fatalf("expected the step to fail via the tool proxy, got: %s", out.String())
	}

	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: failed`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	var stepFailed *engine.Event
	for i := range events {
		if events[i].Type == "step_failed" {
			stepFailed = &events[i]
		}
	}
	if stepFailed == nil || stepFailed.Reason != "tool proxy start failed" {
		t.Fatalf("expected a step_failed event naming the tool proxy, got %+v", events)
	}
}

// TestNewBrokerRoutesClientCredentialsGrant proves the process broker routes a
// client_credentials grant to the ClientCredentials sub-broker, not a bare
// StaticEnv. Proof is the routed sub-broker's own distinctive failure: with the
// client-id env unset, ClientCredentials fails with "client id env ... is not
// set"; a bare StaticEnv given the same grant would instead reject it with
// "direct-bearer grant only". The error is inspected in memory here and never
// logged or written to the ledger, so this replaces the old end-to-end
// discriminator that relied on the failure reason the tool-proxy path no longer
// records.
func TestNewBrokerRoutesClientCredentialsGrant(t *testing.T) {
	t.Setenv("AGENTHOF_TEST_UNSET_CLIENT_ID", "")
	t.Setenv("AGENTHOF_TEST_UNSET_CLIENT_SECRET", "")
	ref := broker.CredentialRef{
		ResourceID:      "github",
		Source:          "static_env",
		Grant:           "client_credentials",
		ClientAuth:      "client_secret_basic",
		Issuer:          "https://issuer.example.test/",
		TokenURL:        "https://token.example.test/",
		ClientIDEnv:     "AGENTHOF_TEST_UNSET_CLIENT_ID",
		ClientSecretEnv: "AGENTHOF_TEST_UNSET_CLIENT_SECRET",
	}
	_, err := newBroker(broker.SubjectTokenTypeAccessToken).Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("resolve must fail with the client-id env unset")
	}
	if !strings.Contains(err.Error(), "client id env") {
		t.Fatalf("client_credentials must route to the ClientCredentials broker, got: %v", err)
	}
	if strings.Contains(err.Error(), "direct-bearer grant only") {
		t.Fatalf("client_credentials was misrouted to a bare StaticEnv broker: %v", err)
	}
}

// TestRunWiresClientCredentialsBrokerForFrontedToolAgent proves `run` wires a
// tool proxy for a fronted agent whose gateway resource declares grant_type:
// client_credentials, and that the step fails via that proxy (fixed reason).
// The client id/secret env vars are deliberately left unset, so the mint fails
// fast without any network call — same no-network shape as
// TestRunWiresToolProxyForFrontedToolAgent, but exercising the
// client_credentials config path end-to-end. Which broker Dispatch routes the
// grant to (ClientCredentials, not a bare StaticEnv) is guarded separately by
// TestNewBrokerRoutesClientCredentialsGrant — the tool-proxy path no longer
// records a broker's error text, so the broker type is not observable here.
func TestRunWiresClientCredentialsBrokerForFrontedToolAgent(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "")
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"front result"}`))
	}))
	defer stub.Close()

	root := t.TempDir()
	files := map[string]string{
		"agents/helper.yaml":    "name: helper\nexecution: fronted\nendpoint: " + stub.URL + "\ninstruction: help\noutput: result\ntools:\n  - resource: github\n    tools: [\"*\"]\n    mode: read-write\n",
		"workflows/single.yaml": "name: single\nsteps:\n  - name: step1\n    agent: helper\n",
		"roles/fr.yaml":         "name: fronted-role\nworkflows: [single]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":        "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
		"gateway.yaml": "tools:\n  github:\n    kind: mcp\n    url: https://mcp.example.test/\n" +
			"    credential_source: static_env\n    grant_type: client_credentials\n" +
			"    client_auth: client_secret_basic\n    issuer: https://issuer.example.test/\n" +
			"    token_endpoint: https://token.example.test/\n" +
			"    client_id_env: AGENTHOF_TEST_UNSET_CLIENT_ID\n" +
			"    client_secret_env: AGENTHOF_TEST_UNSET_CLIENT_SECRET\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately left unset (test-scoped, not process-global) so the mint
	// fails fast inside ClientCredentials, without any network call.
	t.Setenv("AGENTHOF_TEST_UNSET_CLIENT_ID", "")
	t.Setenv("AGENTHOF_TEST_UNSET_CLIENT_SECRET", "")

	logs := t.TempDir()
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", logs, "--tool-proxy-addr", "127.0.0.1:0"}, &out, io.Discard)
	if code != 1 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "finished: failed") {
		t.Fatalf("expected the step to fail via the tool proxy, got: %s", out.String())
	}

	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: failed`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	var stepFailed *engine.Event
	for i := range events {
		if events[i].Type == "step_failed" {
			stepFailed = &events[i]
		}
	}
	if stepFailed == nil || stepFailed.Reason != "tool proxy start failed" {
		t.Fatalf("expected a step_failed event naming the tool proxy, got %+v", events)
	}
	// The ClientCredentials-vs-StaticEnv routing guard lives in
	// TestNewBrokerRoutesClientCredentialsGrant: the tool-proxy path now records
	// only a fixed reason (no broker error text, so no token-endpoint URL or
	// credential reaches the ledger), so the broker type is no longer observable
	// from the run's events.
}

// TestRunToolProxyAddrFlagParsesButIsUnused confirms --tool-proxy-addr is
// accepted (forward-compat) on an ordinary run that declares no gateway
// tools at all, and that such a run is unaffected: the flag does not change
// the listener address, and the stub's own artifact still comes back.
func TestRunToolProxyAddrFlagParsesButIsUnused(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "")
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"front result"}`))
	}))
	defer stub.Close()

	root := t.TempDir()
	files := map[string]string{
		"agents/helper.yaml":    "name: helper\nexecution: fronted\nendpoint: " + stub.URL + "\ninstruction: help\noutput: result\n",
		"workflows/single.yaml": "name: single\nsteps:\n  - name: step1\n    agent: helper\n",
		"roles/fr.yaml":         "name: fronted-role\nworkflows: [single]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":        "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logs := t.TempDir()
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--control-log", ctl, "--log-dir", logs, "--tool-proxy-addr", "127.0.0.1:9999"}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "finished: succeeded") {
		t.Fatalf("run with no gateway tools must be unaffected by the flag: %s", out.String())
	}
}

// writeOBOSample writes a one-step config whose planner grants a
// token_exchange resource at upstreamURL, exchanged at exchangeURL. The
// agent stub is echoCompatHandler, whose "tool:<name>" input calls that
// tool through the door.
func writeOBOSample(t *testing.T, exchangeURL, upstreamURL string) string {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(echoCompatHandler))
	t.Cleanup(stub.Close)
	root := t.TempDir()
	files := map[string]string{
		"agents/planner.yaml": "name: planner\nmodel: fast\ninstruction: plan\noutput: plan\nendpoint: " + stub.URL + "\ntools:\n  - resource: crm\n    tools: [\"*\"]\n    mode: read-write\n",
		"workflows/crm.yaml":  "name: crm\nsteps:\n  - name: plan\n    agent: planner\n",
		"roles/se.yaml":       "name: software-engineer\nworkflows: [crm]\nallowed_groups: [\"*\"]\n",
		"roles/ops.yaml":      "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
		"gateway.yaml": "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\n" +
			"tools:\n  crm:\n    kind: mcp\n    url: " + upstreamURL + "\n    credential_source: static_env\n    grant_type: token_exchange\n" +
			"    client_auth: client_secret_basic\n    token_endpoint: " + exchangeURL + "\n    audience: https://crm.example\n" +
			"    client_id_env: OBO_TEST_CLIENT_ID\n    client_secret_env: OBO_TEST_CLIENT_SECRET\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestRunOBOResourceRefusesAssertedInvoker: an OBO workflow with a dev --as
// invoker is a proper refused run — one run_refused event with the fixed
// reason — before the engine, the gateway, or the exchange endpoint is ever
// touched.
func TestRunOBOResourceRefusesAssertedInvoker(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "")
	var exchanges int32
	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&exchanges, 1)
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer exchange.Close()
	root := writeOBOSample(t, exchange.URL, "http://127.0.0.1:9/mcp")
	logs := t.TempDir()
	ctl := applied(t, root)
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "crm", "--input", "tool:whoami", "--as", "dana@example.com", "--groups", "eng",
		"--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused: obo requires a verified invoker token`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out must carry the run id and the fixed OBO reason: %s", out.String())
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" || events[0].Reason != oboRefusalReason {
		t.Fatalf("expected a single run_refused with the fixed reason, got %+v", events)
	}
	if atomic.LoadInt32(&exchanges) != 0 {
		t.Fatal("the exchange endpoint must not be contacted for a refused run")
	}
}

// TestRunOBOEndToEndInProcess: a verified --token run exchanges the token,
// the upstream sees the EXCHANGED token (never the subject token), the
// ledger records auth_mode token_exchange, and neither token appears in the
// run log or the CLI output.
func TestRunOBOEndToEndInProcess(t *testing.T) {
	t.Chdir(t.TempDir())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	idp := cmdTestOIDCServer(t, key)
	subject := cmdMintToken(t, key, map[string]any{
		"iss": idp.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(),
		"sub": "u-123", "email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", idp.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	t.Setenv("AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE", "urn:ietf:params:oauth:token-type:id_token")
	t.Setenv("OBO_TEST_CLIENT_ID", "agenthof-broker")
	t.Setenv("OBO_TEST_CLIENT_SECRET", "client-secret")

	const exchanged = "zq9exchangedtokenBBBB2222"
	var mu sync.Mutex
	var sawSubject, sawType string
	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		sawSubject, sawType = r.Form.Get("subject_token"), r.Form.Get("subject_token_type")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + exchanged + `","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer exchange.Close()

	var lastAuth string
	upstream := mcp.NewServer(&mcp.Implementation{Name: "crm-stub", Version: "v0.1.0"}, nil)
	mcp.AddTool(upstream, &mcp.Tool{Name: "whoami", Description: "who the bearer is"},
		func(_ context.Context, req *mcp.CallToolRequest, _ struct {
			Text string `json:"text,omitempty"`
		}) (*mcp.CallToolResult, any, error) {
			var auth string
			if req.Extra != nil && req.Extra.Header != nil {
				auth = req.Extra.Header.Get("Authorization")
			}
			mu.Lock()
			lastAuth = auth
			mu.Unlock()
			if auth != "Bearer "+exchanged {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "unauthorized"}}}, nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "acting as: u-123"}}}, nil, nil
		})
	up := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, nil))
	defer up.Close()

	cfg := writeOBOSample(t, exchange.URL, up.URL)
	logs := t.TempDir()
	ctl := applied(t, cfg)
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "crm", "--input", "tool:whoami", "--token", subject,
		"--config", cfg, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	mu.Lock()
	gotAuth, gotSubject, gotType := lastAuth, sawSubject, sawType
	mu.Unlock()
	if gotAuth != "Bearer "+exchanged {
		t.Fatalf("upstream saw %q, want the exchanged token", gotAuth)
	}
	if gotSubject != subject || gotType != "urn:ietf:params:oauth:token-type:id_token" {
		t.Fatalf("exchange must carry the verified token as subject_token with the deployment's subject_token_type (type=%q)", gotType)
	}
	events, _, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Type == "tool_call" {
			found = true
			if e.AuthMode != "token_exchange" || e.Status != "succeeded" {
				t.Fatalf("tool_call = %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("no tool_call event")
	}
	raw, err := os.ReadFile(filepath.Join(logs, m[1]+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{subject, exchanged} {
		if strings.Contains(string(raw), secret) || strings.Contains(out.String(), secret) {
			t.Fatalf("a token reached the ledger or the CLI output (prefix %s)", secret[:8])
		}
	}
}

// stubCallSpawn drives the spawn door from the demo stub: spec is
// <role>/<workflow>:<input>. The artifact line is the door's answer —
// status, child run id, and the child's preview (or the refusal reason) —
// so a test can read the outcome off the parent's step artifact. A refusal
// (403) is an answer the line carries, not an error: the ledger proves it.
func stubCallSpawn(proxyURL, token, spec string) (string, error) {
	target, input, ok := strings.Cut(spec, ":")
	if !ok {
		return "", fmt.Errorf("spawn spec %q needs <role>/<workflow>:<input>", spec)
	}
	role, workflow, ok := strings.Cut(target, "/")
	if !ok {
		return "", fmt.Errorf("spawn spec %q needs <role>/<workflow>:<input>", spec)
	}
	body, err := json.Marshal(map[string]string{"role": role, "workflow": workflow, "input": input})
	if err != nil {
		return "", err
	}
	client, base := doorClient(proxyURL)
	req, err := http.NewRequest(http.MethodPost, base+"/spawn", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		return "", fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	var out struct {
		Status        string `json:"status"`
		ChildRunID    string `json:"child_run_id"`
		OutputPreview string `json:"output_preview"`
		Reason        string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	id := out.ChildRunID
	if id == "" {
		id = "-"
	}
	detail := out.OutputPreview
	if out.Status != "succeeded" {
		detail = out.Reason
	}
	return strings.TrimSpace(fmt.Sprintf("spawn %s %s %s", out.Status, id, detail)), nil
}
