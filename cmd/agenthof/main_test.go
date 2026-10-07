package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/agenthof/agenthof/internal/engine"
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
		"roles/ops.yaml":         "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair]\n",
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

func TestApplyOKAndFailure(t *testing.T) {
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
	// break it: disable coder, apply must fail naming fix-bug
	out.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %s", out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatal("apply must fail with a disabled dependency")
	}
	if !strings.Contains(out.String(), "fix-bug") || !strings.Contains(out.String(), "disabled") {
		t.Fatalf("kill-switch error must name the workflow: %s", out.String())
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
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
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
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
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
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 {
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
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "do it FAIL:coder", "--as", "dev@x", "--config", root, "--log-dir", logs}, &out, io.Discard)
	_ = code // coder always fails on this input; bounces exhaust; run fails honestly
	if !strings.Contains(out.String(), "finished: failed") {
		t.Fatalf("out: %s", out.String())
	}
}

func TestRunRefusedUnknownRole(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	var out bytes.Buffer
	code := cmdRun([]string{"ghost", "fix-bug", "--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", t.TempDir()}, &out, io.Discard)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("code=%d out=%s", code, out.String())
	}
}

func TestRunsPruneDeletesOldRuns(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "r-old.jsonl")
	newPath := filepath.Join(dir, "r-new.jsonl")
	if err := os.WriteFile(oldPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(oldPath, old, old); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", dir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old run should be gone, err=%v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("new run should remain: %v", err)
	}
}

func TestRunsPruneAlsoPrunesArtifactStore(t *testing.T) {
	logDir := t.TempDir()
	artifactDir := t.TempDir()

	oldArtifact := filepath.Join(artifactDir, "deadbeef")
	newArtifact := filepath.Join(artifactDir, "cafef00d")
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
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", logDir, "--artifact-dir", artifactDir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 0 run(s) and 1 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(oldArtifact); !os.IsNotExist(err) {
		t.Fatalf("old artifact should be gone, err=%v", err)
	}
	if _, err := os.Stat(newArtifact); err != nil {
		t.Fatalf("new artifact should remain: %v", err)
	}
}

func TestRunsPruneMissingArtifactDirIsNotAnError(t *testing.T) {
	logDir := t.TempDir()
	artifactDir := filepath.Join(t.TempDir(), "does-not-exist")

	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", logDir, "--artifact-dir", artifactDir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 0 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(artifactDir); !os.IsNotExist(err) {
		t.Fatalf("a missing artifact-dir must not be created just to find nothing to prune: %v", err)
	}
}

func TestRunsPruneGarbageDuration(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "abc", "--log-dir", dir}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2 for garbage duration, got %d\n%s", code, out.String())
	}
}

func TestRunsPruneMissingLogDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", dir}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for missing log dir, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 0 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
}

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
			if code != 2 {
				t.Fatalf("expected exit 2 for %q, got %d\n%s", olderThan, code, out.String())
			}
			if !strings.Contains(out.String(), "--older-than must be a positive duration") {
				t.Fatalf("out for %q: %s", olderThan, out.String())
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("run file should be untouched for %q: %v", olderThan, err)
			}
		})
	}
}

func TestRunsPruneLogDirIsRegularFile(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", notADir}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 when --log-dir is a regular file, got %d\n%s", code, out.String())
	}
}

// TestRunsPruneSparesControlLogAndFragments proves the default layout is
// safe: the control ledger lives at .agenthof/control.jsonl, a sibling of
// (not a member of) the default --log-dir .agenthof/runs, so an aged run
// log under --log-dir is pruned while the ledger and its .torn-* repair
// fragment — both outside --log-dir entirely — are untouched (spec §3.1).
func TestRunsPruneSparesControlLogAndFragments(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, ".agenthof")
	runsDir := filepath.Join(agentDir, "runs")
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	oldRun := filepath.Join(runsDir, "r-old.jsonl")
	controlLog := filepath.Join(agentDir, "control.jsonl")
	fragment := controlLog + ".torn-1"
	for _, p := range []string{oldRun, controlLog, fragment} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, p := range []string{oldRun, controlLog, fragment} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "24h", "--log-dir", runsDir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(oldRun); !os.IsNotExist(err) {
		t.Fatalf("old run log should be pruned, err=%v", err)
	}
	if _, err := os.Stat(controlLog); err != nil {
		t.Fatalf("control log must survive prune: %v", err)
	}
	if _, err := os.Stat(fragment); err != nil {
		t.Fatalf("torn fragment must survive prune: %v", err)
	}
}

// TestRunsPruneNeverDeletesControlLogEvenIfLogDirPointsAtItsDir covers the
// misconfiguration case: an operator points --log-dir directly at the
// control log's own directory (instead of the default .agenthof/runs).
// pruneRuns's *.jsonl glob would otherwise match control.jsonl itself;
// the ledger and its repair fragment must still survive (spec §3.1).
func TestRunsPruneNeverDeletesControlLogEvenIfLogDirPointsAtItsDir(t *testing.T) {
	agentDir := t.TempDir()
	oldRun := filepath.Join(agentDir, "r-old.jsonl")
	controlLog := filepath.Join(agentDir, "control.jsonl")
	fragment := controlLog + ".torn-1"
	for _, p := range []string{oldRun, controlLog, fragment} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, p := range []string{oldRun, controlLog, fragment} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	// A misconfigured --log-dir that resolves to the same directory as
	// control.jsonl must still prune plain aged run logs (proving the
	// guard is discriminating, not just "prune did nothing")...
	code := cmdRuns([]string{"prune", "--older-than", "24h", "--log-dir", agentDir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(oldRun); !os.IsNotExist(err) {
		t.Fatalf("old run log should still be pruned, err=%v", err)
	}
	// ...while the control ledger and its repair fragment survive.
	if _, err := os.Stat(controlLog); err != nil {
		t.Fatalf("control log must survive prune even when --log-dir points at its directory: %v", err)
	}
	if _, err := os.Stat(fragment); err != nil {
		t.Fatalf("torn fragment must survive prune: %v", err)
	}
}

func TestGatewayProvisionMissingMasterKey(t *testing.T) {
	t.Setenv("LITELLM_MASTER_KEY", "")
	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--config", "./config"}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2 with LITELLM_MASTER_KEY unset, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "LITELLM_MASTER_KEY") {
		t.Fatalf("error must name LITELLM_MASTER_KEY: %s", out.String())
	}
}

func TestGatewayProvisionEndToEnd(t *testing.T) {
	root := writeSample(t)
	// writeSample's role has no budget; add one so the provisioner acts.
	rolePath := filepath.Join(root, "roles", "se.yaml")
	if err := os.WriteFile(rolePath, []byte("name: software-engineer\nworkflows: [fix-bug]\nbudget_usd_month: 50\nallowed_groups: [\"*\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/key/generate" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key":"sk-test"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--config", root, "--admin-base", srv.URL}, &out)
	if code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "provisioned key for role software-engineer (budget $50)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); err != nil {
		t.Fatalf("key file not written under ./.agenthof/keys/: %v", err)
	}
}

// --- OIDC wiring, ledgered validation refusals, and mux dispatch ---

// cmdTestOIDCServer spins up an httptest server serving OIDC discovery and
// JWKS documents backed by the given RSA key. Mirrors the recipe in
// internal/identity/oidc_test.go (kept separate so cmd/agenthof does not
// need to export test helpers from internal/identity).
func cmdTestOIDCServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/keys",
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test",
					"alg": "RS256",
					"use": "sig",
					"n":   n,
					"e":   "AQAB",
				},
			},
		})
	})

	return srv
}

// cmdMintToken hand-builds an RS256-signed JWT from the given claims.
func cmdMintToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "RS256", "kid": "test", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestRunTokenRequiresIssuerEnv(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "x", "--token", "some-raw-jwt-value",
		"--config", root, "--log-dir", t.TempDir()}, &out, io.Discard)
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

	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com", "--groups", "finance",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run with allowed group: %d\n%s", code, out.String())
	}

	out.Reset()
	code = cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com", "--groups", "engineering",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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

func TestRunValidationFailureIsLedgered(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "") // a token exported in the ambient shell must not divert this static-path test onto OIDC
	root := writeSample(t)
	var discard bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--groups", "platform-eng"}, &discard); code != 0 {
		t.Fatalf("disable: %d\n%s", code, discard.String())
	}
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out.String())
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
	if !strings.HasPrefix(events[0].Reason, "configuration invalid:") {
		t.Fatalf("reason must start with %q: %s", "configuration invalid:", events[0].Reason)
	}
}

func TestRunOIDCHappyPathEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)

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
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--log-dir", logs, "--tool-proxy-addr", "127.0.0.1:0"}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--log-dir", logs, "--tool-proxy-addr", "127.0.0.1:0"}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--log-dir", logs, "--tool-proxy-addr", "127.0.0.1:9999"}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "crm", "--input", "tool:whoami", "--as", "dana@example.com", "--groups", "eng",
		"--config", root, "--log-dir", logs}, &out, io.Discard)
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
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "crm", "--input", "tool:whoami", "--token", subject,
		"--config", cfg, "--log-dir", logs}, &out, io.Discard)
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

// TestGatewayProvisionSkipsWorkflowLessRole: a control-only role runs nothing,
// so provision mints it no provider key — a key with budget $0 would be a
// credential nothing consumes. The mock counts key generations.
func TestGatewayProvisionSkipsWorkflowLessRole(t *testing.T) {
	root := writeSample(t)
	if err := os.WriteFile(filepath.Join(root, "roles", "se.yaml"), []byte("name: software-engineer\nworkflows: [fix-bug]\nbudget_usd_month: 50\nallowed_groups: [\"*\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte("name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	generated := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/key/generate" {
			generated++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key":"sk-test"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	if code := cmdGateway([]string{"provision", "--config", root, "--admin-base", srv.URL}, &out); code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "role platform-admin: owns no workflows; no key provisioned") {
		t.Fatalf("missing skip line: %s", out.String())
	}
	if generated != 1 {
		t.Fatalf("key generations = %d, want 1 (software-engineer only)", generated)
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "platform-admin.key")); !os.IsNotExist(err) {
		t.Fatalf("a control-only role must get no key file; stat err = %v", err)
	}
}
