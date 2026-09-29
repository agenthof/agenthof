package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testConfig(t *testing.T, mut func(*bridgeConfig)) bridgeConfig {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := bridgeConfig{
		Socket:          "/unused/in-these-tests.sock",
		Command:         []string{exe, childFlag, "TEST_CRED"},
		CredentialEnv:   "TEST_CRED",
		Materialization: matEnvAtSpawn,
		EnvPassthrough:  []string{},
		EgressAllow:     []string{},
		MaxSessions:     4,
		IdleTimeout:     time.Minute,
		MaxLifetime:     time.Minute,
	}
	if mut != nil {
		mut(&cfg)
	}
	return cfg
}

// startBridge serves the bridge over loopback TCP (httptest) — the transport
// under test is the MCP session model, not the socket; listen_test.go covers
// the UDS listener. The bridge's own environment is fixed so pass-through is testable
// and so LEAK proves non-allowlisted variables never reach a child.
func startBridge(t *testing.T, cfg bridgeConfig) (*bridge, string) {
	t.Helper()
	b := newBridge(cfg, nil)
	b.environ = func() []string { return []string{"PATH=/refbridge-own-path", "LEAK=must-not-reach-child"} }
	ts := httptest.NewServer(b.handler())
	t.Cleanup(func() { b.close(); ts.Close() })
	return b, ts.URL
}

// bearerRT stands in for the gateway's injectingTransport: it sets the
// current token on every request, and the token can change mid-session.
type bearerRT struct {
	mu    sync.Mutex
	token string
}

func (r *bearerRT) set(tok string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.token = tok
}

func (r *bearerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	tok := r.token
	r.mu.Unlock()
	req = req.Clone(req.Context())
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func connect(t *testing.T, url string, rt *bearerRT) (*mcp.ClientSession, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "gateway-stand-in", Version: "v0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: rt}}, nil)
	if err == nil {
		t.Cleanup(func() { _ = sess.Close() })
	}
	return sess, err
}

func mustConnect(t *testing.T, url string, rt *bearerRT) *mcp.ClientSession {
	t.Helper()
	sess, err := connect(t, url, rt)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return sess
}

func call(t *testing.T, sess *mcp.ClientSession, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool %s: error result %+v", name, res.Content)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func processGone(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	return p.Signal(syscall.Signal(0)) != nil
}

// onlySession returns the bridge's single live session record (test-only
// access to the package-private table).
func onlySession(t *testing.T, b *bridge) *session {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sessions) != 1 {
		t.Fatalf("live sessions = %d, want exactly 1", len(b.sessions))
	}
	for _, s := range b.sessions {
		return s
	}
	return nil
}

func TestChildEnvIsAllowlistPlusCredential(t *testing.T) {
	b := newBridge(testConfig(t, nil), nil)
	b.environ = func() []string { return []string{"PATH=/p", "LEAK=1"} }
	got := b.childEnv("tok")
	if got == nil {
		t.Fatal("childEnv returned nil: exec would inherit the whole environment")
	}
	if len(got) != 1 || got[0] != "TEST_CRED=tok" {
		t.Fatalf("childEnv = %v, want exactly [TEST_CRED=tok]", got)
	}
	b.cfg.EnvPassthrough = []string{"PATH", "ABSENT"}
	got = b.childEnv("tok")
	if len(got) != 2 || got[0] != "PATH=/p" || got[1] != "TEST_CRED=tok" {
		t.Fatalf("childEnv = %v, want [PATH=/p TEST_CRED=tok] (an allowlisted name absent from refbridge's env is skipped)", got)
	}
}

func TestChildSeesOnlyAllowlistPlusCredential(t *testing.T) {
	_, url := startBridge(t, testConfig(t, nil))
	rt := &bearerRT{token: "tok-a"}
	sess := mustConnect(t, url, rt)
	if got := call(t, sess, "environment"); got != "TEST_CRED" {
		t.Fatalf("child environment = %q, want exactly TEST_CRED", got)
	}
	if got := call(t, sess, "credential"); got != fingerprint("tok-a") {
		t.Fatalf("child credential fingerprint = %q, want sha256 of the injected bearer", got)
	}
}

func TestEnvPassthroughForwardsOnlyNamedVars(t *testing.T) {
	_, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.EnvPassthrough = []string{"PATH"} }))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	if got := call(t, sess, "environment"); got != "PATH,TEST_CRED" {
		t.Fatalf("child environment = %q, want PATH,TEST_CRED (LEAK must never appear)", got)
	}
	if got := call(t, sess, "echo"); got != "" { // echo with no text: still forwarded, still answers
		t.Fatalf("echo = %q, want empty", got)
	}
}

func TestOneChildPerSessionAndTeardownOnClose(t *testing.T) {
	b, url := startBridge(t, testConfig(t, nil))
	s1 := mustConnect(t, url, &bearerRT{token: "tok-1"})
	s2 := mustConnect(t, url, &bearerRT{token: "tok-2"})
	pid1, _ := strconv.Atoi(call(t, s1, "pid"))
	pid2, _ := strconv.Atoi(call(t, s2, "pid"))
	if pid1 == pid2 || pid1 == 0 {
		t.Fatalf("two sessions share child pid %d: children must never be pooled", pid1)
	}
	if call(t, s1, "credential") != fingerprint("tok-1") || call(t, s2, "credential") != fingerprint("tok-2") {
		t.Fatal("each session's child must hold that session's credential")
	}
	if b.liveSessions() != 2 || b.spawns.Load() != 2 {
		t.Fatalf("live=%d spawns=%d, want 2/2", b.liveSessions(), b.spawns.Load())
	}
	_ = s1.Close() // the client sends DELETE for the established session
	eventually(t, "session 1 teardown", func() bool { return b.liveSessions() == 1 })
	eventually(t, "child 1 to exit", func() bool { return processGone(pid1) })
	if processGone(pid2) {
		t.Fatal("closing session 1 must not touch session 2's child")
	}
	b.close()
	eventually(t, "child 2 to exit", func() bool { return processGone(pid2) })
	if b.liveSessions() != 0 {
		t.Fatalf("live=%d after close, want 0", b.liveSessions())
	}
}

func TestSessionCapRejectsInitialize(t *testing.T) {
	b, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.MaxSessions = 1 }))
	first := mustConnect(t, url, &bearerRT{token: "tok-1"})
	call(t, first, "pid") // spawned
	if _, err := connect(t, url, &bearerRT{token: "tok-2"}); err == nil || !strings.Contains(err.Error(), "session cap 1 reached") {
		t.Fatalf("second connect err = %v, want the session cap refusal", err)
	}
	if b.spawns.Load() != 1 {
		t.Fatalf("spawns = %d: a refused session must not spawn", b.spawns.Load())
	}
	_ = first.Close()
	eventually(t, "slot release", func() bool { return b.liveSessions() == 0 })
	if _, err := connect(t, url, &bearerRT{token: "tok-3"}); err != nil {
		t.Fatalf("connect after release: %v", err)
	}
}

func TestIdleSessionIsReaped(t *testing.T) {
	b, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.IdleTimeout = time.Second }))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	pid, _ := strconv.Atoi(call(t, sess, "pid")) // the child is established before the idle window starts
	// No DELETE ever arrives (an Agenthof that crashed sends none): the idle
	// timer alone must end the session and reap the child.
	eventually(t, "idle reap", func() bool { return b.liveSessions() == 0 && processGone(pid) })
}

func TestMaxLifetimeEndsSession(t *testing.T) {
	b, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.MaxLifetime = 2 * time.Second }))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	pid, _ := strconv.Atoi(call(t, sess, "pid")) // the child is established well inside the lifetime
	if b.liveSessions() != 1 {
		t.Fatalf("live=%d before the lifetime elapsed, want 1", b.liveSessions())
	}
	eventually(t, "max-lifetime end", func() bool { return b.liveSessions() == 0 && processGone(pid) })
}

func TestRespawnOnRotationReplacesChild(t *testing.T) {
	b, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.Materialization = matRespawnOnRotation }))
	rt := &bearerRT{token: "tok-a"}
	sess := mustConnect(t, url, rt)
	pidA, _ := strconv.Atoi(call(t, sess, "pid"))
	if call(t, sess, "credential") != fingerprint("tok-a") {
		t.Fatal("first child must hold tok-a")
	}
	rt.set("tok-b") // the broker re-minted; the next call carries the new bearer
	if got := call(t, sess, "credential"); got != fingerprint("tok-b") {
		t.Fatalf("after rotation credential = %q, want sha256(tok-b)", got)
	}
	pidB, _ := strconv.Atoi(call(t, sess, "pid"))
	if pidA == pidB {
		t.Fatal("respawn-on-rotation must replace the child process")
	}
	eventually(t, "old child to exit", func() bool { return processGone(pidA) })
	if b.spawns.Load() != 2 || b.liveSessions() != 1 {
		t.Fatalf("spawns=%d live=%d, want 2/1 (one session, two children over its life)", b.spawns.Load(), b.liveSessions())
	}
}

func TestEnvAtSpawnIgnoresBearerChange(t *testing.T) {
	b, url := startBridge(t, testConfig(t, nil)) // env-at-spawn
	rt := &bearerRT{token: "tok-a"}
	sess := mustConnect(t, url, rt)
	pidA, _ := strconv.Atoi(call(t, sess, "pid"))
	rt.set("tok-b")
	if got := call(t, sess, "credential"); got != fingerprint("tok-a") {
		t.Fatalf("env-at-spawn credential = %q, want sha256(tok-a): the credential is frozen at spawn", got)
	}
	pidB, _ := strconv.Atoi(call(t, sess, "pid"))
	if pidA != pidB || b.spawns.Load() != 1 {
		t.Fatalf("env-at-spawn must not respawn (pids %d/%d, spawns %d)", pidA, pidB, b.spawns.Load())
	}
}

func TestMissingBearerFailsClosed(t *testing.T) {
	b, url := startBridge(t, testConfig(t, nil))
	sess := mustConnect(t, url, &bearerRT{}) // no Authorization at all
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := sess.ListTools(ctx, nil); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Fatalf("ListTools without a bearer err = %v, want a no-credential refusal", err)
	}
	if b.spawns.Load() != 0 {
		t.Fatal("a request without a credential must never spawn a child")
	}
}

func TestToolsListMirrorsChildTools(t *testing.T) {
	_, url := startBridge(t, testConfig(t, nil))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	if got := strings.Join(names, ","); got != "credential,echo,environment,fail,forge,grandchild,pid" {
		t.Fatalf("mirrored tools = %q, want credential,echo,environment,fail,forge,grandchild,pid", got)
	}
}

// startGrandchild has the session's child start a sleeping process it never
// waits for, and returns that process's pid. The grandchild is killed at
// cleanup whatever the test's outcome, so a failure never leaks a sleeper.
func startGrandchild(t *testing.T, sess *mcp.ClientSession) int {
	t.Helper()
	gpid, err := strconv.Atoi(call(t, sess, "grandchild"))
	if err != nil || gpid < 2 {
		t.Fatalf("grandchild pid = %d (%v)", gpid, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(gpid, syscall.SIGKILL) })
	if processGone(gpid) {
		t.Fatal("the grandchild must be running before teardown")
	}
	return gpid
}

// TestSessionCloseReapsGrandchild pins that ending a session ends the whole
// process group the bridge spawned, not only the direct child: a helper the
// child started and left running would otherwise outlive the session,
// holding the credential in its environment.
func TestSessionCloseReapsGrandchild(t *testing.T) {
	b, url := startBridge(t, testConfig(t, nil))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	pid, _ := strconv.Atoi(call(t, sess, "pid"))
	gpid := startGrandchild(t, sess)
	_ = sess.Close()
	eventually(t, "session teardown", func() bool { return b.liveSessions() == 0 && processGone(pid) })
	eventually(t, "grandchild to be reaped", func() bool { return processGone(gpid) })
}

// TestRotationReapsOldGrandchild pins the same for respawn-on-rotation: the
// replaced child's process group ends with it, while the session lives on.
func TestRotationReapsOldGrandchild(t *testing.T) {
	b, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.Materialization = matRespawnOnRotation }))
	rt := &bearerRT{token: "tok-a"}
	sess := mustConnect(t, url, rt)
	gpid := startGrandchild(t, sess)
	rt.set("tok-b")
	if got := call(t, sess, "credential"); got != fingerprint("tok-b") {
		t.Fatalf("after rotation credential = %q, want sha256(tok-b)", got)
	}
	eventually(t, "old grandchild to be reaped", func() bool { return processGone(gpid) })
	if b.liveSessions() != 1 {
		t.Fatalf("live=%d, want 1: rotation must not end the session", b.liveSessions())
	}
}

// TestRejectedChildToolFailsOnlyItsSession pins that a child tool schema the
// SDK server refuses (AddTool panics on it) fails that session's request and
// nothing else: a second session on the same bridge, whose child advertises
// only good tools, completes a call — so the bridge process is still alive.
func TestRejectedChildToolFailsOnlyItsSession(t *testing.T) {
	b, url := startBridge(t, testConfig(t, func(c *bridgeConfig) {
		c.Command = append(c.Command, "poison") // the child poisons its tools/list when its credential is "poison"
	}))
	poisoned := mustConnect(t, url, &bearerRT{token: "poison"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := poisoned.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), `child tool "poison" rejected`) {
		t.Fatalf("call on the poisoned session err = %v, want the rejected-tool refusal", err)
	}
	if strings.Contains(err.Error(), "TEST_CRED=") {
		t.Fatalf("refusal must never carry the credential: %v", err)
	}
	healthy := mustConnect(t, url, &bearerRT{token: "tok-b"})
	if got := call(t, healthy, "environment"); got != "TEST_CRED" {
		t.Fatalf("healthy session environment = %q, want TEST_CRED", got)
	}
	if got := call(t, healthy, "echo"); got != "" {
		t.Fatalf("healthy session echo = %q, want empty", got)
	}
	if b.liveSessions() != 2 {
		t.Fatalf("live=%d, want 2: the poisoned session is refused per request, not ended", b.liveSessions())
	}
}

// TestEndedSessionNeverSpawns pins the orphan race: a tools/* request that
// reaches the spawn path after teardown must fail, not start a child that
// nothing would ever close.
func TestEndedSessionNeverSpawns(t *testing.T) {
	b, url := startBridge(t, testConfig(t, nil))
	mustConnect(t, url, &bearerRT{token: "tok-a"}) // admitted, no child yet
	s := onlySession(t, b)
	s.teardown()
	if b.liveSessions() != 0 {
		t.Fatalf("live=%d after teardown, want 0", b.liveSessions())
	}
	if err := s.ensure("tok-a"); err == nil || !strings.Contains(err.Error(), "session ended") {
		t.Fatalf("ensure after teardown err = %v, want a session-ended refusal", err)
	}
	if _, _, err := s.childFor("tok-a"); err == nil || !strings.Contains(err.Error(), "session ended") {
		t.Fatalf("childFor after teardown err = %v, want a session-ended refusal", err)
	}
	if b.spawns.Load() != 0 {
		t.Fatalf("spawns = %d after teardown, want 0: an ended session must never spawn", b.spawns.Load())
	}
	s.teardown() // a second teardown (the session's own goroutine racing the direct call) is a no-op
	if b.liveSessions() != 0 {
		t.Fatalf("live=%d after repeated teardown, want 0", b.liveSessions())
	}
}

// TestClosedBridgeRefusesInitialize pins the close() window: once the bridge
// is closing, no new session may be admitted (and so no wg.Add can race the
// final wg.Wait).
func TestClosedBridgeRefusesInitialize(t *testing.T) {
	b, url := startBridge(t, testConfig(t, nil))
	first := mustConnect(t, url, &bearerRT{token: "tok-1"})
	pid, _ := strconv.Atoi(call(t, first, "pid"))
	b.close()
	eventually(t, "child to exit on bridge close", func() bool { return processGone(pid) })
	if _, err := connect(t, url, &bearerRT{token: "tok-2"}); err == nil || !strings.Contains(err.Error(), "bridge is closing") {
		t.Fatalf("connect after close err = %v, want the closing refusal", err)
	}
	if b.spawns.Load() != 1 || b.liveSessions() != 0 {
		t.Fatalf("spawns=%d live=%d after close, want 1/0", b.spawns.Load(), b.liveSessions())
	}
}

const attestationKey = "agenthof.dev/runtime-attestation" // the wire contract the gateway reads (internal/rungateway/attestation.go); pinned, not imported

// attestationOf returns the _meta attestation on a result, failing the test
// when it is absent or not an object.
func attestationOf(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	att, ok := res.Meta[attestationKey].(map[string]any)
	if !ok {
		t.Fatalf("result carries no runtime attestation: meta = %v", res.Meta)
	}
	return att
}

func rawCall(t *testing.T, sess *mcp.ClientSession, name string) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func TestEveryResultCarriesRuntimeAttestation(t *testing.T) {
	_, url := startBridge(t, testConfig(t, nil))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	pid, _ := strconv.Atoi(call(t, sess, "pid"))
	res := rawCall(t, sess, "echo")
	att := attestationOf(t, res)
	exe, _ := os.Executable()
	if att["runtime"] != "refbridge" || att["credential_env"] != "TEST_CRED" || att["materialization"] != matEnvAtSpawn {
		t.Fatalf("attestation = %v", att)
	}
	if got := att["command"].([]any); len(got) != 3 || got[0] != exe || got[1] != childFlag {
		t.Fatalf("command = %v, want the configured argv", got)
	}
	if att["pid"] != float64(pid) || att["spawn"] != float64(1) {
		t.Fatalf("pid/spawn = %v/%v, want %d/1", att["pid"], att["spawn"], pid)
	}
	if got := att["env_names"].([]any); len(got) != 1 || got[0] != "TEST_CRED" {
		t.Fatalf("env_names = %v, want exactly [TEST_CRED]", got)
	}
	if s, _ := att["session"].(string); s == "" {
		t.Fatal("session id must be attested (it keys the bridge's own log)")
	}
	// The wire shape is pinned: exactly these keys.
	for _, k := range []string{"runtime", "session", "command", "pid", "spawn", "credential_env", "env_names", "materialization"} {
		if _, ok := att[k]; !ok {
			t.Fatalf("attestation lacks %q: %v", k, att)
		}
	}
	if len(att) != 8 {
		t.Fatalf("attestation has %d keys, want 8: %v", len(att), att)
	}
}

func TestErrorResultCarriesAttestation(t *testing.T) {
	_, url := startBridge(t, testConfig(t, nil))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	res := rawCall(t, sess, "fail")
	if !res.IsError {
		t.Fatal("the child's error result must be relayed as an error result")
	}
	attestationOf(t, res) // an answered call is attested, error or not
}

func TestAttestationSpawnIncrementsOnRotation(t *testing.T) {
	_, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.Materialization = matRespawnOnRotation }))
	rt := &bearerRT{token: "tok-a"}
	sess := mustConnect(t, url, rt)
	first := attestationOf(t, rawCall(t, sess, "echo"))
	rt.set("tok-b")
	second := attestationOf(t, rawCall(t, sess, "echo"))
	if first["spawn"] != float64(1) || second["spawn"] != float64(2) || first["pid"] == second["pid"] {
		t.Fatalf("spawn/pid before %v/%v after %v/%v: a respawn must be visible", first["spawn"], first["pid"], second["spawn"], second["pid"])
	}
	if first["session"] != second["session"] {
		t.Fatal("one session, two children: the session id must not change")
	}
}

func TestAttestationCarriesEnvNamesNeverValues(t *testing.T) {
	_, url := startBridge(t, testConfig(t, func(c *bridgeConfig) { c.EnvPassthrough = []string{"PATH"} }))
	sess := mustConnect(t, url, &bearerRT{token: "tok-secret-value"})
	att := attestationOf(t, rawCall(t, sess, "echo"))
	if got := att["env_names"].([]any); len(got) != 2 || got[0] != "PATH" || got[1] != "TEST_CRED" {
		t.Fatalf("env_names = %v, want [PATH TEST_CRED] sorted", got)
	}
	b, err := json.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"tok-secret-value", "/refbridge-own-path", "must-not-reach-child"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("attestation leaked a value: %s", b)
		}
	}
}

func TestAttestationOverridesChildClaim(t *testing.T) {
	// A child that sets the attestation key itself (a payload trying to
	// forge the runtime's word) is overwritten: only refbridge's account
	// leaves the bridge. The test child's `forge` tool sets the key.
	_, url := startBridge(t, testConfig(t, nil))
	sess := mustConnect(t, url, &bearerRT{token: "tok-a"})
	att := attestationOf(t, rawCall(t, sess, "forge"))
	if att["runtime"] != "refbridge" || att["pid"] == float64(1) {
		t.Fatalf("the child's forged attestation survived: %v", att)
	}
}
