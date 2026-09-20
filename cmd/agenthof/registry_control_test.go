package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
)

// TestRegistryFlipSuccessRecordsControlEvent covers the happy path of
// Task 6's write ordering (spec §3.4): disable then enable each append a
// "success" control/1 event carrying action, agent, invoker, and a
// freshly recomputed config_hash, and each prints the "control head:
// seq=" line.
func TestRegistryFlipSuccessRecordsControlEvent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root,
		"--control-log", controlPath, "--as", "dana@example.com"}, &out)
	if code != 0 {
		t.Fatalf("disable: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "agent coder disabled") {
		t.Fatalf("missing state-change line: %s", out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}

	h, err := config.HashDir(root)
	if err != nil {
		t.Fatalf("HashDir: %v", err)
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{
		`"action":"disable"`, `"outcome":"success"`, `"agent":"coder"`,
		`"config_hash":"` + h + `"`, `"subject":"dana@example.com"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}

	out.Reset()
	code = cmdRegistry([]string{"enable", "coder", "--config", root,
		"--control-log", controlPath, "--as", "dana@example.com"}, &out)
	if code != 0 {
		t.Fatalf("enable: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=2 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}
	data, err = os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if !strings.Contains(string(data), `"action":"enable"`) {
		t.Fatalf("control log missing enable action:\n%s", data)
	}
}

// TestRegistryFlipUnknownAgentRefused covers the unknown-agent branch:
// no flip happens, but the refusal is itself an attributed event with
// reason code agent_not_found, and the process still exits nonzero.
func TestRegistryFlipUnknownAgentRefused(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "ghost", "--config", root,
		"--control-log", controlPath}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for an unknown agent: %s", out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"outcome":"refused"`, `"agent_not_found"`, `"agent":"ghost"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestRegistryFlipUnreadableConfigRecordsIOErrorEvent covers a config
// that fails to load at all (a bad --config, not a genuinely unknown
// agent). Per the review's Fix 1 (spec §3.7: a denial is itself an event
// whenever the control ledger is known writable), this must now be
// recorded — outcome "error", reason io_error — and must never be
// conflated with agent_not_found, which would misattribute a bad path as
// a governance decision about a specific agent.
func TestRegistryFlipUnreadableConfigRecordsIOErrorEvent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", "/nonexistent-agenthof-config-root", "--control-log", controlPath}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for an unreadable config: %s", out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1") {
		t.Fatalf("missing control head line: %s", out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if strings.Contains(string(data), "agent_not_found") {
		t.Fatalf("an unreadable config must not be recorded as agent_not_found:\n%s", data)
	}
	for _, want := range []string{`"outcome":"error"`, `"io_error"`, `"action":"disable"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestRegistryFlipSetEnabledIOErrorRecordsEvent covers a SetEnabled
// failure that is NOT the unknown-agent case (Fix 1b): a known agent
// whose write fails mid-flight (simulated here by making the agents
// directory read-only, so SetEnabled's os.CreateTemp cannot create its
// temp file) must still be recorded as a denial once the control chain
// is known writable — outcome "error", reason io_error.
func TestRegistryFlipSetEnabledIOErrorRecordsEvent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory does not block writes")
	}
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	agentsDir := filepath.Join(root, "agents")
	if err := os.Chmod(agentsDir, 0o555); err != nil {
		t.Fatalf("chmod agents dir read-only: %v", err)
	}
	// Restore write access before t.TempDir()'s own cleanup tries to
	// remove root; t.Cleanup runs LIFO, so this (registered after
	// writeSample's TempDir) runs before TempDir's removal.
	t.Cleanup(func() { _ = os.Chmod(agentsDir, 0o755) })
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a SetEnabled I/O failure: %s", out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1") {
		t.Fatalf("missing control head line: %s", out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"outcome":"error"`, `"io_error"`, `"action":"disable"`, `"agent":"coder"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestRegistryFlipTornControlLedgerRefusesWithoutFlipping covers the
// pre-flip chain verification: a damaged control ledger must refuse
// loudly, name the repair command and the ledger path, leave the agent
// state untouched, and never be written to (the ledger itself is
// unwritable, so there is nothing to record the refusal with).
func TestRegistryFlipTornControlLedgerRefusesWithoutFlipping(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	// A single line with no trailing newline is torn by construction
	// (internal/ledger: the final record must be newline-terminated).
	if err := os.WriteFile(controlPath, []byte(`{"v":"control/1","seq":1,"prev":""`), 0o644); err != nil {
		t.Fatalf("seed torn control log: %v", err)
	}

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root,
		"--control-log", controlPath}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a damaged control ledger: %s", out.String())
	}
	if !strings.Contains(out.String(), "audit repair control") || !strings.Contains(out.String(), controlPath) {
		t.Fatalf("must name the repair command and the ledger path: %s", out.String())
	}

	agentData, err := os.ReadFile(filepath.Join(root, "agents", "coder.yaml"))
	if err != nil {
		t.Fatalf("read agent file: %v", err)
	}
	if strings.Contains(string(agentData), "enabled: false") {
		t.Fatal("agent must not be flipped when the control ledger is damaged")
	}

	after, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if string(after) != `{"v":"control/1","seq":1,"prev":""` {
		t.Fatalf("a damaged control log must not be written to; got:\n%s", after)
	}
}

// TestRegistryFlipTokenRefusedRecordsControlEvent covers the failed-token
// branch: the invoker is refused before any state mutation, but the
// refusal itself is a recorded event with a FIXED reason message (never
// the raw go-oidc error text, which can echo unverified claim values).
func TestRegistryFlipTokenRefusedRecordsControlEvent(t *testing.T) {
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	badToken := cmdMintToken(t, otherKey, map[string]any{
		"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(),
		"sub": "u-123", "email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root,
		"--control-log", controlPath, "--token", badToken}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a rejected token: %s", out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1") {
		t.Fatalf("missing control head line: %s", out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"outcome":"refused"`, `"token_verification_failed"`, `"action":"disable"`, `"token verification failed"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), badToken) {
		t.Fatal("the raw token must never be written to the ledger")
	}

	agentData, err := os.ReadFile(filepath.Join(root, "agents", "coder.yaml"))
	if err != nil {
		t.Fatalf("read agent file: %v", err)
	}
	if strings.Contains(string(agentData), "enabled: false") {
		t.Fatal("agent must not be flipped on a refused token")
	}
}

// TestRegistryFlipTokenRefusedWithTornLedgerPrintsRepairHint covers the
// review's Fix 2 reorder: the control-chain pre-verify must run BEFORE
// any append, including the refused-token append. A bad token combined
// with an already-torn control ledger must still print the "audit
// repair control" hint (not a raw error surfaced from inside
// control.Append), and must not write to the damaged file.
func TestRegistryFlipTokenRefusedWithTornLedgerPrintsRepairHint(t *testing.T) {
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	const torn = `{"v":"control/1","seq":1,"prev":""`
	if err := os.WriteFile(controlPath, []byte(torn), 0o644); err != nil {
		t.Fatalf("seed torn control log: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	badToken := cmdMintToken(t, otherKey, map[string]any{
		"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(),
		"sub": "u-123", "email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root,
		"--control-log", controlPath, "--token", badToken}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit: %s", out.String())
	}
	if !strings.Contains(out.String(), "audit repair control") || !strings.Contains(out.String(), controlPath) {
		t.Fatalf("a torn ledger must print the repair hint even with a bad token: %s", out.String())
	}
	after, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if string(after) != torn {
		t.Fatalf("a damaged control log must not be written to; got:\n%s", after)
	}
}

// TestRegistryFlipHashFailureViaSeamRecordsStateChangedNotRecorded covers
// the final-review fix (M4a): cmdRegistryFlip's post-flip re-hash now goes
// through the package-level hashConfigDir seam (like cmdApply's), instead
// of calling config.HashDir directly, so a hash failure at that point —
// state already changed by SetEnabled, but the success event unbuildable —
// is exercisable by a test rather than only by an unreachable filesystem
// race. It must print "state changed; event NOT recorded", exit nonzero,
// leave the agent's new enabled state on disk, and append no control event.
func TestRegistryFlipHashFailureViaSeamRecordsStateChangedNotRecorded(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	orig := hashConfigDir
	hashConfigDir = func(string) (string, error) { return "", errors.New("simulated hash failure") }
	t.Cleanup(func() { hashConfigDir = orig })

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit when the post-flip hash fails: %s", out.String())
	}
	if !strings.Contains(out.String(), "state changed; event NOT recorded") {
		t.Fatalf("missing residual-risk message: %s", out.String())
	}

	agentData, err := os.ReadFile(filepath.Join(root, "agents", "coder.yaml"))
	if err != nil {
		t.Fatalf("read agent file: %v", err)
	}
	if !strings.Contains(string(agentData), "enabled: false") {
		t.Fatal("agent state must have changed even though the event was not recorded")
	}

	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Fatalf("no control event must be appended when the hash fails post-flip:\n%s", data)
	}
}

// TestRegistryFlipCrashHookAfterStateBeforeAppend covers the final-review
// fix (M4b): the AGENTHOF_TEST_CRASH_AT=after_state_before_append hook
// makes the documented residual-risk window — SetEnabled has already
// changed state, but the process dies before the success control.Append —
// testable directly, without racing the filesystem. It must take the same
// failure path as an append failure: print "state changed; event NOT
// recorded", exit nonzero, leave the new enabled state on disk, and append
// no control event.
func TestRegistryFlipCrashHookAfterStateBeforeAppend(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_state_before_append")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit when the crash hook fires: %s", out.String())
	}
	if !strings.Contains(out.String(), "state changed; event NOT recorded") {
		t.Fatalf("missing residual-risk message: %s", out.String())
	}

	agentData, err := os.ReadFile(filepath.Join(root, "agents", "coder.yaml"))
	if err != nil {
		t.Fatalf("read agent file: %v", err)
	}
	if !strings.Contains(string(agentData), "enabled: false") {
		t.Fatal("agent state must have changed before the simulated crash")
	}

	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Fatalf("no control event must be appended when the crash hook fires:\n%s", data)
	}
}

// TestRegistryFlipNoOpRecordsSuccess covers the review's Fix 3: flipping
// an agent to the state it is already in is not a diff-detection no-op —
// it still rewrites the file and still records a "success" event (spec
// §3.4: "the record is of the action and actor, not a diff").
func TestRegistryFlipNoOpRecordsSuccess(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath}, &out); code != 0 {
		t.Fatalf("first disable: exit %d\n%s", code, out.String())
	}

	out.Reset()
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath}, &out)
	if code != 0 {
		t.Fatalf("no-op disable: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=2") {
		t.Fatalf("missing control head line for the no-op flip: %s", out.String())
	}

	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 records, got %d:\n%s", len(lines), data)
	}
	if !strings.Contains(lines[1], `"action":"disable"`) || !strings.Contains(lines[1], `"outcome":"success"`) {
		t.Fatalf("the no-op flip's second record must still be a success disable: %s", lines[1])
	}
}
