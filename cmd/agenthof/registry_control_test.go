package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// TestRegistryFlipSuccessRecordsControlEvent covers the happy path of
// the write ordering (spec §3.4): disable then enable each append a
// "success" control/1 event carrying action, agent, invoker, and a
// freshly recomputed config_hash, and each prints the "control head:
// seq=" line.
func TestRegistryFlipSuccessRecordsControlEvent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root,
		"--control-log", controlPath, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
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
		"--control-log", controlPath, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
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
		"--control-log", controlPath, "--groups", "platform-eng"}, &out)
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
// agent). Per spec §3.7 (a denial is itself an event whenever the
// control ledger is known writable), this must be recorded — outcome
// "error", reason io_error — and must never be conflated with
// agent_not_found, which would misattribute a bad path as a governance
// decision about a specific agent.
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
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out)
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
	if want := "audit repair control --control-log " + controlPath + " --config " + root; !strings.Contains(out.String(), want) {
		t.Fatalf("must print the repair hint %q: %s", want, out.String())
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
// pre-verify ordering: the control-chain pre-verify must run BEFORE
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
	if want := "audit repair control --control-log " + controlPath + " --config " + root; !strings.Contains(out.String(), want) {
		t.Fatalf("a torn ledger must print the repair hint %q even with a bad token: %s", want, out.String())
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
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out)
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
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out)
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

// TestRegistryFlipNoOpRecordsSuccess covers the no-op case: flipping
// an agent to the state it is already in is not a diff-detection no-op —
// it still rewrites the file and still records a "success" event (spec
// §3.4: "the record is of the action and actor, not a diff").
func TestRegistryFlipNoOpRecordsSuccess(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("first disable: exit %d\n%s", code, out.String())
	}

	out.Reset()
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out)
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

// TestRegistryFlipNotAuthorizedRefusedWithoutFlipping: a caller no role
// grants `disable` is refused — recorded refused/not_authorized — and the
// agent's enabled bit is untouched.
func TestRegistryFlipNotAuthorizedRefusedWithoutFlipping(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--as", "mallory@example.com", "--groups", "finance"}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "registry disable: not authorized: no role grants disable to the invoker") {
		t.Fatalf("missing refusal line: %s", out.String())
	}
	if strings.Contains(out.String(), "agent coder disabled") {
		t.Fatal("must not report a flip")
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"action":"disable"`, `"agent":"coder"`, `"outcome":"refused"`, `"code":"not_authorized"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
	agentData, err := os.ReadFile(filepath.Join(root, "agents", "coder.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(agentData), "enabled: false") {
		t.Fatal("agent must not be flipped by an unauthorized caller")
	}
}

// TestRegistryFlipNotAuthorizedPrecedesAgentLookup: an unauthorized caller
// naming an unknown agent gets not_authorized, never agent_not_found — the
// agent list is not probeable by someone who may not flip anything.
func TestRegistryFlipNotAuthorizedPrecedesAgentLookup(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "ghost", "--config", root, "--control-log", controlPath, "--groups", "finance"}, &out); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "agent_not_found") || !strings.Contains(string(data), "not_authorized") {
		t.Fatalf("want not_authorized and no agent_not_found:\n%s", data)
	}
}

// TestRegistryEnableAfterDisableIsAuthorizedWithoutValidation: with coder
// disabled, registry.Build would reject the config (disabled-agent-ref); the
// kill switch authorizes against LoadDir's roles, so re-enabling still works.
func TestRegistryEnableAfterDisableIsAuthorizedWithoutValidation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out); code != 1 || !strings.Contains(out.String(), "depends on agent") {
		t.Fatalf("apply must reject the disabled dependency: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("enable after disable must succeed: %d\n%s", code, out.String())
	}
}

// TestRegistryFlipAuthorizesAgainstInstalledNotDir: once a configuration is
// installed, the kill switch reads ITS roles — granting finance control in
// the directory without applying it changes nothing; platform-eng, which the
// installed config grants, still flips. --config stays the mutation target.
func TestRegistryFlipAuthorizesAgainstInstalledNotDir(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlPath, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("bootstrap: %d\n%s", code, out.String())
	}
	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte("name: platform-admin\nallowed_groups: [finance]\ncontrol: [apply, enable, disable, repair]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--as", "mallory@example.com", "--groups", "finance"}, &out); code != 1 ||
		!strings.Contains(out.String(), "registry disable: not authorized: no role grants disable to the invoker") {
		t.Fatalf("finance must be refused against the installed roles: %d\n%s", code, out.String())
	}
	agentData, err := os.ReadFile(filepath.Join(root, "agents", "coder.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(agentData), "enabled: false") {
		t.Fatal("agent must not be flipped by a caller the installed config does not grant")
	}
	out.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 ||
		!strings.Contains(out.String(), "agent coder disabled") {
		t.Fatalf("platform-eng (installed grant) must still flip: %d\n%s", code, out.String())
	}
}

// TestRegistryFlipInstalledUnauthorizedNeverReadsConfig pins the ordering: once
// a snapshot is installed, an unauthorized caller is refused against the
// INSTALLED roles before --config is read at all. A nonexistent --config must
// therefore record not_authorized (never io_error) and its path must never be
// printed — the refusal neither depends on nor leaks the config directory.
func TestRegistryFlipInstalledUnauthorizedNeverReadsConfig(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlPath, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("bootstrap: %d\n%s", code, out.String())
	}
	out.Reset()
	missing := filepath.Join(t.TempDir(), "gone")
	if code := cmdRegistry([]string{"disable", "coder", "--config", missing, "--control-log", controlPath, "--as", "mallory@example.com", "--groups", "finance"}, &out); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if strings.Contains(out.String(), missing) {
		t.Fatalf("the unread --config path must never be printed:\n%s", out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "not_authorized") || strings.Contains(string(data), "io_error") {
		t.Fatalf("want not_authorized recorded and no io_error:\n%s", data)
	}
}

// TestRegistryFlipMalformedPointerRecordsIOError: a damaged installed pointer
// fails the kill switch closed — recorded error/io_error, no flip.
func TestRegistryFlipMalformedPointerRecordsIOError(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	store := installedStore(controlPath)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, config.InstalledPointer), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlPath, "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "agent coder disabled") {
		t.Fatal("must not flip")
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"action":"disable"`, `"outcome":"error"`, `"io_error"`, "malformed pointer"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestRegistryFlipWithNothingInstalledIsMarkedBootstrap: a flip that runs
// before any apply edits the directory and records the directory's hash,
// installing nothing; its success event carries bootstrap:true so the audit
// readers can tell it from a flip that installed what it recorded.
func TestRegistryFlipWithNothingInstalledIsMarkedBootstrap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", controlPath, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("enable: %d\n%s", code, out.String())
	}
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"action":"enable"`) || !strings.Contains(string(data), `"bootstrap":true`) {
		t.Fatalf("the nothing-installed flip must be marked bootstrap:\n%s", data)
	}
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", controlPath}, &out); code != 0 {
		t.Fatalf("audit control: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "enabled agent coder (nothing installed; directory edited) — dana@example.com (asserted)") {
		t.Fatalf("audit control must render the bootstrap-era flip distinctly:\n%s", out.String())
	}
}

// lastControlEvent decodes the last record of a control ledger.
func lastControlEvent(t *testing.T, controlLog string) control.DecodedEvent {
	t.Helper()
	recs, _, err := ledger.ReadVerify(controlLog, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	d, err := control.Decode(recs[len(recs)-1].Raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// runFixBug runs software-engineer/fix-bug against ctl and returns the exit
// code and output.
func runFixBug(t *testing.T, root, ctl string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--control-log", ctl, "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir()}, &out, io.Discard)
	return code, out.String()
}

// TestRegistryFlipInstalledReSnapshotsAndRunsFollow: with something
// installed, disable stages a copy of the installed snapshot, flips the bit
// on the copy and installs it — the directory is untouched, the event
// carries the new pointer, runs are refused (disabled-agent-ref, the whole
// configuration), the audit readers do not false-alarm, enable installs a
// third snapshot and runs succeed again, and a repeated flip is idempotent.
func TestRegistryFlipInstalledReSnapshotsAndRunsFollow(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	applyHash := readPointer(t, ctl)
	coderPath := filepath.Join(root, "agents", "coder.yaml")
	dirBefore, err := os.ReadFile(coderPath)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(action string) string {
		t.Helper()
		var out bytes.Buffer
		if code := cmdRegistry([]string{action, "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 || !strings.Contains(out.String(), "agent coder "+action+"d") {
			t.Fatalf("%s: %d\n%s", action, code, out.String())
		}
		return out.String()
	}

	flip("disable")
	disableHash := readPointer(t, ctl)
	if disableHash == applyHash {
		t.Fatal("disable must install a new snapshot")
	}
	if dirAfter, _ := os.ReadFile(coderPath); !bytes.Equal(dirBefore, dirAfter) {
		t.Fatal("the configuration directory must not be touched once something is installed")
	}
	if e := lastControlEvent(t, ctl); e.Action != "disable" || e.Outcome != "success" || e.ConfigHash != disableHash || e.Bootstrap {
		t.Fatalf("event must carry the new pointer and no bootstrap marker: %+v", e)
	}
	cfg, _, _, errs := config.LoadInstalled(installedStore(ctl))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, a := range cfg.Agents {
		if a.Name == "coder" && a.IsEnabled() {
			t.Fatal("the installed snapshot must say disabled")
		}
	}
	if code, out := runFixBug(t, root, ctl); code != 1 || !strings.Contains(out, "disabled in the registry") || !strings.Contains(out, "refused: configuration invalid") {
		t.Fatalf("a run must be refused configuration invalid: %d\n%s", code, out)
	}
	var out bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "matches the last recorded install (disable agent coder)") {
		t.Fatalf("verify must not false-alarm after a flip: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "matches the last recorded install (disable agent coder)") {
		t.Fatalf("audit control: %d\n%s", code, out.String())
	}

	// Idempotent: flip-written bytes re-marshal identically → same hash,
	// a second success event.
	flip("disable")
	if readPointer(t, ctl) != disableHash {
		t.Fatal("a repeated disable must re-point to the same snapshot")
	}
	if e := lastControlEvent(t, ctl); e.Seq != 3 || e.ConfigHash != disableHash {
		t.Fatalf("second disable must record the same hash as seq 3: %+v", e)
	}

	flip("enable")
	enableHash := readPointer(t, ctl)
	if enableHash == disableHash || enableHash == applyHash {
		t.Fatalf("enable re-marshals the file: a third hash, not the apply's back (apply=%s disable=%s enable=%s)", applyHash, disableHash, enableHash)
	}
	if code, out := runFixBug(t, root, ctl); code != 0 {
		t.Fatalf("run after enable: %d\n%s", code, out)
	}
	out.Reset()
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "matches the last recorded install (enable agent coder)") {
		t.Fatalf("%d\n%s", code, out.String())
	}
}

// TestRegistryFlipInstalledUnknownAgentLeavesPointer: the lookup is in the
// installed snapshot, not --config — an agent added to the directory but
// not applied is agent_not_found, and nothing moves.
func TestRegistryFlipInstalledUnknownAgentLeavesPointer(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	before := readPointer(t, ctl)
	if err := os.WriteFile(filepath.Join(root, "agents", "newbie.yaml"), []byte("name: newbie\nmodel: fast\ninstruction: x\noutput: y\nendpoint: http://127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "newbie", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeAgentNotFound {
		t.Fatalf("want refused/agent_not_found: %+v", e)
	}
	if readPointer(t, ctl) != before {
		t.Fatal("pointer must not move")
	}
}

// TestRegistryFlipInstalledHashFailureLeavesPointer: the hash now precedes
// the state change, so a hash failure is a recorded error with the pointer
// untouched — not "state changed; event NOT recorded".
func TestRegistryFlipInstalledHashFailureLeavesPointer(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	before := readPointer(t, ctl)
	orig := hashConfigDir
	hashConfigDir = func(string) (string, error) { return "", errors.New("forced hash failure") }
	t.Cleanup(func() { hashConfigDir = orig })
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "state changed") || strings.Contains(out.String(), "agent coder disabled") {
		t.Fatalf("nothing changed, so nothing may say so:\n%s", out.String())
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError {
		t.Fatalf("want error/io_error: %+v", e)
	}
	if readPointer(t, ctl) != before {
		t.Fatal("pointer must not move")
	}
	entries, _ := os.ReadDir(installedStore(ctl))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") {
			t.Fatalf("the staged copy must be removed: %s", e.Name())
		}
	}
}

// TestRegistryFlipInstalledUnwritableStoreRecordsIOError (Review Focus 2):
// a store the process cannot write to stages nothing, changes nothing, and
// records error/io_error.
func TestRegistryFlipInstalledUnwritableStoreRecordsIOError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory modes are not enforced")
	}
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	before := readPointer(t, ctl)
	store := installedStore(ctl)
	if err := os.Chmod(store, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store, 0o700) })
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError {
		t.Fatalf("want error/io_error: %+v", e)
	}
	if strings.Contains(out.String(), "state changed") {
		t.Fatalf("nothing changed:\n%s", out.String())
	}
	if readPointer(t, ctl) != before {
		t.Fatal("pointer must not move")
	}
}

// TestRegistryFlipInstalledCrashHookShowsAsUnrecordedInstall: the crash hook
// after the commit and before the append leaves the pointer moved with no
// event; audit verify control exits 5 with the new wording.
func TestRegistryFlipInstalledCrashHookShowsAsUnrecordedInstall(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	applyHash := readPointer(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_state_before_append")
	var out bytes.Buffer
	code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code == 0 || !strings.Contains(out.String(), "state changed; event NOT recorded") {
		t.Fatalf("code=%d\n%s", code, out.String())
	}
	moved := readPointer(t, ctl)
	if moved == applyHash {
		t.Fatal("the pointer must have moved before the simulated crash")
	}
	if e := lastControlEvent(t, ctl); e.Action != "apply" {
		t.Fatalf("no flip event may be recorded: %+v", e)
	}
	out.Reset()
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &out); code != exitInstalledMismatch {
		t.Fatalf("exit %d, want %d\n%s", code, exitInstalledMismatch, out.String())
	}
	want := "installed config: " + moved + " — does NOT match the last recorded install (" + applyHash + ", apply): the install was not recorded, or its record was lost\n"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("want %q in:\n%s", want, out.String())
	}
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), want) {
		t.Fatalf("audit control: %d\n%s", code, out.String())
	}
}

// TestApplyAfterDisableReEnables is the documentation's proof of the
// declared-state model: apply from the unchanged directory re-asserts it —
// agent enabled, pointer back on the apply's hash, recorded as an apply —
// and the control ledger shows apply, disable, apply in order.
func TestApplyAfterDisableReEnables(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	applyHash := readPointer(t, ctl)
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 || !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 2 roles") {
		t.Fatalf("apply must re-assert the directory: %d\n%s", code, out.String())
	}
	if readPointer(t, ctl) != applyHash {
		t.Fatal("the pointer must be back on the apply's hash")
	}
	if code, out := runFixBug(t, root, ctl); code != 0 {
		t.Fatalf("run after re-apply: %d\n%s", code, out)
	}
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, r := range recs {
		d, _ := control.Decode(r.Raw)
		actions = append(actions, d.Action+"/"+d.Outcome)
	}
	if strings.Join(actions, " ") != "apply/success disable/success apply/success" {
		t.Fatalf("ledger order: %v", actions)
	}
}

// TestAuditVerifyControlBootstrapFlipDoesNotVouchForUnrecordedApply is the
// end-to-end blocker scenario: a flip with nothing installed records the
// directory's hash X (marked bootstrap); an apply of that unchanged
// directory installs X but its record is lost. The flip's hash equals the
// pointer and must NOT vouch for it: exit 5, "no install on record".
func TestAuditVerifyControlBootstrapFlipDoesNotVouchForUnrecordedApply(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("enable: %d\n%s", code, out.String())
	}
	flipHash := lastControlEvent(t, ctl).ConfigHash
	out.Reset()
	if code := cmdAuditControl([]string{"--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "enabled agent coder (nothing installed; directory edited)") {
		t.Fatalf("audit control: %d\n%s", code, out.String())
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	out.Reset()
	_ = cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if readPointer(t, ctl) != flipHash {
		t.Fatalf("fixture: the apply of the flipped directory must install the flip's hash (%s vs %s)", readPointer(t, ctl), flipHash)
	}
	out.Reset()
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &out); code != exitInstalledMismatch {
		t.Fatalf("exit %d, want %d\n%s", code, exitInstalledMismatch, out.String())
	}
	if !strings.Contains(out.String(), "installed config: "+flipHash+" — no install on record: the install was not recorded, or its record was lost") {
		t.Fatalf("output: %s", out.String())
	}
	// A clean apply of the same directory records it: vouched for now.
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &out); code != 0 || !strings.Contains(out.String(), "matches the last recorded install (apply)") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}

	// A run under X joins to the apply (form 1), never to the flip.
	logs := t.TempDir()
	out.Reset()
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--control-log", ctl, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs, "--control-log", ctl}, &out); code != 0 {
		t.Fatalf("audit: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "config "+flipHash+" — applied by dana@example.com (asserted)") || strings.Contains(out.String(), "kill switch") {
		t.Fatalf("the join must name the apply, never the bootstrap-era flip:\n%s", out.String())
	}
}
