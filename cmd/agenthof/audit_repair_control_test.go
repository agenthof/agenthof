package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuditRepairControlTornTailSucceeds covers the happy path (spec
// §3.6): a torn-tail control log is repaired, the fragment is moved
// aside, the live file verifies clean again, and the ledger is
// permanently tainted.
func TestAuditRepairControlTornTailSucceeds(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlPath, "--as", "dana@example.com"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	f, err := os.OpenFile(controlPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, err := f.Write([]byte(`{"v":"control/1","seq":2,"partial`)); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Before repair, verify reports torn.
	var verifyOut bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", controlPath}, &verifyOut); code != 1 {
		t.Fatalf("pre-repair verify: exit %d, want 1: %s", code, verifyOut.String())
	}

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--as", "ops@example.com"}, &out)
	if code != 0 {
		t.Fatalf("repair: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "control ledger tainted") {
		t.Fatalf("missing tainted line: %s", out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=2 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}

	matches, err := filepath.Glob(controlPath + ".torn-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("torn fragment glob = %v, err %v, want exactly one match", matches, err)
	}

	verifyOut.Reset()
	code = cmdAuditVerify([]string{"control", "--control-log", controlPath}, &verifyOut)
	if code != 3 {
		t.Fatalf("post-repair verify: exit %d, want 3 (tainted): %s", code, verifyOut.String())
	}
}

// TestAuditRepairControlTerminatedUnparseableLineTaints covers the
// brief's other named torn shape end-to-end through the real CLI
// commands: a newline-TERMINATED final line that still fails to parse as
// JSON (not just a missing trailing newline) is also a torn tail. Repair
// must move that whole line into the fragment, truncate back to the
// clean prefix, succeed, and `audit verify control` must then report the
// ledger TAINTED (exit 3) forever.
func TestAuditRepairControlTerminatedUnparseableLineTaints(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlPath, "--as", "dana@example.com"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	f, err := os.OpenFile(controlPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	// A complete, newline-terminated line that is still not valid JSON.
	if _, err := f.Write([]byte("not json at all\n")); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var verifyOut bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", controlPath}, &verifyOut); code != 1 {
		t.Fatalf("pre-repair verify: exit %d, want 1: %s", code, verifyOut.String())
	}

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--as", "ops@example.com"}, &out)
	if code != 0 {
		t.Fatalf("repair: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "control ledger tainted") {
		t.Fatalf("missing tainted line: %s", out.String())
	}

	matches, err := filepath.Glob(controlPath + ".torn-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("torn fragment glob = %v, err %v, want exactly one match", matches, err)
	}
	fragContent, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read torn file: %v", err)
	}
	if string(fragContent) != "not json at all\n" {
		t.Fatalf("torn file content = %q, want the whole garbage line", fragContent)
	}

	verifyOut.Reset()
	code = cmdAuditVerify([]string{"control", "--control-log", controlPath}, &verifyOut)
	if code != 3 {
		t.Fatalf("post-repair verify: exit %d, want 3 (tainted): %s", code, verifyOut.String())
	}
	if !strings.Contains(verifyOut.String(), "TAINTED") {
		t.Fatalf("missing TAINTED line: %s", verifyOut.String())
	}
}

// TestAuditRepairControlCleanLogRefused covers Repair's refusal (via the
// command) on an already-clean control log.
func TestAuditRepairControlCleanLogRefused(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlPath, "--as", "dana@example.com"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--as", "ops@example.com"}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit repairing a clean log: %s", out.String())
	}
	if !strings.Contains(out.String(), "not torn") {
		t.Fatalf("missing not-torn message: %s", out.String())
	}
}

// TestAuditRepairControlChainBrokenRefused covers Repair's refusal (via
// the command) on a mid-file chain break, naming the broken line.
func TestAuditRepairControlChainBrokenRefused(t *testing.T) {
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	const broken = `{"v":"control/1","seq":1,"prev":"deadbeef","time":"2026-01-01T00:00:00Z","action":"apply","outcome":"success","invoker":{},"witness":{},"log_id":"x"}` + "\n"
	if err := os.WriteFile(controlPath, []byte(broken), 0o600); err != nil {
		t.Fatalf("seed broken control log: %v", err)
	}

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--as", "ops@example.com"}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit repairing a chain-broken log: %s", out.String())
	}
	if !strings.Contains(out.String(), "not auto-repairable") {
		t.Fatalf("missing not-auto-repairable message: %s", out.String())
	}
}

// TestAuditRepairControlMissingLogExitsOne covers a control log that has
// never been written to: reported plainly, exit 1, matching
// cmdAuditControl/cmdAuditVerifyControl's own wording.
func TestAuditRepairControlMissingLogExitsOne(t *testing.T) {
	controlPath := filepath.Join(t.TempDir(), "never-written.jsonl")

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--as", "ops@example.com"}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: %s", code, out.String())
	}
	want := "no control ledger at " + controlPath + " — nothing recorded yet\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

// TestAuditRepairControlMissingSubcommandExitsTwo covers `audit repair`
// with no "control" argument: a usage error.
func TestAuditRepairControlMissingSubcommandExitsTwo(t *testing.T) {
	var out bytes.Buffer
	code := cmdAuditRepairControl(nil, &out)
	if code != 2 {
		t.Fatalf("exit = %d, want 2: %s", code, out.String())
	}
}

// TestAuditRepairControlUsageErrorExitsTwo covers --token given without
// AGENTHOF_OIDC_ISSUER set: a usage error, exit 2, mirroring
// resolveInvoker's contract used by apply/registry.
func TestAuditRepairControlUsageErrorExitsTwo(t *testing.T) {
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--token", "whatever"}, &out)
	if code != 2 {
		t.Fatalf("exit = %d, want 2: %s", code, out.String())
	}
}

// TestAuditRepairControlTokenRefusedDoesNotAppend covers a rejected
// --token: the command must exit nonzero WITHOUT writing any control
// event, since the ledger being repaired may itself be the torn/
// unwritable file in question — there is no known-writable chain to
// safely record the refusal against.
func TestAuditRepairControlTokenRefusedDoesNotAppend(t *testing.T) {
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")
	const torn = `{"v":"control/1","seq":1,"prev":""`
	if err := os.WriteFile(controlPath, []byte(torn), 0o600); err != nil {
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
		"sub": "u-123", "email": "ops@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	before, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", controlPath, "--token", badToken}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a rejected token: %s", out.String())
	}
	if strings.Contains(out.String(), badToken) {
		t.Fatal("the raw token must never be printed")
	}

	after, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused token must not write anything to the ledger")
	}
	if matches, _ := filepath.Glob(controlPath + ".torn-*"); len(matches) != 0 {
		t.Fatalf("a refused token must not create a fragment file: %v", matches)
	}
}
