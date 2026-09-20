package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

// TestApplyRecordsSuccessEvent covers apply's happy path (spec §3.4/§3.7,
// Task 7): a valid config records a "success" control/1 event carrying
// the invoker and a config_hash, and prints the control head.
func TestApplyRecordsSuccessEvent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &out)
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 1 roles") {
		t.Fatalf("missing registry-ok line: %s", out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}

	h, err := config.HashDir(root)
	if err != nil {
		t.Fatalf("HashDir: %v", err)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{
		`"action":"apply"`, `"outcome":"success"`,
		`"config_hash":"` + h + `"`, `"subject":"dana@example.com"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestApplyRecordsRejectedEventWithConfigHash covers apply's validation
// failure branch: a config that fails registry.Build validation (a role
// naming a workflow that references a disabled agent, reusing
// TestApplyOKAndFailure's fixture) is still recorded — outcome
// "rejected", reason validation_failed — and config_hash is the hash of
// the REJECTED bytes.
func TestApplyRecordsRejectedEventWithConfigHash(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	// Disable coder directly (not via cmdRegistry, to keep this test's
	// control log free of an extra disable event) so fix-bug's step
	// references a disabled dependency and registry.Build rejects it.
	coderPath := filepath.Join(root, "agents", "coder.yaml")
	data, err := os.ReadFile(coderPath)
	if err != nil {
		t.Fatalf("read coder.yaml: %v", err)
	}
	if err := os.WriteFile(coderPath, append(data, []byte("enabled: false\n")...), 0o644); err != nil {
		t.Fatalf("disable coder: %v", err)
	}
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("apply must fail with a disabled dependency: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}

	h, err := config.HashDir(root)
	if err != nil {
		t.Fatalf("HashDir: %v", err)
	}
	logData, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{
		`"action":"apply"`, `"outcome":"rejected"`, `"validation_failed"`,
		`"config_hash":"` + h + `"`,
	} {
		if !strings.Contains(string(logData), want) {
			t.Fatalf("control log missing %q:\n%s", want, logData)
		}
	}
}

// TestApplyHashFailureRecordsIOErrorNotSuccess covers the review fix: a
// config that LoadDir/Build would otherwise accept, but whose config_hash
// can't be computed (simulated here via the hashConfigDir seam — LoadDir
// and HashDir read the exact same bytes through the exact same
// enumeration, so there is no filesystem-only way to make one fail
// without the other), must never be recorded as a hash-less "success":
// config_hash is required on that outcome (spec §3.2), so the honest
// record is outcome "error" / reason io_error instead.
func TestApplyHashFailureRecordsIOErrorNotSuccess(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	orig := hashConfigDir
	hashConfigDir = func(string) (string, error) { return "", errors.New("simulated hash failure") }
	t.Cleanup(func() { hashConfigDir = orig })

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit when config_hash cannot be computed: %s", out.String())
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"action":"apply"`, `"outcome":"error"`, `"io_error"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), `"outcome":"success"`) {
		t.Fatalf("a hash failure must never be recorded as success:\n%s", data)
	}
}

// TestApplyHashFailureOnRejectedConfigRecordsIOErrorNotRejected covers
// the same fix on the rejected branch: a config that fails
// registry.Build's validation but whose config_hash also can't be
// computed must be recorded as outcome "error" / io_error, never a
// hash-less "rejected".
func TestApplyHashFailureOnRejectedConfigRecordsIOErrorNotRejected(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	coderPath := filepath.Join(root, "agents", "coder.yaml")
	data, err := os.ReadFile(coderPath)
	if err != nil {
		t.Fatalf("read coder.yaml: %v", err)
	}
	if err := os.WriteFile(coderPath, append(data, []byte("enabled: false\n")...), 0o644); err != nil {
		t.Fatalf("disable coder: %v", err)
	}
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	orig := hashConfigDir
	hashConfigDir = func(string) (string, error) { return "", errors.New("simulated hash failure") }
	t.Cleanup(func() { hashConfigDir = orig })

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit when config_hash cannot be computed: %s", out.String())
	}
	logData, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"action":"apply"`, `"outcome":"error"`, `"io_error"`} {
		if !strings.Contains(string(logData), want) {
			t.Fatalf("control log missing %q:\n%s", want, logData)
		}
	}
	if strings.Contains(string(logData), `"outcome":"rejected"`) {
		t.Fatalf("a hash failure must never be recorded as rejected:\n%s", logData)
	}
}

// TestApplyUnparseableConfigRecordsRejectedNotIOError covers the
// final-review fix (M3): a config directory whose agent YAML is present
// and READABLE but fails to parse must be recorded as outcome "rejected" /
// reason validation_failed, with a config_hash over the unparseable bytes —
// not outcome "error" / io_error with no hash. LoadDir reports a parse
// failure through the same []error path as an unreadable file, but
// hashConfigDir succeeding on the same directory is what distinguishes
// "the bytes are there but bad" from a genuine I/O denial.
func TestApplyUnparseableConfigRecordsRejectedNotIOError(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	coderPath := filepath.Join(root, "agents", "coder.yaml")
	if err := os.WriteFile(coderPath, []byte("name: [unterminated"), 0o644); err != nil {
		t.Fatalf("write unparseable agent yaml: %v", err)
	}
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("apply must fail on unparseable config: exit %d\n%s", code, out.String())
	}

	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"action":"apply"`, `"outcome":"rejected"`, `"validation_failed"`, `"config_hash":"sha256:`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), `"outcome":"error"`) || strings.Contains(string(data), `"io_error"`) {
		t.Fatalf("an unparseable-but-readable config must not be recorded as io_error:\n%s", data)
	}
}

// TestApplyUnreadableConfigStillRecordsIOError covers the existing
// unreadable-config path (a bad --config root, no directory at all): it
// must keep recording outcome "error" / reason io_error with no
// config_hash, since hashConfigDir also fails there.
func TestApplyUnreadableConfigStillRecordsIOError(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdApply([]string{"--config", "/nonexistent-agenthof-config-root", "--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("apply must fail on an unreadable config: exit %d\n%s", code, out.String())
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	for _, want := range []string{`"action":"apply"`, `"outcome":"error"`, `"io_error"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), `"config_hash"`) {
		t.Fatalf("an unreadable config must not carry a config_hash:\n%s", data)
	}
}

// TestApplyTornControlLedgerRefusesWithoutEvent covers the pre-verify
// step: a damaged control ledger must refuse loudly, name the repair
// command and the ledger path, and never be written to — the ledger
// itself is unwritable, so there is nothing to record the refusal with.
func TestApplyTornControlLedgerRefusesWithoutEvent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	const torn = `{"v":"control/1","seq":1,"prev":""`
	if err := os.WriteFile(controlLog, []byte(torn), 0o644); err != nil {
		t.Fatalf("seed torn control log: %v", err)
	}

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a damaged control ledger: %s", out.String())
	}
	if !strings.Contains(out.String(), "audit repair control") || !strings.Contains(out.String(), controlLog) {
		t.Fatalf("must name the repair command and the ledger path: %s", out.String())
	}

	after, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if string(after) != torn {
		t.Fatalf("a damaged control log must not be written to; got:\n%s", after)
	}
}
