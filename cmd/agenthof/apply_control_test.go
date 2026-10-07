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

// TestApplyRecordsSuccessEvent covers apply's happy path (spec §3.4/§3.7):
// a valid config records a "success" control/1 event carrying
// the invoker and a config_hash, and prints the control head.
func TestApplyRecordsSuccessEvent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 2 roles") {
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
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out)
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
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out)
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
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out)
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
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out)
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
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "platform-eng"}, &out)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a damaged control ledger: %s", out.String())
	}
	if want := "audit repair control --control-log " + controlLog + " --config " + root; !strings.Contains(out.String(), want) {
		t.Fatalf("must print the repair hint %q: %s", want, out.String())
	}

	after, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatalf("read control log: %v", err)
	}
	if string(after) != torn {
		t.Fatalf("a damaged control log must not be written to; got:\n%s", after)
	}
}

// TestApplyNotAuthorizedRecordsRefusedWithConfigHash: once a configuration is
// installed, a caller whose groups it grants no `apply` is refused — recorded
// refused/not_authorized with the hash of the config they tried to apply — and
// the fixed message never echoes their groups.
func TestApplyNotAuthorizedRecordsRefusedWithConfigHash(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var boot bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &boot); code != 0 {
		t.Fatalf("bootstrap apply: exit %d\n%s", code, boot.String())
	}

	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "mallory@example.com", "--groups", "finance"}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "apply: not authorized: no role grants apply to the invoker") {
		t.Fatalf("missing refusal line: %s", out.String())
	}
	if strings.Contains(out.String(), "registry ok") {
		t.Fatalf("an unauthorized apply must not report success: %s", out.String())
	}
	h, err := config.HashDir(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"action":"apply"`, `"outcome":"refused"`, `"code":"not_authorized"`,
		`"message":"not authorized: no role grants apply to the invoker"`,
		`"config_hash":"` + h + `"`, `"subject":"mallory@example.com"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestApplyNoGroupsIsRefused: with a configuration installed, the OS user with
// no groups asserted is nobody's member — default-deny.
func TestApplyNoGroupsIsRefused(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var boot bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &boot); code != 0 {
		t.Fatalf("bootstrap apply: exit %d\n%s", code, boot.String())
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog}, &out); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"not_authorized"`) {
		t.Fatalf("expected a not_authorized record:\n%s", data)
	}
}

// TestApplyNotAuthorizedPrecedesValidation: an unauthorized caller applying an
// INVALID config learns one refusal — not the config's validation errors —
// and the record is refused, not rejected.
func TestApplyNotAuthorizedPrecedesValidation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var boot bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &boot); code != 0 {
		t.Fatalf("bootstrap apply: exit %d\n%s", code, boot.String())
	}
	coderPath := filepath.Join(root, "agents", "coder.yaml")
	data, err := os.ReadFile(coderPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coderPath, append(data, []byte("enabled: false\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "finance"}, &out); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "depends on agent") {
		t.Fatalf("validation errors leaked to an unauthorized caller: %s", out.String())
	}
	logData, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logData), `"rejected"`) || !strings.Contains(string(logData), `"refused"`) {
		t.Fatalf("want refused, not rejected:\n%s", logData)
	}
}

// TestApplyNotAuthorizedHashFailureRecordsIOError: the refused event needs a
// config_hash; if it cannot be computed the honest record is error/io_error,
// never a hash-less refusal (same rule as success/rejected).
func TestApplyNotAuthorizedHashFailureRecordsIOError(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var boot bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &boot); code != 0 {
		t.Fatalf("bootstrap apply: exit %d\n%s", code, boot.String())
	}
	orig := hashConfigDir
	hashConfigDir = func(string) (string, error) { return "", errors.New("simulated hash failure") }
	t.Cleanup(func() { hashConfigDir = orig })

	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--groups", "finance"}, &out); code == 0 {
		t.Fatalf("expected nonzero exit: %s", out.String())
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"outcome":"error"`, `"io_error"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), `"refused"`) {
		t.Fatalf("a hash failure must never be recorded as a hash-less refusal:\n%s", data)
	}
}

// snapshotHashDir is the content-addressed directory a snapshot with hash
// "sha256:<hex>" lives in under store.
func snapshotHashDir(store, hash string) string {
	return filepath.Join(store, strings.TrimPrefix(hash, "sha256:"))
}

func readPointer(t *testing.T, controlLog string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(installedStore(controlLog), config.InstalledPointer))
	if err != nil {
		t.Fatalf("read installed pointer: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// TestApplyBootstrapInstallsAndRecordsBootstrap: on a fresh control root the
// first apply is permitted, installs a content-addressed snapshot beside the
// ledger, points `current` at it, and is recorded with bootstrap:true.
func TestApplyBootstrapInstallsAndRecordsBootstrap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var out bytes.Buffer
	// finance: no role grants it anything — and it still bootstraps.
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "mallory@example.com", "--groups", "finance"}, &out); code != 0 {
		t.Fatalf("bootstrap apply: exit %d\n%s", code, out.String())
	}
	h, err := config.HashDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := readPointer(t, controlLog); got != h {
		t.Fatalf("pointer=%q want %q", got, h)
	}
	snap := snapshotHashDir(installedStore(controlLog), h)
	if _, err := os.Stat(filepath.Join(snap, "roles", "ops.yaml")); err != nil {
		t.Fatalf("snapshot missing roles/ops.yaml: %v", err)
	}
	if sh, err := config.HashDir(snap); err != nil || sh != h {
		t.Fatalf("HashDir(snapshot)=%q err=%v, want %q", sh, err, h)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"outcome":"success"`, `"bootstrap":true`, `"config_hash":"` + h + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestApplySelfGrantRefusedAgainstInstalled is the proof the design exists
// for: the installed configuration grants apply to platform-eng only; a
// finance caller applies a configuration that WOULD grant finance control,
// and is refused against the installed roles — nothing installed, the
// pointer untouched, the refusal recorded with the proposed config's hash.
func TestApplySelfGrantRefusedAgainstInstalled(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var boot bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &boot); code != 0 {
		t.Fatalf("bootstrap apply: exit %d\n%s", code, boot.String())
	}
	installedHash := readPointer(t, controlLog)

	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte("name: platform-admin\nallowed_groups: [finance]\ncontrol: [apply, enable, disable, repair]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	proposed, err := config.HashDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "mallory@example.com", "--groups", "finance"}, &out)
	if code != 1 || !strings.Contains(out.String(), "apply: not authorized: no role grants apply to the invoker") {
		t.Fatalf("self-grant must be refused: exit %d\n%s", code, out.String())
	}
	if got := readPointer(t, controlLog); got != installedHash {
		t.Fatalf("pointer moved on a refused apply: %q -> %q", installedHash, got)
	}
	if _, err := os.Stat(snapshotHashDir(installedStore(controlLog), proposed)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused config must not be snapshotted (err=%v)", err)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"outcome":"refused"`) || !strings.Contains(string(data), `"config_hash":"`+proposed+`"`) {
		t.Fatalf("refusal must carry the proposed hash:\n%s", data)
	}
	if strings.Count(string(data), `"outcome":"success"`) != 1 {
		t.Fatalf("exactly one success (the bootstrap) expected:\n%s", data)
	}
}

// TestApplyAuthorizedReapplyFlipsPointerAndIdenticalIsNoOp: an authorized
// re-apply of changed bytes installs a second snapshot and flips the pointer;
// re-applying identical bytes records a success but adds no snapshot and
// leaves no staging residue; only the first apply is a bootstrap.
func TestApplyAuthorizedReapplyFlipsPointerAndIdenticalIsNoOp(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	args := []string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}
	var out bytes.Buffer
	if code := cmdApply(args, &out); code != 0 {
		t.Fatalf("bootstrap: %d\n%s", code, out.String())
	}
	first := readPointer(t, controlLog)
	if err := os.WriteFile(filepath.Join(root, "agents", "planner.yaml"), []byte("name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := cmdApply(args, &out); code != 0 {
		t.Fatalf("re-apply: %d\n%s", code, out.String())
	}
	second := readPointer(t, controlLog)
	if second == first {
		t.Fatal("pointer must flip to the new snapshot")
	}
	out.Reset()
	if code := cmdApply(args, &out); code != 0 {
		t.Fatalf("identical re-apply: %d\n%s", code, out.String())
	}
	if got := readPointer(t, controlLog); got != second {
		t.Fatalf("identical re-apply moved the pointer: %q", got)
	}
	ents, err := os.ReadDir(installedStore(controlLog))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if len(names) != 3 { // two snapshots + current
		t.Fatalf("store must hold two snapshots and the pointer, got %v", names)
	}
	for _, n := range names {
		if strings.HasPrefix(n, ".") {
			t.Fatalf("staging residue left in the store: %v", names)
		}
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"outcome":"success"`) != 3 || strings.Count(string(data), `"bootstrap":true`) != 1 {
		t.Fatalf("want 3 successes of which 1 bootstrap:\n%s", data)
	}
}

// TestApplyNoApplyFloorRejected: a configuration that grants apply to no role
// is rejected at apply (no-apply-floor) and nothing is installed — it would
// otherwise be the last configuration this control root could ever accept.
func TestApplyNoApplyFloorRejected(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte("name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [enable, disable, repair]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 1 || !strings.Contains(out.String(), "roles: (config): no role grants apply") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "registry ok") {
		t.Fatalf("must not report success: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(installedStore(controlLog), config.InstalledPointer)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing may be installed (err=%v)", err)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := config.HashDir(root)
	for _, want := range []string{`"outcome":"rejected"`, `"validation_failed"`, `"config_hash":"` + h + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("control log missing %q:\n%s", want, data)
		}
	}
}

// TestApplyInstallThenRecordGapPrintsAndExitsNonzero: the crash hook fires
// after the snapshot is installed and the pointer flipped, before the
// success append — the documented residual: print the analogue message,
// exit nonzero, leave the install in place, record nothing.
func TestApplyInstallThenRecordGapPrintsAndExitsNonzero(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	args := []string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}
	var out bytes.Buffer
	if code := cmdApply(args, &out); code != 0 {
		t.Fatalf("bootstrap: %d\n%s", code, out.String())
	}
	if err := os.WriteFile(filepath.Join(root, "agents", "planner.yaml"), []byte("name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	out.Reset()
	code := cmdApply(args, &out)
	if code == 0 || !strings.Contains(out.String(), msgInstalledNotRecorded) {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	h, _ := config.HashDir(root)
	if got := readPointer(t, controlLog); got != h {
		t.Fatalf("the install must have landed before the simulated crash: pointer=%q want %q", got, h)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(strings.TrimRight(string(data), "\n"), "\n")); n != 1 {
		t.Fatalf("only the bootstrap may be recorded, got %d records:\n%s", n, data)
	}
}

// TestApplyMalformedPointerFailsClosed: a damaged pointer never re-opens the
// bootstrap permit — apply records error/io_error, installs nothing, and
// names the escape hatch.
func TestApplyMalformedPointerFailsClosed(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	store := installedStore(controlLog)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, config.InstalledPointer), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 1 || !strings.Contains(out.String(), "refusing to apply (remove "+filepath.Join(store, config.InstalledPointer)+" to re-bootstrap)") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if got := readPointer(t, controlLog); got != "garbage" {
		t.Fatalf("pointer must be untouched: %q", got)
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"outcome":"error"`) || !strings.Contains(string(data), `"io_error"`) || strings.Contains(string(data), `"success"`) {
		t.Fatalf("want a recorded error, no success:\n%s", data)
	}
}

// TestApplyStoreUnwritableRecordsIOErrorInstallsNothing: the store path is
// occupied by a file. Reading the pointer under it fails with ENOTDIR (not
// "does not exist"), so apply takes the fail-closed installed-config branch
// — recorded as error/io_error with no config_hash, exit 1, nothing
// installed. A store that exists but cannot be written takes the
// StageSnapshot branch to the same recorded outcome.
func TestApplyStoreUnwritableRecordsIOErrorInstallsNothing(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	if err := os.WriteFile(installedStore(controlLog), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 1 || strings.Contains(out.String(), "registry ok") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	data, err := os.ReadFile(controlLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"outcome":"error"`) || !strings.Contains(string(data), `"io_error"`) || strings.Contains(string(data), `"config_hash"`) {
		t.Fatalf("want a hash-less recorded io_error:\n%s", data)
	}
}
