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

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// vouchAs runs config vouch as dana (platform-eng) and fatals on exit != 0.
func vouchAs(t *testing.T, ctl string) {
	t.Helper()
	var out bytes.Buffer
	if code := cmdConfigVouch([]string{"--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("config vouch: exit %d\n%s", code, out.String())
	}
}

func vouchCode(t *testing.T, ctl string, extra ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdConfigVouch(append([]string{"--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, extra...), &out)
	return code, out.String()
}

// crashGap applies root under ctl with the install→record crash hook: the
// pointer moves to the new snapshot, nothing is recorded. Returns the new hash.
func crashGap(t *testing.T, root, ctl string) string {
	t.Helper()
	// Keep the planner's live endpoint so the HEALED configuration still
	// runs (test 24 re-runs after the vouch); change only the instruction so
	// the pointer moves to a new snapshot.
	prev, err := os.ReadFile(filepath.Join(root, "agents", "planner.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ep string
	for _, line := range strings.Split(string(prev), "\n") {
		if strings.HasPrefix(line, "endpoint:") {
			ep = line + "\n"
		}
	}
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\n"+ep)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	_, _ = applyCode(t, root, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	return readPointer(t, ctl)
}

// TestConfigVouchHealsAnApplyCrashGap (spec test 24): run refused not on
// record; config vouch → exit 0, a vouch/success row naming the pointer with
// the superseded install in detail and the three identities; audit verify
// control exit 0 "(vouch)"; run executes; pull version = the vouch's seq.
func TestConfigVouchHealsAnApplyCrashGap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	old := readPointer(t, ctl)
	hash := crashGap(t, root, ctl)
	if hash == old {
		t.Fatal("fixture: the pointer must have moved")
	}
	if code, out := runFixBug(t, root, ctl); code != 1 || !strings.Contains(out, "configuration not on record") {
		t.Fatalf("before the heal the run must refuse: %d\n%s", code, out)
	}
	code, out := vouchCode(t, ctl, "--as", "ops@example.com", "--groups", "nobody")
	if code != 0 || !strings.Contains(out, "vouched: "+hash+"\n") || !strings.Contains(out, "control head: seq=2 ") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	e := lastControlEvent(t, ctl)
	if e.Action != "vouch" || e.Outcome != "success" || e.ConfigHash != hash || e.Reason != nil || e.Bootstrap ||
		e.Detail != "previously on record: "+old+", apply" || e.Invoker.Subject != "ops@example.com" || e.AssertedAs != "" || e.Witness.Hostname == "" {
		t.Fatalf("%+v", e)
	}
	var audit bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", ctl}, &audit); code != 0 || !strings.Contains(audit.String(), "installed config: "+hash+" — matches the last recorded install (vouch)") {
		t.Fatalf("audit verify control: %d\n%s", code, audit.String())
	}
	if code, out := runFixBug(t, root, ctl); code != 0 {
		t.Fatalf("after the heal the run executes: %d\n%s", code, out)
	}
	if p := pullAPI(t, ctl, opsInvoker); p.Kind != pulled || p.Snapshot.Version != 2 || p.Snapshot.Hash != hash {
		t.Fatalf("pull: %d %+v", p.Kind, p.Snapshot)
	}
}

// TestConfigVouchRefusesAByteCorruptPointer (test 26): bytes that do not hash
// as the pointer are never blessed — exit 1, the mismatch text and the rm
// current hatch, recorded vouch/error/io_error hash-less, pointer untouched.
func TestConfigVouchRefusesAByteCorruptPointer(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	hash := crashGap(t, root, ctl)
	store := installedStore(ctl)
	writeFileIn(t, config.SnapshotDir(store, hash), "roles/ops.yaml", "name: platform-admin\nallowed_groups: [finance]\ncontrol: [apply]\n")
	code, out := vouchCode(t, ctl)
	if code != 1 || !strings.Contains(out, "installed config "+hash+": snapshot hashes as ") || !strings.Contains(out, installedHatch("config vouch", "vouch", store)) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	e := lastControlEvent(t, ctl)
	if e.Action != "vouch" || e.Outcome != "error" || e.Reason == nil || e.Reason.Code != control.CodeIOError || e.ConfigHash != "" {
		t.Fatalf("%+v", e)
	}
	if readPointer(t, ctl) != hash {
		t.Fatal("the pointer must not move")
	}
	for _, ev := range controlEvents(t, ctl) {
		if ev.Action == "vouch" && ev.Outcome == "success" {
			t.Fatal("corrupt bytes must never be vouched")
		}
	}
}

// TestConfigVouchAlreadyOnRecordIsIdempotent (test 27, OQ5 ruled): a vouched
// pointer → exit 0, a clear line, nothing appended; twice is a no-op.
func TestConfigVouchAlreadyOnRecordIsIdempotent(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	hash := readPointer(t, ctl)
	before := ledgerBytes(t, ctl)
	for i := 0; i < 2; i++ {
		code, out := vouchCode(t, ctl)
		if code != 0 || out != "config vouch: "+hash+" is already on record (apply, version 1); nothing to do\n" {
			t.Fatalf("run %d: exit %d %q", i, code, out)
		}
	}
	if !bytes.Equal(before, ledgerBytes(t, ctl)) {
		t.Fatal("already on record appends nothing")
	}
}

// TestConfigVouchNothingInstalled (test 28): exit 1, a clear line, no record.
func TestConfigVouchNothingInstalled(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	code, out := vouchCode(t, ctl)
	if code != 1 || out != "config vouch: nothing is installed under "+installedStore(ctl)+"; nothing to vouch for\n" {
		t.Fatalf("exit %d %q", code, out)
	}
	if _, err := os.Stat(ctl); err == nil {
		if recs, _, _ := ledger.ReadVerify(ctl, ledger.Locked); len(recs) != 0 {
			t.Fatal("nothing installed records nothing")
		}
	}
}

// TestConfigVouchRefusesALockoutFloor (test 29, M1): three correctly hashed,
// hand-aimed snapshots whose roles could never authorize an apply → exit 1,
// recorded vouch/rejected/validation_failed with the pointer hash, not
// vouched; rm current escapes.
func TestConfigVouchRefusesALockoutFloor(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	for name, roles := range map[string]string{
		"apply granted to no role": "name: ops\nallowed_groups: [platform-eng]\ncontrol: [enable]\n",
		"no groups":                "name: ops\nallowed_groups: []\ncontrol: [apply]\n",
		"public marker only":       "name: ops\nallowed_groups: [\"*\"]\ncontrol: [apply]\n",
	} {
		t.Run(name, func(t *testing.T) {
			ctl := filepath.Join(t.TempDir(), "control.jsonl")
			hash := installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": roles})
			code, out := vouchCode(t, ctl)
			if code != 1 || !strings.Contains(out, "no role grants apply to a named group") {
				t.Fatalf("exit %d\n%s", code, out)
			}
			e := lastControlEvent(t, ctl)
			if e.Action != "vouch" || e.Outcome != "rejected" || e.Reason == nil || e.Reason.Code != control.CodeValidationFailed || e.ConfigHash != hash || !strings.Contains(e.Reason.Message, "no role grants apply to a named group") {
				t.Fatalf("%+v", e)
			}
			if _, mismatch := installedPointerLine(ctl, mustRecords(t, ctl)); !mismatch {
				t.Fatal("a rejected vouch must not vouch")
			}
			if err := os.Remove(filepath.Join(installedStore(ctl), config.InstalledPointer)); err != nil {
				t.Fatal(err)
			}
			if code, out := vouchCode(t, ctl); code != 1 || !strings.Contains(out, "nothing to vouch for") {
				t.Fatalf("after rm current: %d\n%s", code, out)
			}
		})
	}
}

// TestConfigVouchAnyIdentityIsRecorded (test 30): an identity no role names
// vouches a legitimate gap and is recorded as the invoker with the host's
// witness; a token that fails verification is refused and recorded.
func TestConfigVouchAnyIdentityIsRecorded(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	hash := crashGap(t, root, ctl)
	var out bytes.Buffer
	if code := cmdConfigVouch([]string{"--control-log", ctl, "--as", "outsider", "--groups", "nobody"}, &out); code != 0 {
		t.Fatalf("%d\n%s", code, out.String())
	}
	e := lastControlEvent(t, ctl)
	if e.Invoker.Subject != "outsider" || e.Invoker.Method != "asserted" || e.ConfigHash != hash || e.Witness.OSUser == "" {
		t.Fatalf("%+v", e)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := cmdTestOIDCServer(t, key)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := cmdMintToken(t, otherKey, map[string]any{"iss": issuer.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	t.Setenv("AGENTHOF_OIDC_ISSUER", issuer.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	crashGap(t, root, ctl)
	out.Reset()
	if code := cmdConfigVouch([]string{"--control-log", ctl, "--token", bad}, &out); code != 1 || !strings.Contains(out.String(), "config vouch: token authentication failed:") {
		t.Fatalf("%d\n%s", code, out.String())
	}
	if e := lastControlEvent(t, ctl); e.Action != "vouch" || e.Outcome != "refused" || e.Reason == nil || e.Reason.Code != control.CodeTokenVerificationFailed || e.Reason.Message != "token verification failed" || e.ConfigHash != "" {
		t.Fatalf("%+v", e)
	}
}

// TestConfigVouchSignsWhenConfigured (test 32): the vouch's record is what
// gets signed; the pull serves 200 with it; config sign afterwards is
// "already signed".
func TestConfigVouchSignsWhenConfigured(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, id := signedRoot(t)
	hash := crashGap(t, root, ctl)
	code, out := vouchCode(t, ctl)
	if code != 0 || !strings.Contains(out, "signed: key_id "+id+"\n") {
		t.Fatalf("%d\n%s", code, out)
	}
	f := readSig(t, ctl)
	if f.Hash != hash || f.Version != lastControlEvent(t, ctl).Seq || !config.Verify(signingPub(t, ctl), f.Payload, f.Sig) {
		t.Fatalf("%+v", f)
	}
	if p := pullAPI(t, ctl, opsInvoker); p.Kind != pulled || p.Snapshot.Signature == nil {
		t.Fatalf("pull: %d", p.Kind)
	}
	if code, s := signCode(t, ctl); code != 0 || !strings.HasPrefix(s, "already signed: "+hash) {
		t.Fatalf("config sign after vouch: %d %q", code, s)
	}
}

// TestConfigVouchTornLedgerRefusesThenHealsAfterRepair (test 34): a torn
// ledger → exit 1 with the repair hint, unrecorded; after repair → heals.
func TestConfigVouchTornLedgerRefusesThenHealsAfterRepair(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	crashGap(t, root, ctl)
	appendFragment(t, ctl)
	before := ledgerBytes(t, ctl)
	code, out := vouchCode(t, ctl)
	if code != 1 || !strings.Contains(out, "control ledger damaged; run: agenthof audit repair control --control-log "+ctl) {
		t.Fatalf("%d\n%s", code, out)
	}
	if !bytes.Equal(before, ledgerBytes(t, ctl)) {
		t.Fatal("a torn ledger records nothing")
	}
	repairAs(t, root, ctl)
	vouchAs(t, ctl)
	if _, mismatch := installedPointerLine(ctl, mustRecords(t, ctl)); mismatch {
		t.Fatal("after repair the vouch heals")
	}
}

// TestConfigVouchBusyUnderAHeldWriterLock (test 35): installed.lock held
// elsewhere → busy, exit 1, unrecorded. Waits the real lock timeout.
func TestConfigVouchBusyUnderAHeldWriterLock(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	crashGap(t, root, ctl)
	unlock, err := ledger.LockFile(installedLock(ctl))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	before := ledgerBytes(t, ctl)
	if code, out := vouchCode(t, ctl); code != 1 || out != "config vouch: "+msgLockBusy+"\n" {
		t.Fatalf("%d %q", code, out)
	}
	if !bytes.Equal(before, ledgerBytes(t, ctl)) {
		t.Fatal("busy records nothing")
	}
}
