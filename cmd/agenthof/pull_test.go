package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// edgeInvoker belongs to the group the pull-only role names; opsInvoker to
// the group writeSample's platform-admin role (apply, no pull) names;
// outsider to a group no role names.
var (
	edgeInvoker = identity.Invoker{Subject: "edge@example.com", Issuer: "https://idp.test", Method: "oidc", Groups: []string{"execution-points"}}
	opsInvoker  = identity.Invoker{Subject: "dana@example.com", Issuer: "https://idp.test", Method: "oidc", Groups: []string{"platform-eng"}}
	outsider    = identity.Invoker{Subject: "mallory@example.com", Issuer: "https://idp.test", Method: "oidc", Groups: []string{"finance"}}
)

// pullSample is writeSample plus a pull-only role and a provision/prune-only
// role, so every authorization branch has a fixture.
func pullSample(t *testing.T) string {
	t.Helper()
	root := writeSample(t)
	writeFileIn(t, root, "roles/edge.yaml", "name: edge\nallowed_groups: [execution-points]\ncontrol: [pull]\n")
	writeFileIn(t, root, "roles/keys.yaml", "name: keys\nallowed_groups: [key-holders]\ncontrol: [provision, prune]\n")
	return root
}

// applyAs is a CLI apply of root under ctl as dana (platform-eng).
func applyAs(t *testing.T, root, ctl string) {
	t.Helper()
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out.String())
	}
}

// pullFacts reads the two facts the availability rule is defined over: the
// chain verdict (a missing ledger file is an accepted, empty chain) and the
// pointer line's mismatch.
func pullFacts(t *testing.T, ctl string) (verr error, mismatch bool) {
	t.Helper()
	recs, _, verr := ledger.ReadVerify(ctl, ledger.Locked)
	if errors.Is(verr, fs.ErrNotExist) {
		verr, recs = nil, nil
	}
	if verr != nil {
		return verr, true
	}
	_, mismatch = installedPointerLine(ctl, recs)
	return nil, mismatch
}

// ledgerBytes returns the ledger's bytes, or nil when there is no file.
func ledgerBytes(t *testing.T, ctl string) []byte {
	t.Helper()
	b, err := os.ReadFile(ctl)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

// pullAPI runs the API-path pull and asserts the ledger is byte-identical
// afterwards: no pull outcome writes.
func pullAPI(t *testing.T, ctl string, inv identity.Invoker) pullOutcome {
	t.Helper()
	before := ledgerBytes(t, ctl)
	_, errBefore := os.Stat(ctl)
	out := pullConfig(pullRequest{ControlLog: ctl, Authorize: true, Invoker: inv})
	if after := ledgerBytes(t, ctl); !bytes.Equal(before, after) {
		t.Fatalf("a pull must never write the control ledger (kind %d)", out.Kind)
	}
	// Existence, not just bytes: bytes.Equal(nil, []byte{}) is true, so a pull
	// that created an empty ledger would slip past the byte compare.
	if _, errAfter := os.Stat(ctl); (errBefore == nil) != (errAfter == nil) {
		t.Fatalf("a pull must never create or remove the control ledger (kind %d)", out.Kind)
	}
	return out
}

// appendFragment appends the partial record the repair fixtures are pinned
// to: the apply's own record survives, only a torn tail follows it.
func appendFragment(t *testing.T, ctl string) {
	t.Helper()
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"v":"control/1","seq":2,"partial`)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func repairAs(t *testing.T, root, ctl string) {
	t.Helper()
	var out bytes.Buffer
	if code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "ops@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("repair: exit %d\n%s", code, out.String())
	}
}

func TestPullAllowedIsPullOrApply(t *testing.T) {
	edge := config.RoleDef{Name: "edge", AllowedGroups: []string{"execution-points"}, Control: []string{"pull"}}
	ops := config.RoleDef{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"apply"}}
	keys := config.RoleDef{Name: "keys", AllowedGroups: []string{"key-holders"}, Control: []string{"provision", "prune"}}
	roles := []config.RoleDef{edge, ops, keys}
	if !pullAllowed(roles, edgeInvoker) || !pullAllowed(roles, opsInvoker) {
		t.Fatal("pull and apply must each allow a pull")
	}
	if pullAllowed(roles, identity.Invoker{Subject: "k", Groups: []string{"key-holders"}}) || pullAllowed(roles, outsider) || pullAllowed(roles, identity.Invoker{Subject: "x", Groups: []string{"*"}}) {
		t.Fatal("provision/prune, no membership, and a claimed * must not allow a pull")
	}
	public := config.RoleDef{Name: "open", AllowedGroups: []string{"*"}, Control: []string{"pull", "apply"}}
	if pullAllowed([]config.RoleDef{public}, outsider) {
		t.Fatal("a public role grants no pull")
	}
}

func TestPullConfigOutcomeTable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pullNothingInstalled {
		t.Fatalf("nothing installed: kind %d", out.Kind)
	}
	root := pullSample(t)
	applyAs(t, root, ctl)
	hash := readPointer(t, ctl)
	want, err := config.HashDir(root)
	if err != nil || want != hash {
		t.Fatalf("pointer %q, HashDir %q err %v", hash, want, err)
	}

	edge := pullAPI(t, ctl, edgeInvoker)
	if edge.Kind != pulled || edge.Snapshot.Hash != hash || edge.Snapshot.Version != 1 || edge.Snapshot.InstalledAt.IsZero() {
		t.Fatalf("pull-only role: %+v err %v", edge.Snapshot, edge.Err)
	}
	files := make(map[string][]byte, len(edge.Snapshot.Files))
	for rel, text := range edge.Snapshot.Files {
		files[rel] = []byte(text)
	}
	if got, _ := config.HashFiles(files); got != hash {
		t.Fatalf("served files hash %q, want %q", got, hash)
	}
	if len(edge.Snapshot.Files) != 8 {
		t.Fatalf("files = %d, want writeSample's 6 plus two roles", len(edge.Snapshot.Files))
	}
	if ev := controlEvents(t, ctl); !edge.Snapshot.InstalledAt.Equal(ev[0].Time) {
		t.Fatalf("installed_at must be the installing event's time: %v vs %v", edge.Snapshot.InstalledAt, ev[0].Time)
	}
	if ops := pullAPI(t, ctl, opsInvoker); ops.Kind != pulled || ops.Snapshot.Version != 1 {
		t.Fatalf("apply implies pull: kind %d", ops.Kind)
	}
	if keys := pullAPI(t, ctl, identity.Invoker{Subject: "k@example.com", Groups: []string{"key-holders"}}); keys.Kind != pullRefused {
		t.Fatalf("provision/prune only: kind %d", keys.Kind)
	}
	if out := pullAPI(t, ctl, outsider); out.Kind != pullRefused {
		t.Fatalf("outsider: kind %d", out.Kind)
	}

	// Tampered agent file: the lenient authorization read still decides —
	// an ungranted caller is refused, a granted one gets store-unusable with
	// the mismatch text in Err, and nobody receives the bytes.
	snap := filepath.Join(installedStore(ctl), strings.TrimPrefix(hash, "sha256:"))
	writeFileIn(t, snap, "agents/coder.yaml", "name: coder\nmodel: fast\ninstruction: EVIL\noutput: patch\n")
	if out := pullAPI(t, ctl, outsider); out.Kind != pullRefused {
		t.Fatalf("tampered, ungranted: kind %d", out.Kind)
	}
	out := pullAPI(t, ctl, edgeInvoker)
	if out.Kind != pullStoreUnusable || out.Err == nil || !strings.Contains(out.Err.Error(), "installed config "+hash+": snapshot hashes as ") {
		t.Fatalf("tampered, granted: kind %d err %v", out.Kind, out.Err)
	}
	if out.Snapshot.Files != nil {
		t.Fatal("tampered bytes must never be returned")
	}
}

// TestPullConfigSnapshotGoneIsStoreUnusable: a pointer naming a directory
// that no longer exists is store damage (500), never "retry" and never
// "nothing installed".
func TestPullConfigSnapshotGoneIsStoreUnusable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	applyAs(t, pullSample(t), ctl)
	hash := readPointer(t, ctl)
	if err := os.RemoveAll(filepath.Join(installedStore(ctl), strings.TrimPrefix(hash, "sha256:"))); err != nil {
		t.Fatal(err)
	}
	out := pullAPI(t, ctl, opsInvoker)
	if out.Kind != pullStoreUnusable || out.Err == nil || !strings.Contains(out.Err.Error(), "installed config "+hash+": ") {
		t.Fatalf("gone snapshot: kind %d err %v", out.Kind, out.Err)
	}
}

// installByHandWithPointer writes files as a snapshot under ctl's store and
// points current at it, with no ledger record — for snapshots apply cannot
// install (a non-UTF-8 file is rejected by the YAML loader at apply).
func installByHandWithPointer(t *testing.T, ctl string, files map[string]string) string {
	t.Helper()
	src := t.TempDir()
	for rel, content := range files {
		writeFileIn(t, src, rel, content)
	}
	hash, err := config.HashDir(src)
	if err != nil {
		t.Fatal(err)
	}
	store := installedStore(ctl)
	snap := filepath.Join(store, strings.TrimPrefix(hash, "sha256:"))
	for rel, content := range files {
		writeFileIn(t, snap, rel, content)
	}
	if err := os.WriteFile(filepath.Join(store, config.InstalledPointer), []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestPullConfigNotBundleable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	// A file name the enumeration lists but a bundle cannot carry: applied
	// locally (a directory apply does not check bundle names).
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	root := pullSample(t)
	writeFileIn(t, root, "roles/"+strings.Repeat("x", 196)+".yaml", "name: long\nallowed_groups: [nobody]\ncontrol: [prune]\n")
	applyAs(t, root, ctl)
	out := pullAPI(t, ctl, opsInvoker)
	if out.Kind != pullNotBundleable || !errors.Is(out.Err, config.ErrNotBundleable) {
		t.Fatalf("long name: kind %d err %v", out.Kind, out.Err)
	}

	// A file that is not valid UTF-8: byte-transparent in the store, refused
	// for distribution before the ledger is even consulted.
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	installByHandWithPointer(t, ctl, map[string]string{
		"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n",
		"gateway.yaml":   "models: {}\n# \xff\xfe\n",
	})
	out = pullAPI(t, ctl, opsInvoker)
	if out.Kind != pullNotBundleable || out.Err == nil || !strings.Contains(out.Err.Error(), "not valid UTF-8") {
		t.Fatalf("non-UTF-8: kind %d err %v", out.Kind, out.Err)
	}
}

// TestPullConfigAvailabilityInvariant pins the rule the pull answers by:
// pulled ⟹ the chain verifies AND the pointer line matches; not-on-record
// ⟺ the chain verifies (a missing ledger file is an empty chain) AND the
// pointer line mismatches; a chain that does not verify ⟹ ledger damaged.
// Each case asserts the kind and those two facts, and nothing else.
func TestPullConfigAvailabilityInvariant(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	check := func(t *testing.T, name, ctl string, want pullKind, wantMismatch bool) pullOutcome {
		t.Helper()
		out := pullAPI(t, ctl, opsInvoker)
		verr, mismatch := pullFacts(t, ctl)
		switch want {
		case pulled:
			if out.Kind != pulled || verr != nil || mismatch {
				t.Fatalf("%s: kind %d verr %v mismatch %v; want pulled on a verified chain with a matching pointer", name, out.Kind, verr, mismatch)
			}
		case pullNotRecorded:
			if out.Kind != pullNotRecorded || verr != nil || !mismatch {
				t.Fatalf("%s: kind %d verr %v mismatch %v; want not-on-record on a verified chain with a mismatching pointer", name, out.Kind, verr, mismatch)
			}
		case pullLedgerDamaged:
			if out.Kind != pullLedgerDamaged || verr == nil {
				t.Fatalf("%s: kind %d verr %v; want ledger-damaged on a chain that does not verify", name, out.Kind, verr)
			}
		}
		if wantMismatch != mismatch && want != pullLedgerDamaged {
			t.Fatalf("%s: mismatch %v, want %v", name, mismatch, wantMismatch)
		}
		return out
	}

	// Pointer present, no ledger file at all: an empty chain that vouches for nothing.
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	check(t, "pointer without a ledger", ctl, pullNotRecorded, true)

	// The install→record gap: the crash hook leaves the pointer moved and
	// nothing appended; a re-apply records the install and clears it.
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	root := pullSample(t)
	applyAs(t, root, ctl)
	check(t, "recorded apply", ctl, pulled, false)
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	var buf bytes.Buffer
	_ = cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	check(t, "install not recorded", ctl, pullNotRecorded, true)
	applyAs(t, root, ctl)
	if out := check(t, "re-apply records it", ctl, pulled, false); out.Snapshot.Version != 2 || out.Snapshot.Hash != readPointer(t, ctl) {
		t.Fatalf("re-apply: %+v", out.Snapshot)
	}

	// A pointer re-aimed by hand at an older, correctly named snapshot: the
	// ledger's last install is not that one.
	older := controlEvents(t, ctl)[0].ConfigHash
	if err := os.WriteFile(filepath.Join(installedStore(ctl), config.InstalledPointer), []byte(older+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(t, "pointer re-aimed at an older snapshot", ctl, pullNotRecorded, true)

	// An unrepaired torn tail: the valid prefix would match, and still never vouches.
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	root = pullSample(t)
	applyAs(t, root, ctl)
	appendFragment(t, ctl)
	if recs, _, _ := ledger.ReadVerify(ctl, ledger.Locked); len(recs) != 1 {
		t.Fatalf("the apply's record must survive the fragment: %d records", len(recs))
	} else if _, mismatch := installedPointerLine(ctl, recs); mismatch {
		t.Fatal("fixture: the valid prefix must match the pointer, or this proves nothing")
	}
	out := check(t, "torn tail, unrepaired", ctl, pullLedgerDamaged, true)
	var te *ledger.TornError
	if !errors.As(out.Err, &te) {
		t.Fatalf("Err must carry the torn verdict: %v", out.Err)
	}

	// Fixture A — a repaired ledger still vouches: apply (seq 1), fragment,
	// repair (seq 2), pull → pulled with version 1.
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	root = pullSample(t)
	applyAs(t, root, ctl)
	appendFragment(t, ctl)
	repairAs(t, root, ctl)
	if out := check(t, "fixture A: repaired ledger", ctl, pulled, false); out.Snapshot.Version != 1 {
		t.Fatalf("fixture A: version %d, want 1 (the apply, not the repair)", out.Snapshot.Version)
	}
	if tainted, _ := control.IsTainted(mustRecords(t, ctl)); !tainted {
		t.Fatal("fixture A must be tainted, or it proves nothing")
	}

	// Fixture B — taint and mismatch together: apply A (seq 1), crash-hook
	// apply B (pointer → B, nothing appended), fragment, repair (seq 2),
	// pull → not on record: the chain is clean and tainted and the last
	// install is A.
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	root = pullSample(t)
	applyAs(t, root, ctl)
	hashA := readPointer(t, ctl)
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan B\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	buf.Reset()
	_ = cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if readPointer(t, ctl) == hashA {
		t.Fatal("fixture B: the pointer must have moved to B")
	}
	appendFragment(t, ctl)
	repairAs(t, root, ctl)
	check(t, "fixture B: tainted and not on record", ctl, pullNotRecorded, true)
	if last, ok := control.LastInstalling(mustRecords(t, ctl)); !ok || last.ConfigHash != hashA {
		t.Fatalf("fixture B: the last install must still be A: ok=%v %+v", ok, last)
	}
}

// TestPullConfigVersionFollowsEveryInstall: an identical re-apply advances
// version and keeps the hash; a kill-switch flip is the install, so version
// is the flip's seq, installed_at its time, hash the flip's pointer.
func TestPullConfigVersionFollowsEveryInstall(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	root := pullSample(t)
	applyAs(t, root, ctl)
	first := pullAPI(t, ctl, opsInvoker)
	applyAs(t, root, ctl)
	second := pullAPI(t, ctl, opsInvoker)
	if first.Kind != pulled || second.Kind != pulled || second.Snapshot.Version != 2 || second.Snapshot.Hash != first.Snapshot.Hash {
		t.Fatalf("identical re-apply: %+v then %+v", first.Snapshot, second.Snapshot)
	}
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: exit %d\n%s", code, out.String())
	}
	flip := pullAPI(t, ctl, opsInvoker)
	ev := controlEvents(t, ctl)
	if flip.Kind != pulled || flip.Snapshot.Version != 3 || flip.Snapshot.Hash != readPointer(t, ctl) || flip.Snapshot.Hash == first.Snapshot.Hash || !flip.Snapshot.InstalledAt.Equal(ev[2].Time) {
		t.Fatalf("after a flip: %+v (events %d)", flip.Snapshot, len(ev))
	}
}

// TestPullConfigBusyWhenTheLedgerLockIsHeld: a writer holding the ledger's
// exclusive flock past the retry makes the pull busy — nothing else set,
// nothing written. Waits the real lockTimeout; t.Parallel, so it runs only
// after every sequential t.Setenv test has returned — the apply path reads
// AGENTHOF_TEST_CRASH_AT (set by some of those), which a parallel test must
// not race.
func TestPullConfigBusyWhenTheLedgerLockIsHeld(t *testing.T) {
	t.Parallel()
	h, ctl, _ := newConfigHost(t, true)
	if res := h.Apply(apiInvoker, sampleBundle(t), apiclient.Precondition{ExpectNone: true}, apiVia()); res.Status != apiclient.ApplyInstalled {
		t.Fatalf("%+v", res)
	}
	holdLock(t, "ledger", ctl, 9000)
	out := pullConfig(pullRequest{ControlLog: ctl, Authorize: true, Invoker: apiInvoker})
	if out.Kind != pullBusy || !errors.Is(out.Err, ledger.ErrLockHeld) || out.Snapshot.Hash != "" {
		t.Fatalf("busy: kind %d err %v snapshot %+v", out.Kind, out.Err, out.Snapshot)
	}
}

func TestPullConfigLocalModeReadsWithoutIdentity(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if out := pullConfig(pullRequest{ControlLog: ctl}); out.Kind != pullNothingInstalled {
		t.Fatalf("nothing installed: kind %d", out.Kind)
	}
	applyAs(t, pullSample(t), ctl)
	out := pullConfig(pullRequest{ControlLog: ctl})
	if out.Kind != pulled || out.Snapshot.Hash != readPointer(t, ctl) || out.Snapshot.Version != 1 {
		t.Fatalf("local: kind %d %+v", out.Kind, out.Snapshot)
	}
}

// TestPullSourceNeverRecordsOrLocks pins by source that the pull path has no
// control-ledger write and takes no writer lock.
func TestPullSourceNeverRecordsOrLocks(t *testing.T) {
	src, err := os.ReadFile("pull.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"control.Append", "ledger.LockFile", "installedLock(", "ledger.Open("} {
		if strings.Contains(string(src), forbidden) {
			t.Fatalf("pull.go must not contain %q: a pull is a read", forbidden)
		}
	}
}
