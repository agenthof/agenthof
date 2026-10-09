package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/ledger"
)

// goldenPubPEM is the public half of a pair this host does NOT hold: a
// signing.pub from "another pair" for the mismatch cases.
const goldenPubPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n"

// goldenKeyID is that key's id.
const goldenKeyID = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"

// readSig parses installed/<hex>.sig for ctl's current pointer.
func readSig(t *testing.T, ctl string) config.SignatureFile {
	t.Helper()
	f, err := config.ParseSignatureFile(mustRead(t, config.SignaturePath(installedStore(ctl), readPointer(t, ctl))))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func noSig(t *testing.T, ctl string) {
	t.Helper()
	if _, err := os.Stat(config.SignaturePath(installedStore(ctl), readPointer(t, ctl))); !os.IsNotExist(err) {
		t.Fatalf("no .sig may exist for the pointer: %v", err)
	}
}

func applyCode(t *testing.T, root, ctl string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	return code, out.String()
}

// TestApplyUnsignedWhenNoKey: state A is exactly the unsigned install —
// no .sig, no key id, the store listing unchanged (the "two snapshots +
// current" check in apply_control_test.go stays green).
func TestApplyUnsignedWhenNoKey(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	res := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(root), AllowBootstrap: true}, &out)
	if res.Kind != applyInstalled || res.KeyID != "" || strings.Contains(out.String(), "signed") {
		t.Fatalf("%+v\n%s", res, out.String())
	}
	noSig(t, ctl)
	noStagingResidue(t, ctl)
}

// TestApplySignsWhenConfigured: with the pair in place an apply writes a
// .sig that verifies under signing.pub, binds the ledger's log_id and the
// install's seq, renders installed_at exactly as the ledger's time encodes
// to JSON, prints the key id, and an identical re-apply rewrites it for
// the new seq.
func TestApplySignsWhenConfigured(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	code, out := applyCode(t, root, ctl)
	if code != 0 || !strings.HasSuffix(out, "control head: seq=1 sha256="+mustRecordsHead(t, ctl)+"\nsigned: key_id "+id+"\n") {
		t.Fatalf("%d\n%s", code, out)
	}
	f := readSig(t, ctl)
	ev := controlEvents(t, ctl)
	if f.Hash != readPointer(t, ctl) || f.Version != 1 || f.KeyID != id || f.LogID != controlLogID(t, ctl) {
		t.Fatalf("%+v", f)
	}
	if j, _ := json.Marshal(ev[0].Time.UTC()); f.InstalledAt != strings.Trim(string(j), `"`) {
		t.Fatalf("installed_at %q must be the ledger time's JSON rendering %s", f.InstalledAt, j)
	}
	if !config.Verify(signingPub(t, ctl), f.Payload, f.Sig) {
		t.Fatal("the .sig must verify under signing.pub")
	}
	noStagingResidue(t, ctl)

	first := mustRead(t, config.SignaturePath(installedStore(ctl), f.Hash))
	if code, _ := applyCode(t, root, ctl); code != 0 {
		t.Fatalf("identical re-apply: %d", code)
	}
	again := readSig(t, ctl)
	if again.Version != 2 || again.Hash != f.Hash || bytes.Equal(first, mustRead(t, config.SignaturePath(installedStore(ctl), f.Hash))) {
		t.Fatalf("an identical re-apply must rewrite the .sig for seq 2: %+v", again)
	}
	var buf bytes.Buffer
	res := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(root), AllowBootstrap: true}, &buf)
	if res.Kind != applyInstalled || res.KeyID != id || res.SignCause != nil {
		t.Fatalf("%+v", res)
	}
	names := mustReadDirNames(t, installedStore(ctl))
	if len(names) != 3 { // one snapshot, its .sig, current
		t.Fatalf("store: %v", names)
	}
}

// mustRecordsHead is the control head hash after the last append.
func mustRecordsHead(t *testing.T, ctl string) string {
	t.Helper()
	_, head, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	return head.Hash
}

// TestApplyNotSignedWhenPrivateKeyMissing (state B): the install lands and
// is recorded; only the signature is missing — exit 1, the cause and the
// remedy printed, no .sig.
func TestApplyNotSignedWhenPrivateKeyMissing(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	if err := os.Remove(signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	code, out := applyCode(t, root, ctl)
	if code != 1 || !strings.Contains(out, "registry ok: 2 agents, 1 workflows, 4 roles\n") || !strings.Contains(out, "control head: seq=1 ") ||
		!strings.HasSuffix(out, msgInstalledNotSigned+": signing.key missing; run: agenthof config sign --control-log "+ctl+"\n") {
		t.Fatalf("%d\n%s", code, out)
	}
	if e := lastControlEvent(t, ctl); e.Action != "apply" || e.Outcome != "success" || e.ConfigHash != readPointer(t, ctl) {
		t.Fatalf("the install must be recorded: %+v", e)
	}
	noSig(t, ctl)
	noStagingResidue(t, ctl)
}

// TestApplyNotSignedWhenPublicFileMissing (state C): configured and broken,
// never a silent unsigned install; the remedy is config keygen.
func TestApplyNotSignedWhenPublicFileMissing(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	if err := os.Remove(signingPubPath(ctl)); err != nil {
		t.Fatal(err)
	}
	code, out := applyCode(t, root, ctl)
	if code != 1 || !strings.HasSuffix(out, msgInstalledNotSigned+": signing.pub missing; run: agenthof config keygen --control-log "+ctl+"\n") {
		t.Fatalf("%d\n%s", code, out)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "success" {
		t.Fatalf("%+v", e)
	}
	noSig(t, ctl)
}

// TestApplyNotSignedOnKeyMismatch: signing.pub from another pair — the
// message names both ids and nothing is written (a .sig the pull could
// never verify must not exist).
func TestApplyNotSignedOnKeyMismatch(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	if err := os.WriteFile(signingPubPath(ctl), []byte(goldenPubPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := applyCode(t, root, ctl)
	if code != 1 || !strings.Contains(out, msgInstalledNotSigned+": "+signingKeyPath(ctl)+" (key_id "+id+") is not the private key of "+signingPubPath(ctl)+" (key_id "+goldenKeyID+"); run: agenthof config sign") {
		t.Fatalf("%d\n%s", code, out)
	}
	noSig(t, ctl)
}

// TestApplyCrashHookAfterRecordBeforeSign: the install→record→sign gap,
// exercisable like the install→record gap: recorded, not signed, exit 1.
func TestApplyCrashHookAfterRecordBeforeSign(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_record_before_sign")
	code, out := applyCode(t, root, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code != 1 || !strings.Contains(out, "control head: seq=1 ") || !strings.Contains(out, msgInstalledNotSigned+": ") {
		t.Fatalf("%d\n%s", code, out)
	}
	if e := lastControlEvent(t, ctl); e.Outcome != "success" {
		t.Fatalf("%+v", e)
	}
	noSig(t, ctl)

	// In state A the hook is inert: there is no sign step to crash before.
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_record_before_sign")
	code, out = applyCode(t, root, ctl2)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code != 0 || strings.Contains(out, "signature") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// TestApplyUnrecordedIsNeverRelabelledNotSigned: with a key configured, the
// install→record gap stays installed_not_recorded — there is no (version,
// time) to sign — and no .sig is written.
func TestApplyUnrecordedIsNeverRelabelledNotSigned(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	var out bytes.Buffer
	res := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(root), AllowBootstrap: true}, &out)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if res.Kind != applyInstalledNotRecorded || strings.Contains(out.String(), "signature") {
		t.Fatalf("%+v\n%s", res, out.String())
	}
	noSig(t, ctl)
}

// TestBuildSignatureClassifies: the sign core's own verdicts, without an
// installer around it.
func TestBuildSignatureClassifies(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if _, err := buildSignature(ctl); !errors.Is(err, errSigningOff) {
		t.Fatalf("state A: %v", err)
	}
	keygenAt(t, ctl)
	if _, err := buildSignature(ctl); !errors.Is(err, errNothingInstalled) {
		t.Fatalf("nothing installed: %v", err)
	}
	installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	if _, err := buildSignature(ctl); !errors.Is(err, errNotOnRecord) {
		t.Fatalf("pointer without a ledger: %v", err)
	}
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	applyAs(t, pullSample(t), ctl)
	info, err := buildSignature(ctl)
	if err != nil || info.Version != 1 || info.Hash != readPointer(t, ctl) || len(info.Sig) != 88 {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := os.Stat(config.SignaturePath(installedStore(ctl), info.Hash)); err != nil {
		t.Fatal("the apply already wrote the .sig; buildSignature must not have removed it")
	}
	appendFragment(t, ctl)
	if _, err := buildSignature(ctl); !errors.Is(err, errLedgerDamaged) {
		t.Fatalf("torn: %v", err)
	}
}

// TestSigningSourceNeverRecords pins by source that the sign path writes no
// control event.
func TestSigningSourceNeverRecords(t *testing.T) {
	src, err := os.ReadFile("signing.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "control.Append") {
		t.Fatal("signing.go must not contain control.Append: signing is a derivation, not a control event")
	}
}
