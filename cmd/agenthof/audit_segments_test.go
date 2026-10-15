package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/investigate"
)

// withHistory plants a manifest beside ctl and removes the active: a root
// with history and no active — FaultActiveMissing, never "nothing recorded".
func withHistory(t *testing.T, ctl string) {
	t.Helper()
	m := `{"v":"segments/1","log_id":"` + strings.Repeat("ab", 16) + `","segments":[]}`
	if err := os.WriteFile(control.ManifestPath(ctl), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
}

// TestActiveMissingWithHistoryIsNotNotExist: audit control, audit verify
// control and audit repair control print the FaultActiveMissing text and
// exit 1 — never "nothing recorded yet" — and vouchInstalled reports
// not-verifiable, never "no install on record".
func TestActiveMissingWithHistoryIsNotNotExist(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	withHistory(t, ctl)
	for _, args := range [][]string{
		{"control", "--control-log", ctl},
		{"verify", "control", "--control-log", ctl},
		{"repair", "control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"},
	} {
		var out bytes.Buffer
		code := cmdAudit(args, &out)
		if code != 1 || strings.Contains(out.String(), "nothing recorded yet") || !strings.Contains(out.String(), "control ledger active segment missing") {
			t.Fatalf("%v: exit %d\n%s", args, code, out.String())
		}
	}
	_, _, refusal := vouchInstalled(ctl, readPointer(t, ctl))
	if refusal == nil || refusal.Kind != verifyNotVerifiable || strings.Contains(refusal.Error(), "no install on record") || strings.Contains(refusal.Error(), "audit repair control") {
		t.Fatalf("vouchInstalled: %v", refusal)
	}
	if _, err := os.Lstat(ctl); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no reader may recreate the active")
	}
}

// TestVouchInstalledOnASetFault: a sealed-segment or structural fault is
// not-verifiable with the seam's text and no repair hint; a torn active
// keeps today's repair hint.
func TestVouchInstalledOnASetFault(t *testing.T) {
	ctl := applied(t, writeSample(t))
	if err := os.WriteFile(control.SegmentPath(ctl, 3), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, refusal := vouchInstalled(ctl, readPointer(t, ctl))
	if refusal == nil || refusal.Kind != verifyNotVerifiable || !strings.Contains(refusal.Error(), "but no manifest") || strings.Contains(refusal.Error(), "audit repair control") {
		t.Fatalf("set fault: %v", refusal)
	}
	_ = os.Remove(control.SegmentPath(ctl, 3))
	tearTail(t, ctl)
	_, _, refusal = vouchInstalled(ctl, readPointer(t, ctl))
	if refusal == nil || !strings.Contains(refusal.Error(), "run: agenthof audit repair control") {
		t.Fatalf("torn active: %v", refusal)
	}
}

// TestWritablePrechecksClassify: busy, torn (the repair hint, with --config
// where the command has one), and a structural fault (its own text) at
// apply's and the shared precheck.
func TestWritablePrechecksClassify(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	if err := os.WriteFile(control.SegmentPath(ctl, 1), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || !strings.Contains(out.String(), "but no manifest") || strings.Contains(out.String(), "audit repair control") {
		t.Fatalf("apply on a set fault: %d\n%s", code, out.String())
	}
	out.Reset()
	if ok := controlLedgerWritable("runs prune", ctl, &out); ok || !strings.Contains(out.String(), "runs prune: control ledger has segment files") {
		t.Fatalf("precheck: %v %s", ok, out.String())
	}
	_ = os.Remove(control.SegmentPath(ctl, 1))
	tearTail(t, ctl)
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || out.String() != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl+" --config "+root+"\n" {
		t.Fatalf("apply on a torn active must print exactly today's hint: %d\n%s", code, out.String())
	}
}

// TestVerifyControlAcrossSegments: on a sealed root verify prints the head
// (the seal record), one segment line, the active line and exits 0; the
// pointer still matches (the install is inside the sealed segment);
// --expect-head seq:hash with a seq inside the sealed segment holds, and a
// wrong hash there is exit 4; audit control prints the segment line.
func TestVerifyControlAcrossSegments(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := sealedRoot(t)
	code, out := verifyControl(t, "--control-log", ctl, "--offline")
	if code != 0 || !regexp.MustCompile(`(?m)^control head: seq=3 sha256=[0-9a-f]{64}\n`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^segment 1: seq 1–3 sealed \S+ control\.jsonl\.seg-000001 sha256=[0-9a-f]{64} verified\n`).MatchString(out) ||
		!strings.Contains(out, "active: empty (next seq 4)\n") || !strings.Contains(out, "matches the last recorded install") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	recs := controlRecords(t, ctl)
	sum := sha256.Sum256(recs[1].Raw)
	if code, _ := verifyControl(t, "--control-log", ctl, "--offline", "--expect-head", "2:"+hex.EncodeToString(sum[:])); code != 0 {
		t.Fatal("seq:hash inside a sealed segment must hold")
	}
	if code, _ := verifyControl(t, "--control-log", ctl, "--offline", "--expect-head", "2:"+strings.Repeat("0", 64)); code != 4 {
		t.Fatal("a wrong hash inside a sealed segment is exit 4")
	}
	var buf bytes.Buffer
	if code := cmdAudit([]string{"control", "--control-log", ctl}, &buf); code != 0 || !strings.Contains(buf.String(), "segment 1: seq 1–3 sealed") || !strings.Contains(buf.String(), "segment 1 sealed (seq 1–2)") || !strings.Contains(buf.String(), "verified (3 events, 1 sealed segments)") {
		t.Fatalf("audit control: %d\n%s", code, buf.String())
	}
	// A never-sealed root prints no segment line (byte-identical goldens).
	plain := applied(t, writeSample(t))
	if _, out := verifyControl(t, "--control-log", plain, "--offline"); strings.Contains(out, "segment") || strings.Contains(out, "active:") {
		t.Fatalf("never-sealed root must not print segment lines:\n%s", out)
	}
}

// TestVerifyControlExitEightIsLast: state B alone → 8 with the state line;
// state B + wrong --expect-head → 4; + moved pointer → 5; + taint → 3.
func TestVerifyControlExitEightIsLast(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, sealSample(t))
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	code, out := verifyControl(t, "--control-log", ctl, "--offline")
	if code != exitRotationIncomplete || !strings.Contains(out, "control ledger: segment 1 sealed, rotation not completed; run: agenthof audit seal\n") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if code, _ := verifyControl(t, "--control-log", ctl, "--offline", "--expect-head", strings.Repeat("0", 64)); code != 4 {
		t.Fatalf("4 outranks 8: %d", code)
	}
	repointTo(t, ctl, "sha256:"+strings.Repeat("ab", 32))
	if code, _ := verifyControl(t, "--control-log", ctl, "--offline"); code != exitInstalledMismatch {
		t.Fatalf("5 outranks 8: %d", code)
	}
	// State C → 8 too.
	ctl2 := applied(t, sealSample(t))
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_manifest_before_swap")
	auditSeal(t, ctl2)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code, out := verifyControl(t, "--control-log", ctl2, "--offline"); code != exitRotationIncomplete || !strings.Contains(out, "rotation not completed") {
		t.Fatalf("state C: %d\n%s", code, out)
	}
}

// TestVerifyControlSetFaultExitsOneFirst: a torn sealed segment prints the
// head of the valid prefix and the fault and exits 1 — no anchor line, no
// pointer line, no segment lines.
func TestVerifyControlSetFaultExitsOneFirst(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := sealedRoot(t)
	seg := control.SegmentPath(ctl, 1)
	data, _ := os.ReadFile(seg)
	if err := os.WriteFile(seg, data[:len(data)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := verifyControl(t, "--control-log", ctl, "--offline")
	if code != 1 || !strings.Contains(out, "control ledger segment 1 (control.jsonl.seg-000001) torn at seq 3") || strings.Contains(out, "anchors:") || strings.Contains(out, "installed config:") || strings.Contains(out, "segment 1: seq") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "control head: seq=2 ") {
		t.Fatalf("the valid prefix's head prints first:\n%s", out)
	}
}

// TestReadersAcrossASealedBoundary: vouchInstalled vouches for an install
// inside a sealed segment with the global seq as the version; the anchor of
// a sealed head is reproduced; IsTainted spans segments; pull and sign see
// the global version.
func TestReadersAcrossASealedBoundary(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	useStub(t)
	ctl := sealedRoot(t)
	tlogPostureFor(t, ctl, "http://stub.invalid")
	records, last, refusal := vouchInstalled(ctl, readPointer(t, ctl))
	if refusal != nil || last.Seq != 2 || len(records) != 3 {
		t.Fatalf("%v %+v %d", refusal, last, len(records))
	}
	var out bytes.Buffer
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 || !strings.Contains(out.String(), "anchored: seq=3 ") {
		t.Fatalf("anchor after a seal must cover the sealed head, not refuse 'the chain has 0 records': %d\n%s", code, out.String())
	}
	if code, out := verifyControl(t, "--control-log", ctl, "--offline"); code != 0 || !strings.Contains(out, "anchors: 1 (1 verified, 0 mismatch, 0 unverifiable)") {
		t.Fatalf("%d\n%s", code, out)
	}
	inst, refusal := recordedInstall(ctl, readPointer(t, ctl))
	if refusal != nil || inst.Version != 2 {
		t.Fatalf("recordedInstall: %v %+v", refusal, inst)
	}
}

// TestAuditControlOnARotationAndASetFault: audit control is a read — a seal
// that was not rotated renders its state line and exits 0; a torn sealed
// segment renders the valid prefix, the verdict and the fault's remedy, and
// exits 1.
func TestAuditControlOnARotationAndASetFault(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, sealSample(t))
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	var buf bytes.Buffer
	if code := cmdAudit([]string{"control", "--control-log", ctl}, &buf); code != 0 || !strings.Contains(buf.String(), "control ledger: segment 1 sealed, rotation not completed; run: agenthof audit seal\n") {
		t.Fatalf("state B: %d\n%s", code, buf.String())
	}

	ctl = sealedRoot(t)
	seg := control.SegmentPath(ctl, 1)
	data, _ := os.ReadFile(seg)
	if err := os.WriteFile(seg, data[:len(data)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	code := cmdAudit([]string{"control", "--control-log", ctl}, &buf)
	if code != 1 || !strings.Contains(buf.String(), "control ledger — 2 events") || !strings.Contains(buf.String(), "control ledger integrity: TORN (segment 1)\n") || !strings.Contains(buf.String(), "a sealed segment is never repaired in place") {
		t.Fatalf("torn sealed segment: %d\n%s", code, buf.String())
	}
}

// TestVerifyControlUnverifiableAnchorOutranksAnIncompleteRotation: with an
// anchor on record and a seal stopped in state B, a verifier that holds the
// anchor's proof exits 8 alone, and one that cannot decide the anchor exits
// 7 — exit 8 is last.
func TestVerifyControlUnverifiableAnchorOutranksAnIncompleteRotation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	stub := useStub(t)
	ctl := applied(t, sealSample(t))
	tlogPostureFor(t, ctl, "http://stub.invalid")
	var out bytes.Buffer
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out.String())
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code, text := verifyControl(t, "--control-log", ctl, "--offline"); code != exitRotationIncomplete || !strings.Contains(text, "anchors: 1 (1 verified, 0 mismatch, 0 unverifiable)") {
		t.Fatalf("state B with a verified anchor: %d\n%s", code, text)
	}
	stub.Fail()
	if code, text := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorUnverifiable || !strings.Contains(text, "rotation not completed") {
		t.Fatalf("7 outranks 8: %d\n%s", code, text)
	}
}

// TestVerifyControlIntegrityVerdictsOutrankAnIncompleteRotation: a root in
// state B that is also anchor-mismatched exits 6, and one that is also
// tainted exits 3 — a verdict on the chain is never hidden behind exit 8.
func TestVerifyControlIntegrityVerdictsOutrankAnIncompleteRotation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	crashSeal := func(ctl string) {
		t.Helper()
		t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
		auditSeal(t, ctl)
		t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	}

	// 6: an anchor whose proof was altered (chain recomputed), then the seal stops in state B.
	useStub(t)
	ctl := applied(t, sealSample(t))
	tlogPostureFor(t, ctl, "http://stub.invalid")
	var out bytes.Buffer
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out.String())
	}
	rewriteTail(t, ctl, 2, func(seq int, m map[string]any) {
		p := m["anchor"].(map[string]any)["proof"].(string)
		m["anchor"].(map[string]any)["proof"] = "A" + p[1:]
	})
	crashSeal(ctl)
	if code, text := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorMismatch || !strings.Contains(text, "MISMATCH") || !strings.Contains(text, "rotation not completed") {
		t.Fatalf("6 outranks 8: %d\n%s", code, text)
	}

	// 3: a repair record on the chain (a torn tail repaired), then the seal stops in state B.
	root := sealSample(t)
	ctl = applied(t, root)
	tearTail(t, ctl)
	out.Reset()
	if code := cmdAudit([]string{"repair", "control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("repair: %d\n%s", code, out.String())
	}
	crashSeal(ctl)
	if code, text := verifyControl(t, "--control-log", ctl, "--offline"); code != 3 || !strings.Contains(text, "TAINTED") || !strings.Contains(text, "rotation not completed") {
		t.Fatalf("3 outranks 8: %d\n%s", code, text)
	}
}

// TestAuditRepairControlCompletesAPostSealRotation: the command prints the
// state-B repair line, verify exits 3 (tainted) with the segment line.
func TestAuditRepairControlCompletesAPostSealRotation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := sealSample(t)
	ctl := applied(t, root)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	// An older binary appends after the seal: emulate with a raw chained record.
	recs := controlRecords(t, ctl)
	sum := sha256.Sum256(recs[len(recs)-1].Raw)
	f, _ := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"v":"control/1","seq":` + strconv.Itoa(len(recs)+1) + `,"time":"2026-10-15T10:00:00Z","action":"prune","outcome":"success","invoker":{"subject":"old","issuer":"local","method":"static"},"witness":{"os_user":"o","hostname":"h"},"prev":"` + hex.EncodeToString(sum[:]) + `"}` + "\n")
	_ = f.Close()
	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 0 || !regexp.MustCompile(`(?m)^repaired: moved \d+ bytes \(sha256=[0-9a-f]{64}\) to .*control\.jsonl\.torn-\d+; rotation of segment 1 completed; control ledger tainted\n`).MatchString(out.String()) {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if code, vout := verifyControl(t, "--control-log", ctl, "--offline"); code != 3 || !strings.Contains(vout, "segment 1: seq 1–2 sealed") || !strings.Contains(vout, "TAINTED: repaired at seq 3") {
		t.Fatalf("%d\n%s", code, vout)
	}
}

// TestAuditRepairControlRefusesAnIncompleteRotation: state B is not a repair
// matter — the command points at audit seal, exits 1, and changes nothing.
func TestAuditRepairControlRefusesAnIncompleteRotation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := sealSample(t)
	ctl := applied(t, root)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	before, _ := os.ReadFile(ctl)
	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 1 || !strings.Contains(out.String(), "run audit seal") || strings.Contains(out.String(), "repaired:") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
		t.Fatal("a refusal changes nothing")
	}
	if frags, _ := filepath.Glob(ctl + ".torn-*"); len(frags) != 0 {
		t.Fatalf("no fragment on a refusal: %v", frags)
	}
}

// TestInvestigateAcrossSegments: Sources[].count is the logical count, the
// integrity verdict verified, the seal event present with kind seal, and a
// boundary tamper reads broken.
func TestInvestigateAcrossSegments(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := sealedRoot(t)
	var out bytes.Buffer
	if code := cmdInvestigate([]string{"--json", "--log-dir", t.TempDir(), "--control-log", ctl}, &out); code != 0 {
		t.Fatalf("%d\n%s", code, out.String())
	}
	var doc struct {
		Sources []struct {
			Kind  string `json:"kind"`
			Count int    `json:"count"`
		} `json:"sources"`
		Integrity struct {
			OK bool `json:"ok"`
		} `json:"integrity"`
		Events []struct {
			Kind string `json:"kind"`
		} `json:"events"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	seals := 0
	for _, e := range doc.Events {
		if e.Kind == "seal" {
			seals++
		}
	}
	if !doc.Integrity.OK || seals != 1 || len(doc.Sources) != 1 || doc.Sources[0].Count != 3 {
		t.Fatalf("%+v", doc)
	}
	// Plant a foreign genesis, as an older binary would, in the empty active.
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"v":"control/1","seq":1,"time":"2026-10-15T10:00:00Z","action":"apply","outcome":"success","invoker":{"subject":"old","issuer":"local","method":"static"},"witness":{"os_user":"o","hostname":"h"},"prev":"","log_id":"` + strings.Repeat("cd", 16) + `"}` + "\n")
	_ = f.Close()
	out.Reset()
	cmdInvestigate([]string{"--json", "--log-dir", t.TempDir(), "--control-log", ctl}, &out)
	var tampered struct {
		Sources []struct {
			Kind      string `json:"kind"`
			Integrity string `json:"integrity"`
		} `json:"sources"`
		Integrity struct {
			OK bool `json:"ok"`
		} `json:"integrity"`
	}
	if err := json.Unmarshal(out.Bytes(), &tampered); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(tampered.Sources) != 1 || tampered.Sources[0].Kind != "control" || tampered.Sources[0].Integrity != "broken" || tampered.Integrity.OK {
		t.Fatalf("a boundary tamper is broken:\n%s", out.String())
	}
	var buf bytes.Buffer
	if code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 1 || !strings.Contains(buf.String(), "a writer older than this root's seals") || strings.Contains(buf.String(), "restore it from a copy") {
		t.Fatalf("repair refuses with the cause: %d\n%s", code, buf.String())
	}
}

// TestPruneSparesSegmentsAndManifest: runs prune pointed AT the control root
// with a zero retention removes nothing of the ledger set — the segment and
// manifest names never end in .jsonl, which is the enumerators' rule; the
// active is spared by name and identity as today.
func TestPruneSparesSegmentsAndManifest(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := sealedRoot(t)
	dir := filepath.Dir(ctl)
	before, _ := os.ReadDir(dir)
	if n, err := pruneRuns(dir, 0, ctl); err != nil || n != 0 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) {
		t.Fatalf("prune removed something: %v → %v", before, after)
	}
	res, err := investigate.Timeline(dir, ctl, investigate.Filter{}, investigate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Sources {
		if strings.Contains(s.Path, ".seg-") || strings.Contains(s.Path, ".segments") {
			t.Fatalf("a segment listed as a run: %+v", s)
		}
	}
}
