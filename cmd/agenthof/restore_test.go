package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sink/sinktest"
)

// restoreControl runs audit restore control as dana (platform-eng, which
// the seal sample grants repair).
func restoreControl(t *testing.T, ctl string, extra ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdAudit(append([]string{"restore", "control", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, extra...), &out)
	return code, out.String()
}

// lastRecordOf decodes the logical chain's last record (across segments;
// lastControlEvent reads the active file alone).
func lastRecordOf(t *testing.T, ctl string) control.DecodedEvent {
	t.Helper()
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	d, err := control.Decode(v.Records[len(v.Records)-1].Raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// replacedFiles lists the <base>.replaced-* files beside ctl.
func replacedFiles(t *testing.T, ctl string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(ctl))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filepath.Base(ctl)+".replaced-") {
			out = append(out, filepath.Join(filepath.Dir(ctl), e.Name()))
		}
	}
	return out
}

// TestAuditRestoreControlMissingSegment: the sealed file removed → verify
// exits 1 (a set fault); restore puts it back from the fake's v-1 and
// records it; verify exits 0; audit control renders the record.
func TestAuditRestoreControlMissingSegment(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, f := wormSealedRoot(t)
	seg1 := control.SegmentPath(ctl, 1)
	want, _ := os.ReadFile(seg1)
	if err := os.Remove(seg1); err != nil {
		t.Fatal(err)
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 1 || !strings.Contains(out, "control ledger segment 1 missing") {
		t.Fatalf("verify before: %d\n%s", code, out)
	}
	code, out := restoreControl(t, ctl)
	if code != 0 || !regexp.MustCompile(`^restored: segment 1 from s3-object-lock `+regexp.QuoteMeta(f.URL())+`/agenthof version=v-1 sha256=[0-9a-f]{64} \(nothing was there\)\ncontrol head: seq=4 sha256=[0-9a-f]{64}\n$`).MatchString(out) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if back, _ := os.ReadFile(seg1); !bytes.Equal(back, want) {
		t.Fatal("the restored file is not what was removed")
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 0 {
		t.Fatalf("verify after: %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdAudit([]string{"control", "--control-log", ctl}, &buf); code != 0 || !strings.Contains(buf.String(), "restored a sealed segment from its protected copy (segment 1 restored from s3-object-lock version v-1; nothing was there) — dana@example.com (asserted)") {
		t.Fatalf("audit control: %d\n%s", code, buf.String())
	}
	e := lastRecordOf(t, ctl)
	if e.Action != "restore" || e.Outcome != "success" || e.ConfigHash != "" || e.Seq != 4 {
		t.Fatalf("%+v", e)
	}
	if len(replacedFiles(t, ctl)) != 0 {
		t.Fatal("nothing was there to move aside")
	}
}

// TestAuditRestoreControlSegmentFlagAndEvidence: --segment names an ordinal
// not at fault → refused naming the one that is; --segment 1 on a truncated
// segment 1 → restored, the damaged bytes kept at .replaced-000001-*.
func TestAuditRestoreControlSegmentFlagAndEvidence(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	seg1 := control.SegmentPath(ctl, 1)
	data, _ := os.ReadFile(seg1)
	damaged := data[:len(data)-10]
	if err := os.WriteFile(seg1, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := restoreControl(t, ctl, "--segment", "2")
	if code != 1 || !strings.Contains(out, "segment 2 is not at fault; the fault is in segment 1") || strings.Contains(out, "restored:") {
		t.Fatalf("%d\n%s", code, out)
	}
	if len(replacedFiles(t, ctl)) != 0 {
		t.Fatal("a refusal moves nothing aside")
	}
	code, out = restoreControl(t, ctl, "--segment", "1")
	if code != 0 || !regexp.MustCompile(`(?m)^restored: segment 1 from s3-object-lock .* version=v-1 sha256=[0-9a-f]{64} \(control\.jsonl\.replaced-000001-\d+\)\n`).MatchString(out) {
		t.Fatalf("%d\n%s", code, out)
	}
	kept := replacedFiles(t, ctl)
	if len(kept) != 1 {
		t.Fatalf("replaced files %v", kept)
	}
	if b, _ := os.ReadFile(kept[0]); !bytes.Equal(b, damaged) {
		t.Fatal("the replaced file holds the damaged bytes")
	}
	if back, _ := os.ReadFile(seg1); !bytes.Equal(back, data) {
		t.Fatal("segment 1 is the sealed bytes again")
	}
	if e := lastRecordOf(t, ctl); e.Action != "restore" || !strings.HasSuffix(e.Detail, "replaced bytes kept at "+filepath.Base(kept[0])) {
		t.Fatalf("%+v", e)
	}
	for _, bad := range []string{"0", "-1", "x", ""} {
		if code, out := restoreControl(t, ctl, "--segment", bad); code != 2 || !strings.Contains(out, "--segment") {
			t.Fatalf("%q: %d\n%s", bad, code, out)
		}
	}
}

// TestAuditRestoreControlRefusalsUnrecorded: every refusal is printed and
// not recorded — no grant (naming no posture or path), a bad token, no sink
// configured, a posture the build cannot honour (exit 2), a clean root.
func TestAuditRestoreControlRefusalsUnrecorded(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	_ = os.Remove(control.SegmentPath(ctl, 1))
	before, _ := os.ReadFile(ctl)
	dir := filepath.Dir(ctl)

	var out bytes.Buffer
	code := cmdAudit([]string{"restore", "control", "--control-log", ctl, "--as", "mallory@example.com", "--groups", "finance"}, &out)
	if code != 1 || out.String() != "audit restore control: not authorized: no role grants repair to the invoker\n" {
		t.Fatalf("mallory: %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "integrity") || strings.Contains(out.String(), dir) {
		t.Fatalf("an unauthorized caller learns nothing of the root:\n%s", out.String())
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := cmdTestOIDCServer(t, key)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := cmdMintToken(t, otherKey, map[string]any{"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	out.Reset()
	if code := cmdAudit([]string{"restore", "control", "--control-log", ctl, "--token", bad}, &out); code != 1 || !strings.Contains(out.String(), "audit restore control: token authentication failed") || strings.Contains(out.String(), bad) || strings.Contains(out.String(), dir) {
		t.Fatalf("token: %d\n%s", code, out.String())
	}
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	out.Reset()
	if code := cmdAudit([]string{"restore", "control", "--control-log", ctl, "--token", "whatever"}, &out); code != 2 || !strings.Contains(out.String(), "AGENTHOF_OIDC_ISSUER must be set") {
		t.Fatalf("token without issuer: %d\n%s", code, out.String())
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
		t.Fatal("nothing recorded")
	}
	if _, err := os.Stat(control.SegmentPath(ctl, 1)); err == nil {
		t.Fatal("nothing restored")
	}

	// No posture: a floor root that sealed.
	floor := sealedRoot(t)
	_ = os.Remove(control.SegmentPath(floor, 1))
	code, text := restoreControl(t, floor)
	if code != 1 || text != "audit restore control: no sink configured in "+integrityPath(floor)+"; a protected copy exists only under sink: worm\n" {
		t.Fatalf("floor: %d\n%s", code, text)
	}
	writeIntegrity(t, floor, "sink: local\n")
	if code, text := restoreControl(t, floor); code != 1 || !strings.Contains(text, "no sink configured in") {
		t.Fatalf("local: %d\n%s", code, text)
	}
	// --integrity names the posture copy to read, and its absence fails closed.
	other := filepath.Join(t.TempDir(), "integrity.yaml")
	if code, text := restoreControl(t, floor, "--integrity", other); code != 2 || !strings.Contains(text, "audit restore control: integrity "+other+": ") {
		t.Fatalf("--integrity absent: %d\n%s", code, text)
	}

	// A posture this build cannot honour: exit 2, the file named once.
	p := writeIntegrity(t, floor, wormMisconfigure)
	if code, text := restoreControl(t, floor); code != 2 || text != "audit restore control: "+wormFault(p)+"\n" {
		t.Fatalf("misconfigure: %d\n%s", code, text)
	}

	// A clean root.
	clean, _ := wormSealedRoot(t)
	cleanBefore, _ := os.ReadFile(clean)
	if code, text := restoreControl(t, clean); code != 1 || text != "audit restore control: "+control.ErrNothingToRestore.Error()+"\n" {
		t.Fatalf("clean: %d\n%s", code, text)
	}
	if after, _ := os.ReadFile(clean); !bytes.Equal(cleanBefore, after) {
		t.Fatal("nothing recorded on a clean root")
	}

	// Nothing recorded yet.
	none := filepath.Join(t.TempDir(), "control.jsonl")
	root := sealSample(t)
	out.Reset()
	if code := cmdAudit([]string{"restore", "control", "--control-log", none, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || !strings.Contains(out.String(), "no sink configured in") {
		t.Fatalf("nothing recorded, floor: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(none); !os.IsNotExist(err) {
		t.Fatal("nothing created")
	}
	if code := cmdAudit([]string{"restore"}, &out); code != 2 {
		t.Fatalf("missing subcommand: %d", code)
	}
}

// TestAuditRestoreControlNoTaint: after a restore verify exits 0 and prints
// no TAINTED line; a later writer appends as usual.
func TestAuditRestoreControlNoTaint(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	_ = os.Remove(control.SegmentPath(ctl, 1))
	if code, out := restoreControl(t, ctl); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	code, out := verifyControl(t, "--control-log", ctl)
	if code != 0 || strings.Contains(out, "TAINTED") || !strings.Contains(out, "control head: seq=4 ") {
		t.Fatalf("%d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdAudit([]string{"control", "--control-log", ctl}, &buf); code != 0 || strings.Contains(buf.String(), "TAINTED") || !strings.Contains(buf.String(), "control ledger integrity: verified (4 events, 1 sealed segments)") || !strings.Contains(buf.String(), "control ledger — 4 events\nlog_id: "+ledgerID(t, ctl)+"\n\n") {
		t.Fatalf("audit control: %d\n%s", code, buf.String())
	}
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	if tainted, _ := control.IsTainted(v.Records); tainted {
		t.Fatal("a restore taints nothing")
	}
	if code, out := auditSeal(t, ctl); code != 0 || !strings.Contains(out, "sealed: segment 2 seq=4..5 ") {
		t.Fatalf("the restore record seals as any record: %d\n%s", code, out)
	}
}

// TestAuditRestoreControlNotOldestAndUnlocked: the chain selects a later
// version when the oldest at the key does not chain (printed), and restores
// from a version that is not locked (printed).
func TestAuditRestoreControlNotOldestAndUnlocked(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl, f := wormSealedRoot(t)
	key := segmentKey(t, ctl, 1)
	real, _ := os.ReadFile(control.SegmentPath(ctl, 1))
	f.RemoveVersion(key, "v-1")
	f.Plant(key, []byte("foreign\n"), "COMPLIANCE", far)
	if id := f.Plant(key, real, "COMPLIANCE", far); id != "v-3" {
		t.Fatalf("planted %s", id)
	}
	_ = os.Remove(control.SegmentPath(ctl, 1))
	code, out := restoreControl(t, ctl)
	if code != 0 || !strings.Contains(out, " version=v-3 sha256=") || !strings.Contains(out, "\nselected version v-3 is not the oldest at the key — the oldest does not chain; verify will report LOCAL MISMATCH until the sink is examined\n") || strings.Contains(out, "UNLOCKED") {
		t.Fatalf("%d\n%s", code, out)
	}
	if back, _ := os.ReadFile(control.SegmentPath(ctl, 1)); !bytes.Equal(back, real) {
		t.Fatal("the chain's bytes")
	}
	if code, vout := verifyControl(t, "--control-log", ctl); code != 9 || !strings.Contains(vout, "LOCAL MISMATCH") {
		t.Fatalf("verify judges the oldest: %d\n%s", code, vout)
	}

	ctl, f = wormSealedRoot(t)
	key = segmentKey(t, ctl, 1)
	real, _ = os.ReadFile(control.SegmentPath(ctl, 1))
	f.RemoveVersion(key, "v-1")
	f.Plant(key, real, "", time.Time{})
	_ = os.Remove(control.SegmentPath(ctl, 1))
	code, out = restoreControl(t, ctl)
	if code != 0 || !strings.Contains(out, " version=v-2 sha256=") || !strings.Contains(out, "\nsegment 1 restored from an UNLOCKED version") || strings.Contains(out, "not the oldest") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// TestAuditRestoreControlBusy: installed.lock held by another process →
// the busy line, exit 1, nothing restored (waits the real lock timeout).
func TestAuditRestoreControlBusy(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	_ = os.Remove(control.SegmentPath(ctl, 1))
	holdLock(t, "file", installedLock(ctl), 9000)
	code, out := restoreControl(t, ctl)
	if code != 1 || out != "audit restore control: "+msgLockBusy+"\n" {
		t.Fatalf("%d\n%s", code, out)
	}
	if _, err := os.Stat(control.SegmentPath(ctl, 1)); err == nil {
		t.Fatal("busy restores nothing")
	}
}

// thriceSealedWormRoot seals a worm root three times — segment 1 (seq 1–3),
// segment 2 (seq 4–5), segment 3 (seq 6–7), each with a protected copy; the
// active is empty.
func thriceSealedWormRoot(t *testing.T) (string, string, *sinktest.Fake) {
	t.Helper()
	root, ctl, f := twiceSealedWormRoot(t)
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("disable: %d\n%s", code, buf.String())
	}
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal 3: %d\n%s", code, out)
	}
	return root, ctl, f
}

// ledgerID is the genesis's log_id, read while the local set still has one.
func ledgerID(t *testing.T, ctl string) string {
	t.Helper()
	id, err := control.GenesisLogID(sealedView(t, ctl).Records)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// sha256Of is a file's whole-file digest.
func sha256Of(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestAuditRestoreRebuildWholeSet: three sealed segments and the manifest
// deleted → --rebuild puts every file back byte-identical from the fake,
// records it, verify exits 0, audit control renders the record.
func TestAuditRestoreRebuildWholeSet(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := thriceSealedWormRoot(t)
	id := ledgerID(t, ctl)
	files := []string{control.SegmentPath(ctl, 1), control.SegmentPath(ctl, 2), control.SegmentPath(ctl, 3), control.ManifestPath(ctl)}
	want := map[string]string{}
	for _, p := range files {
		want[p] = sha256Of(t, p)
	}
	for _, p := range files {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	code, out := restoreControl(t, ctl, "--rebuild", "--log-id", id)
	if code != 0 || !regexp.MustCompile(`^rebuilt: segments 1–3 from s3-object-lock `+regexp.QuoteMeta(f.URL())+`/agenthof \(3 written, 0 replaced\)\ncontrol head: seq=8 sha256=[0-9a-f]{64}\n$`).MatchString(out) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for p, h := range want {
		if got := sha256Of(t, p); got != h {
			t.Fatalf("%s: rebuilt %s, was %s", filepath.Base(p), got, h)
		}
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 0 || strings.Contains(out, "TAINTED") {
		t.Fatalf("verify after: %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdAudit([]string{"control", "--control-log", ctl}, &buf); code != 0 || !strings.Contains(buf.String(), "restored a sealed segment from its protected copy (rebuild from s3-object-lock: 3 segments verified against the sink, 3 written, 0 replaced, manifest rewritten, active kept) — dana@example.com (asserted)") {
		t.Fatalf("audit control: %d\n%s", code, buf.String())
	}
	if e := lastRecordOf(t, ctl); e.Action != "restore" || e.Outcome != "success" || e.Seq != 8 {
		t.Fatalf("%+v", e)
	}
	if len(replacedFiles(t, ctl)) != 0 {
		t.Fatal("nothing was there to move aside")
	}
	// A re-run verifies the set against the sink, writes nothing, records.
	if code, out := restoreControl(t, ctl, "--rebuild", "--log-id", id); code != 0 || !strings.HasPrefix(out, "rebuilt: segments 1–3 from s3-object-lock "+f.URL()+"/agenthof (0 written, 0 replaced)\ncontrol head: seq=9 ") {
		t.Fatalf("re-run: %d\n%s", code, out)
	}
}

// TestAuditRestoreRebuildTidiedTruncation: segments 2–3 dropped, the
// manifest shortened, a record appended to the active — a clean local chain
// verify's sink pass catches (9). The rebuild puts the segments back and
// refuses to record: the active no longer chains (the remedy line, exit 1).
// The remedy's re-run writes nothing and records.
func TestAuditRestoreRebuildTidiedTruncation(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := thriceSealedWormRoot(t)
	id := ledgerID(t, ctl)
	for _, n := range []int{2, 3} {
		if err := os.Remove(control.SegmentPath(ctl, n)); err != nil {
			t.Fatal(err)
		}
	}
	m := readManifest(t, ctl)
	m.Segments = m.Segments[:1]
	writeManifest(t, ctl, m)
	if err := os.WriteFile(ctl, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inv := identity.Invoker{Subject: "dana@example.com", Issuer: "static", Method: "static"}
	if _, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("the tidied set takes an append: %v", err)
	}
	active, _ := os.ReadFile(ctl)
	if code, out := verifyControl(t, "--control-log", ctl); code != 9 {
		t.Fatalf("verify before: %d\n%s", code, out)
	}
	code, out := restoreControl(t, ctl, "--rebuild", "--log-id", id)
	want := "audit restore control: rebuilt 3 sealed segments; NOT recorded — the active does not chain from segment 3's head: move " + ctl + " aside (its records are evidence, not chain), create an empty " + ctl + ", then re-run audit restore control --rebuild --log-id " + id + " to record the rebuild\n"
	if code != 1 || !strings.HasSuffix(out, want) || !regexp.MustCompile(`(?m)^rebuilt: segments 1–3 from s3-object-lock .* \(2 written, 0 replaced\) kept at control\.jsonl\.replaced-segments-\d+\n`).MatchString(out) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(active, after) {
		t.Fatal("nothing recorded: the active is untouched")
	}
	for _, n := range []int{2, 3} {
		if _, err := os.Stat(control.SegmentPath(ctl, n)); err != nil {
			t.Fatalf("segment %d is back: %v", n, err)
		}
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 1 || !strings.Contains(out, "active segment does not chain from segment 3's head") {
		t.Fatalf("verify between: %d\n%s", code, out)
	}
	if err := os.Rename(ctl, ctl+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ctl, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out = restoreControl(t, ctl, "--rebuild", "--log-id", id)
	if code != 0 || !strings.HasPrefix(out, "rebuilt: segments 1–3 from s3-object-lock "+f.URL()+"/agenthof (0 written, 0 replaced)\ncontrol head: seq=8 ") {
		t.Fatalf("re-run: %d\n%s", code, out)
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 0 {
		t.Fatalf("verify after: %d\n%s", code, out)
	}
	if e := lastRecordOf(t, ctl); e.Action != "restore" || !strings.HasSuffix(e.Detail, "0 written, 0 replaced, manifest kept, active kept") {
		t.Fatalf("%+v", e)
	}
}

// TestAuditRestoreRebuildGap: a key with no version in the bucket refuses
// the whole rebuild naming the ordinal, nothing written.
func TestAuditRestoreRebuildGap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := thriceSealedWormRoot(t)
	id := ledgerID(t, ctl)
	f.RemoveVersions(segmentKey(t, ctl, 2))
	for _, n := range []int{1, 2, 3} {
		if err := os.Remove(control.SegmentPath(ctl, n)); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadFile(ctl)
	code, out := restoreControl(t, ctl, "--rebuild", "--log-id", id)
	if code != 1 || out != "audit restore control: control: cannot rebuild: the sink holds segments 1–1 and 3–3; segment 2 is missing from the bucket — a chain with a hole cannot be reconstructed\n" {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, n := range []int{1, 2, 3} {
		if _, err := os.Stat(control.SegmentPath(ctl, n)); err == nil {
			t.Fatalf("segment %d written", n)
		}
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
		t.Fatal("nothing recorded")
	}
	// A delete marker on a key is not a gap: the locked versions stand.
	_, ctl, f = thriceSealedWormRoot(t)
	id = ledgerID(t, ctl)
	f.AddDeleteMarker(segmentKey(t, ctl, 2))
	_ = os.Remove(control.SegmentPath(ctl, 2))
	if code, out := restoreControl(t, ctl, "--rebuild", "--log-id", id); code != 0 || !strings.Contains(out, "(1 written, 0 replaced)") || strings.Contains(out, "delete marker") {
		t.Fatalf("marker: %d\n%s", code, out)
	}
	// A top key holding only a marker is reported, and the local segment
	// beyond the rebuilt set is kept as a trailing entry — said so.
	_, ctl, f = thriceSealedWormRoot(t)
	id = ledgerID(t, ctl)
	f.RemoveVersions(segmentKey(t, ctl, 3))
	f.AddDeleteMarker(segmentKey(t, ctl, 3))
	if code, out := restoreControl(t, ctl, "--rebuild", "--log-id", id); code != 0 || !strings.HasPrefix(out, "segment 3: the sink holds only a delete marker at its key — every version was removed; not rebuilt\nsegment 3: not in the sink — local only, kept as a trailing entry\nrebuilt: segments 1–2 from s3-object-lock "+f.URL()+"/agenthof (0 written, 0 replaced)\ncontrol head: seq=8 ") {
		t.Fatalf("marker-only top key: %d\n%s", code, out)
	}
	if code, out := verifyControl(t, "--control-log", ctl, "--offline"); code != 0 {
		t.Fatalf("verify after: %d\n%s", code, out)
	}
}

// TestAuditRestoreRebuildUsage: --rebuild without --log-id and with
// --segment are usage (exit 2, before the invoker); state B refuses with
// "run audit seal", exit 1.
func TestAuditRestoreRebuildUsage(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	id := ledgerID(t, ctl)
	var out bytes.Buffer
	if code := cmdAudit([]string{"restore", "control", "--control-log", ctl, "--as", "mallory@example.com", "--groups", "finance", "--rebuild"}, &out); code != 2 || out.String() != "audit restore control: --rebuild requires --log-id <id> (the ledger's identity — from audit control's header or the bucket listing)\n" {
		t.Fatalf("no --log-id: %d\n%s", code, out.String())
	}
	if code, text := restoreControl(t, ctl, "--rebuild", "--log-id", id, "--segment", "1"); code != 2 || text != "audit restore control: --segment cannot be combined with --rebuild\n" {
		t.Fatalf("--segment: %d\n%s", code, text)
	}
	for _, bad := range []string{"<id>", "x", strings.ToUpper(id), id + "0"} {
		if code, text := restoreControl(t, ctl, "--rebuild", "--log-id", bad); code != 2 || text != "audit restore control: --log-id must be the ledger's identity, 32 lowercase hex characters (as audit control's header and the bucket listing spell it)\n" {
			t.Fatalf("--log-id %q: %d\n%s", bad, code, text)
		}
	}
	before, _ := os.ReadFile(ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_sink")
	var buf bytes.Buffer
	cmdRegistry([]string{"enable", "coder", "--config", sealSample(t), "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf)
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code, text := verifyControl(t, "--control-log", ctl, "--offline"); code != exitRotationIncomplete {
		t.Fatalf("state B: %d\n%s", code, text)
	}
	stateB, _ := os.ReadFile(ctl)
	if bytes.Equal(before, stateB) {
		t.Fatal("the fixture appended and sealed")
	}
	if code, text := restoreControl(t, ctl, "--rebuild", "--log-id", id); code != 1 || !strings.Contains(text, "run audit seal to complete it — not a restore matter") {
		t.Fatalf("state B: %d\n%s", code, text)
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(stateB, after) {
		t.Fatal("nothing recorded")
	}
}

// TestAuditRestoreRebuildLogIDMismatch: --log-id of another ledger with
// the genesis present → refused naming both, nothing touched.
func TestAuditRestoreRebuildLogIDMismatch(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := wormSealedRoot(t)
	id := ledgerID(t, ctl)
	other := strings.Repeat("b", 32)
	before, _ := os.ReadFile(ctl)
	code, out := restoreControl(t, ctl, "--rebuild", "--log-id", other)
	if code != 1 || out != "audit restore control: control: --log-id "+other+" but this root is ledger "+id+"; a rebuild reconstructs one ledger\n" {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) || len(replacedFiles(t, ctl)) != 0 {
		t.Fatal("nothing touched")
	}
}
