package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sink/sinktest"
)

// keyOrder returns a record's top-level keys in wire order.
func keyOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %v", err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// TestNoSealIsToday pins the hard invariant: a root that never seals is
// today's root. Drive apply → kill switch → anchor (stub) → prune; the root's
// directory holds exactly today's entries, every record's key sequence is
// the pre-change sequence for its action, no record carries "seal", log_id
// is on seq 1 only, and control.Read returns ledger.ReadVerify's records
// and head.
func TestNoSealIsToday(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	useStub(t)
	root := anchorSample(t)
	ctl := applied(t, root)
	tlogPostureFor(t, ctl, "http://stub.invalid")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir(), "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	entries, err := os.ReadDir(filepath.Dir(ctl))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"control.jsonl", "installed", "installed.lock", "integrity.yaml"}; strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("directory listing %v, want %v (no .segments, no .seg-*)", names, want)
	}
	want, wantHead, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil || v.Head != wantHead || len(v.Records) != len(want) || v.Sealed != nil {
		t.Fatalf("Read ≠ ReadVerify: %v %+v", err, v.Head)
	}
	orders := map[string][]string{
		"apply":   {"v", "seq", "time", "action", "outcome", "invoker", "witness", "config_hash", "bootstrap", "prev", "log_id"},
		"disable": {"v", "seq", "time", "action", "agent", "outcome", "invoker", "witness", "config_hash", "prev"},
		"anchor":  {"v", "seq", "time", "action", "outcome", "invoker", "witness", "anchor", "prev"},
		"prune":   {"v", "seq", "time", "action", "outcome", "invoker", "witness", "detail", "prev"},
	}
	for i, r := range v.Records {
		if string(r.Raw) != string(want[i].Raw) {
			t.Fatalf("record %d differs", i)
		}
		if bytes.Contains(r.Raw, []byte(`"seal"`)) {
			t.Fatalf("record %d carries a seal key:\n%s", i, r.Raw)
		}
		var rec struct {
			Action string `json:"action"`
			LogID  string `json:"log_id"`
		}
		_ = json.Unmarshal(r.Raw, &rec)
		if (i == 0) != (rec.LogID != "") {
			t.Fatalf("log_id must be on seq 1 only (record %d: %q)", i+1, rec.LogID)
		}
		got := strings.Join(keyOrder(t, r.Raw), ",")
		if exp := strings.Join(orders[rec.Action], ","); got != exp {
			t.Fatalf("%s record key order:\n got %s\nwant %s", rec.Action, got, exp)
		}
	}
	if !regexp.MustCompile(`"seq":1,`).Match(v.Records[0].Raw) {
		t.Fatal("genesis is seq 1")
	}
}

// sealSample is writeSample with the platform-admin role also granting anchor
// and seal. Call it before applied.
func sealSample(t *testing.T) string {
	t.Helper()
	root := writeSample(t)
	role := "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair, provision, prune, anchor, seal]\n"
	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte(role), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func auditSeal(t *testing.T, ctl string, extra ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdAudit(append([]string{"seal", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, extra...), &out)
	return code, out.String()
}

// sealedRoot applies sealSample, flips one agent (two records) and seals
// once: segment 1 holds seq 1–3 (apply, disable, seal); the active is empty.
func sealedRoot(t *testing.T) string {
	t.Helper()
	root := sealSample(t)
	ctl := applied(t, root)
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal: %d\n%s", code, out)
	}
	return ctl
}

// TestAuditSealSuccessPrintsAndRotates: exit 0; the sealed: line and the head
// line (the head is the seal record); the layout; apply still appends after.
func TestAuditSealSuccessPrintsAndRotates(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := sealedRoot(t)
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil || len(v.Sealed) != 1 || v.Head.Count != 3 || v.Active.Records != 0 {
		t.Fatalf("%v %+v", err, v)
	}
	root := sealSample(t)
	ctl2 := applied(t, root)
	code, out := auditSeal(t, ctl2)
	if code != 0 || !regexp.MustCompile(`(?m)^sealed: segment 1 seq=1\.\.2 sha256=[0-9a-f]{64} \(control\.jsonl\.seg-000001\)\n`).MatchString(out) || !regexp.MustCompile(`(?m)^control head: seq=2 sha256=[0-9a-f]{64}\n`).MatchString(out) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl2, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 || !strings.Contains(buf.String(), "control head: seq=3 ") {
		t.Fatalf("apply after a seal: %d\n%s", code, buf.String())
	}
}

// TestAuditSealAuthorization: no grant → recorded refused/not_authorized in
// the active, exit 1, no files created; nothing installed → recorded refused;
// a failed token → recorded refused; the recorded refusal lands even when
// --if-larger-than is not met.
func TestAuditSealAuthorization(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t)) // the sample grants no seal
	code, out := auditSeal(t, ctl, "--if-larger-than", "1g")
	if code != 1 || !strings.Contains(out, "audit seal: not authorized: no role grants seal to the invoker") || !strings.Contains(out, "control head: seq=2 ") {
		t.Fatalf("%d\n%s", code, out)
	}
	v, _ := control.Read(ctl, ledger.Locked)
	last, _ := control.Decode(v.Records[1].Raw)
	if last.Action != "seal" || last.Outcome != "refused" || last.Reason.Code != control.CodeNotAuthorized || last.Seal != nil {
		t.Fatalf("%+v", last)
	}
	entries, _ := os.ReadDir(filepath.Dir(ctl))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".seg") {
			t.Fatalf("a refusal creates nothing: %s", e.Name())
		}
	}
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	code, out = auditSeal(t, ctl2)
	if code != 1 || !strings.Contains(out, "audit seal: "+msgNothingInstalled) {
		t.Fatalf("nothing installed: %d\n%s", code, out)
	}
	// A token signed by a key the issuer does not serve: hermetic, through the
	// in-process OIDC server (registry's bad-token pattern).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := cmdTestOIDCServer(t, key)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := cmdMintToken(t, otherKey, map[string]any{"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	var buf bytes.Buffer
	if code := cmdAudit([]string{"seal", "--control-log", ctl, "--token", bad}, &buf); code != 1 || !strings.Contains(buf.String(), "token authentication failed") || !strings.Contains(buf.String(), "control head: seq=3 ") {
		t.Fatalf("token: %d\n%s", code, buf.String())
	}
}

// TestAuditSealIfLargerThan: 1g on a small root → exit 0, nothing recorded,
// no files; 0 → seals; bad grammar → exit 2 before anything.
func TestAuditSealIfLargerThan(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, sealSample(t))
	before, _ := os.ReadFile(ctl)
	code, out := auditSeal(t, ctl, "--if-larger-than", "1g")
	if code != 0 || !regexp.MustCompile(`^audit seal: active segment is \d+ bytes, not larger than 1g; nothing sealed\n$`).MatchString(out) {
		t.Fatalf("%d\n%s", code, out)
	}
	after, _ := os.ReadFile(ctl)
	if !bytes.Equal(before, after) {
		t.Fatal("a no-op records nothing")
	}
	for _, bad := range []string{"10x", "-1", "abc", "1kb", ""} {
		if code, out := auditSeal(t, ctl, "--if-larger-than", bad); code != 2 || !strings.Contains(out, "--if-larger-than must be") {
			t.Fatalf("%q: %d\n%s", bad, code, out)
		}
	}
	if code, _ := auditSeal(t, ctl, "--if-larger-than", "0"); code != 0 {
		t.Fatal("0 seals a non-empty active")
	}
	if code, out := auditSeal(t, ctl); code != 1 || !strings.Contains(out, "audit seal: the active segment is empty; nothing to seal") {
		t.Fatalf("empty: %d\n%s", code, out)
	}
	for in, want := range map[string]int64{"0": 0, "50m": 52428800, "1K": 1024, "2g": 2 << 30, "123": 123} {
		if got, ok := parseSize(in); !ok || got != want {
			t.Fatalf("parseSize(%q) = %d %v", in, got, ok)
		}
	}
}

// TestAuditSealCrashStatesComplete: the three hooks through the command —
// state A′ (first seal and later seal: Read ok, apply appends, the next seal
// reuses the link), state B (apply → the completion hint, exit 1, unrecorded;
// re-run completes and prints the completion line) and state C (same) — and
// a refused completion is printed, not recorded.
func TestAuditSealCrashStatesComplete(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	for _, tc := range []struct{ hook, state string }{{"after_link_before_seal", "A'"}, {"after_seal_before_manifest", "B"}, {"after_manifest_before_swap", "C"}} {
		t.Run(tc.hook, func(t *testing.T) {
			root := sealSample(t)
			ctl := applied(t, root)
			t.Setenv("AGENTHOF_TEST_CRASH_AT", tc.hook)
			code, out := auditSeal(t, ctl)
			t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
			if code != 1 {
				t.Fatalf("%d\n%s", code, out)
			}
			if tc.state != "A'" && !strings.Contains(out, "sealed; rotation NOT completed — re-run: agenthof audit seal") {
				t.Fatalf("%s", out)
			}
			var buf bytes.Buffer
			code = cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf)
			if tc.state == "A'" {
				if code != 0 {
					t.Fatalf("A′ appends: %d\n%s", code, buf.String())
				}
			} else if code != 1 || !strings.Contains(buf.String(), "the active segment is sealed and not yet rotated; run: agenthof audit seal") || strings.Contains(buf.String(), "audit repair control") {
				t.Fatalf("%s: writers print the completion hint: %d\n%s", tc.state, code, buf.String())
			}
			if tc.state != "A'" {
				var mallory bytes.Buffer
				if code := cmdAudit([]string{"seal", "--control-log", ctl, "--as", "mallory@example.com", "--groups", "finance"}, &mallory); code != 1 || !strings.Contains(mallory.String(), "not authorized") || strings.Contains(mallory.String(), "control head:") {
					t.Fatalf("a refused completion is printed, not recorded: %d\n%s", code, mallory.String())
				}
			}
			code, out = auditSeal(t, ctl)
			if code != 0 {
				t.Fatalf("completion: %d\n%s", code, out)
			}
			if tc.state != "A'" && !strings.Contains(out, "completed rotation of segment 1\n") {
				t.Fatalf("%s", out)
			}
			v, err := control.Read(ctl, ledger.Locked)
			if err != nil || v.State != control.StateOpen || len(v.Sealed) != 1 {
				t.Fatalf("%v %+v", err, v)
			}
		})
	}
}

// TestAuditSealThroughASymlink: --control-log is a symlink; the segments and
// the manifest appear beside the real file, the link still points at the
// new empty active, and Read through either name is the same View.
func TestAuditSealThroughASymlink(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	real := applied(t, sealSample(t))
	link := filepath.Join(filepath.Dir(real), "link.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if code, out := auditSeal(t, link); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	if _, err := os.Stat(control.SegmentPath(real, 1)); err != nil {
		t.Fatal("the segment lives beside the real file")
	}
	if _, err := os.Lstat(control.ManifestPath(link)); err == nil {
		t.Fatal("nothing is created beside the link")
	}
	fi, _ := os.Lstat(link)
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link must survive the swap")
	}
	a, _ := control.Read(real, ledger.Locked)
	b, _ := control.Read(link, ledger.Locked)
	if a.Head != b.Head || len(a.Sealed) != len(b.Sealed) || a.Active.Path != b.Active.Path {
		t.Fatalf("%+v vs %+v", a, b)
	}
}

// TestApplyOnStateBOverTheAPI: POST /v1/config/apply on a state-B root →
// 500 {status:"rotation_incomplete"}, nothing recorded, never ledger_damaged.
func TestApplyOnStateBOverTheAPI(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, sealSample(t))
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_manifest")
	auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	before, _ := control.Read(ctl, ledger.Locked)
	res := (&configHost{controlLog: ctl, allowBootstrap: false, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Apply(identity.Static("dana@example.com"), map[string][]byte{"roles/x.yaml": []byte("name: x\n")}, apiclient.Precondition{ExpectNone: true}, nil)
	if res.Status != apiclient.ApplyRotationIncomplete || res.Reason != apiclient.ReasonRotationIncomplete {
		t.Fatalf("%+v", res)
	}
	after, _ := control.Read(ctl, ledger.Locked)
	if after.Head != before.Head {
		t.Fatal("nothing recorded")
	}
}

// TestAuditSealRefusesGenesisWithoutLogID: a root older than the genesis
// log_id authorizes (the vouch stops at LastInstalling) and is then refused
// before anything is linked or recorded — it cannot be rotated, so it remains
// a single, still-writable file; the message names no re-run.
func TestAuditSealRefusesGenesisWithoutLogID(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	hash := installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, seal]\n"})
	c, err := ledger.Open(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"v":"control/1","seq":1,"time":"2026-10-09T02:12:01Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"h"},"config_hash":"` + hash + `","prev":""}`
	if err := c.Append([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	before, _ := os.ReadFile(ctl)
	code, out := auditSeal(t, ctl)
	if code != 1 || !strings.Contains(out, "audit seal: control: the control ledger genesis carries no log_id; it cannot be sealed and remains a single file") || strings.Contains(out, "re-run") || strings.Contains(out, "control head:") {
		t.Fatalf("%d\n%s", code, out)
	}
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
		t.Fatal("nothing recorded")
	}
	entries, _ := os.ReadDir(filepath.Dir(ctl))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".seg") {
			t.Fatalf("nothing linked: %s", e.Name())
		}
	}
	if err := control.Writable(ctl); err != nil {
		t.Fatalf("the root stays writable: %v", err)
	}
}

// wormPostureFor writes a sink: worm posture beside ctl naming the fake's
// bucket plus prefix, and places the fake's key pair in the two env NAMES
// the posture names.
func wormPostureFor(t *testing.T, ctl string, f *sinktest.Fake, prefix, retention string) {
	t.Helper()
	writeIntegrity(t, ctl, "sink: worm\nsink_backend:\n  kind: s3-object-lock\n  url: "+f.URL()+prefix+"\n  mode: compliance\n  retention: "+retention+"\n  credential:\n    credential_source: static_env\n    client_auth: sigv4\n    client_id_env: AGENTHOF_TEST_WORM_ID\n    client_secret_env: AGENTHOF_TEST_WORM_SECRET\n")
	t.Setenv("AGENTHOF_TEST_WORM_ID", f.KeyID)
	t.Setenv("AGENTHOF_TEST_WORM_SECRET", f.Secret)
}

// wormRoot is sealedRoot's root before its seal, under a worm posture: apply,
// one disable, the posture.
func wormRoot(t *testing.T) (string, string, *sinktest.Fake) {
	t.Helper()
	root := sealSample(t)
	ctl := applied(t, root)
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	f := sinktest.NewFake(t)
	wormPostureFor(t, ctl, f, "/agenthof", "1d")
	return root, ctl, f
}

// wormSealedRoot is sealedRoot under a worm posture: segment 1 = seq 1–3
// with a sink block, its copy in the fake.
func wormSealedRoot(t *testing.T) (string, *sinktest.Fake) {
	t.Helper()
	_, ctl, f := wormRoot(t)
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal: %d\n%s", code, out)
	}
	return ctl, f
}

// segmentKey is the fake's key for segment n of ctl's ledger under the
// "agenthof" prefix. A set fault (a torn root) still yields the verified
// prefix, and the genesis is in it.
func segmentKey(t *testing.T, ctl string, n int) string {
	t.Helper()
	v, err := control.Read(ctl, ledger.Locked)
	var se *control.SetError
	if err != nil && !errors.As(err, &se) {
		t.Fatal(err)
	}
	id, err := control.GenesisLogID(v.Records)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("agenthof/%s/seg-%06d", id, n)
}

func noSegmentSibling(t *testing.T, ctl string) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Dir(ctl))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".seg") {
			t.Fatalf("nothing linked, no manifest: %s", e.Name())
		}
	}
}

func fakeHost(f *sinktest.Fake) string {
	return strings.TrimPrefix(f.URL(), "http://")[:strings.Index(strings.TrimPrefix(f.URL(), "http://"), "/")]
}

// TestAuditSealWormPrintsProtected: the protected: line, immediately before
// sealed:, names the record's block and the sink's receipt; the fake holds
// exactly one version at the key whose bytes are the sealed file; the lock
// the fake holds is at least the block's retain_until (the sink locks to
// the later of the record's date and its retention from now, so a second
// boundary between the record and the PUT may make it a second longer).
func TestAuditSealWormPrintsProtected(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := wormRoot(t)
	code, out := auditSeal(t, ctl)
	if code != 0 || !regexp.MustCompile(`(?m)^protected: s3-object-lock http://127\.0\.0\.1:\d+/worm/agenthof key=agenthof/[0-9a-f]{32}/seg-000001 version=v-1 compliance until 20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ\nsealed: segment 1 seq=1\.\.3 `).MatchString(out) || strings.Contains(out, "already confirmed") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	key := segmentKey(t, ctl, 1)
	vs := f.Versions(key)
	seg, _ := os.ReadFile(control.SegmentPath(ctl, 1))
	if len(vs) != 1 || !bytes.Equal(vs[0].Data, seg) || vs[0].Mode != "COMPLIANCE" {
		t.Fatalf("versions at %s: %+v", key, vs)
	}
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil || v.Sealed[0].Sink == nil || vs[0].Until.Before(v.Sealed[0].Sink.RetainUntil) || v.Sealed[0].Sink.Key != key {
		t.Fatalf("%v %+v vs %+v", err, v.Sealed[0].Sink, vs[0])
	}
}

// TestAuditSealFloorPrintsNoProtectedLine: without a posture there is no
// protected: line.
func TestAuditSealFloorPrintsNoProtectedLine(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, sealSample(t))
	code, out := auditSeal(t, ctl)
	if code != 0 || strings.Contains(out, "protected:") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// TestSealPreflightRefusalRecordsNothing: a bucket without Object Lock, and
// a credential that cannot list, are refused before anything is linked or
// recorded — the cause only, no re-run line, no head line.
func TestSealPreflightRefusalRecordsNothing(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	for name, want := range map[string]string{
		"lock disabled": "audit seal: bucket worm does not have Object Lock enabled; enable it on the bucket (versioning is required) before sink: worm\n",
		"list denied":   "audit seal: status 403 AccessDenied from HOST (ListObjectVersions)\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, ctl, f := wormRoot(t)
			if name == "lock disabled" {
				f.LockDisabled = true
			} else {
				f.Deny = map[string]bool{"ListObjectVersions": true}
			}
			before, _ := os.ReadFile(ctl)
			code, out := auditSeal(t, ctl)
			if code != 1 || out != strings.ReplaceAll(want, "HOST", fakeHost(f)) {
				t.Fatalf("%d\n%s", code, out)
			}
			noSegmentSibling(t, ctl)
			if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
				t.Fatal("nothing recorded")
			}
			if err := control.Writable(ctl); err != nil {
				t.Fatalf("the root stays writable: %v", err)
			}
		})
	}
}

const sealStateBLine = "audit seal: sealed; protected copy NOT confirmed — rotation NOT completed; re-run: agenthof audit seal\n"

// TestSealPutOnlyCredentialLandsInStateB: a credential that can PUT
// but not read the lock back lands the seal in state B naming the IAM
// remedy; writers refuse, verify exits 8; a re-run with the same policy
// fails the same way without a second PUT — its line says the copy was
// already at the key, since that run wrote nothing; once the policy is
// fixed the re-run confirms the copy already there and completes.
func TestSealPutOnlyCredentialLandsInStateB(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root, ctl, f := wormRoot(t)
	f.Deny = map[string]bool{"GetObjectRetention": true}
	want := "audit seal: protected copy written but NOT confirmed: the credential cannot read the object's retention; grant s3:GetObjectRetention, s3:GetObject and s3:ListBucketVersions, then re-run (status 403 AccessDenied from " + fakeHost(f) + " (GetObjectRetention))\n" + sealStateBLine
	code, out := auditSeal(t, ctl)
	if code != 1 || out != want {
		t.Fatalf("%d\n%s", code, out)
	}
	key := segmentKey(t, ctl, 1)
	if vs := f.Versions(key); len(vs) != 1 {
		t.Fatalf("one version: %+v", vs)
	}
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 1 || !strings.Contains(buf.String(), "the active segment is sealed and not yet rotated; run: agenthof audit seal") {
		t.Fatalf("writers refuse: %d\n%s", code, buf.String())
	}
	if code, out := verifyControl(t, "--control-log", ctl); code != 8 {
		t.Fatalf("verify: %d\n%s", code, out)
	}
	code, out = auditSeal(t, ctl)
	if rerun := strings.Replace(want, "protected copy written but", "protected copy already at the key but", 1); code != 1 || out != rerun {
		t.Fatalf("re-run with the policy unchanged: %d\n%s", code, out)
	}
	if vs := f.Versions(key); len(vs) != 1 {
		t.Fatalf("still one version: %+v", vs)
	}
	delete(f.Deny, "GetObjectRetention")
	code, out = auditSeal(t, ctl)
	if code != 0 || !strings.HasPrefix(out, "completed rotation of segment 1\nprotected: s3-object-lock ") || !regexp.MustCompile(`(?m)^protected: .* version=v-1 compliance until 20[0-9T:-]+Z \(already confirmed\)\nsealed: `).MatchString(out) {
		t.Fatalf("re-run after the fix: %d\n%s", code, out)
	}
	if vs := f.Versions(key); len(vs) != 1 {
		t.Fatalf("still one version: %+v", vs)
	}
	puts := 0
	for _, req := range f.Requests() {
		if req.Op == "PutObject" {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("%d PutObject requests, want 1", puts)
	}
}

// TestRotateRefusesOccupiedKeyLeavesStateB (through the seal): a
// foreign object at the seal's key is refused by the preflight with nothing
// linked or recorded; planted after the record, it is refused by the
// completion with no PUT and state B stands.
func TestRotateRefusesOccupiedKeyLeavesStateB(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, ctl, f := wormRoot(t)
	key := segmentKey(t, ctl, 1)
	f.Plant(key, []byte("foreign\n"), "COMPLIANCE", far)
	before, _ := os.ReadFile(ctl)
	code, out := auditSeal(t, ctl)
	if code != 1 || !strings.Contains(out, "audit seal: key "+key+" is occupied by a version, and a fresh seal's key must be empty") || strings.Contains(out, "re-run") || strings.Contains(out, "control head:") {
		t.Fatalf("%d\n%s", code, out)
	}
	noSegmentSibling(t, ctl)
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
		t.Fatal("nothing recorded")
	}

	_, ctl, f = wormRoot(t)
	key = segmentKey(t, ctl, 1)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_sink")
	code, out = auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code != 1 || !strings.HasSuffix(out, sealStateBLine) {
		t.Fatalf("hook: %d\n%s", code, out)
	}
	f.Plant(key, []byte("foreign\n"), "COMPLIANCE", far)
	code, out = auditSeal(t, ctl)
	// State B: the refusal names the fork and the bound on this key — never
	// a fresh prefix (the record's URL is pinned) or a removal compliance
	// mode forbids.
	if code != 1 || !strings.Contains(out, "audit seal: key "+key+" is occupied by a version that is not this segment, and the seal never writes on top: another writer landed an object at this ledger's key first — a fork;") || !strings.Contains(out, "a compliance-locked version blocks the key until its retention ends") || strings.Contains(out, "fresh prefix") || !strings.HasSuffix(out, sealStateBLine) {
		t.Fatalf("re-run: %d\n%s", code, out)
	}
	if v, err := control.Read(ctl, ledger.Locked); err != nil || v.State != control.StateSealedNotRotated {
		t.Fatalf("state B stands: %v %+v", err, v.State)
	}
	for _, req := range f.Requests() {
		if req.Op == "PutObject" {
			t.Fatal("never written on top of a foreign object")
		}
	}
}

// TestSealSinkTimeoutAndPostureBuild: --sink-timeout bounds each sink call
// (the preflight times out, nothing recorded); a malformed value is usage.
func TestSealSinkTimeoutAndPostureBuild(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := wormRoot(t)
	f.Slow = 50 * time.Millisecond
	before, _ := os.ReadFile(ctl)
	code, out := auditSeal(t, ctl, "--sink-timeout", "1ms")
	if code != 1 || !strings.Contains(out, fakeHost(f)) || !strings.Contains(out, "deadline") || strings.Contains(out, "re-run") {
		t.Fatalf("%d\n%s", code, out)
	}
	noSegmentSibling(t, ctl)
	if after, _ := os.ReadFile(ctl); !bytes.Equal(before, after) {
		t.Fatal("nothing recorded")
	}
	if code, out := auditSeal(t, ctl, "--sink-timeout", "0x"); code != 2 || !strings.Contains(out, "sink-timeout") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// TestSealPostureFlippedToLocalRefusesCompletion (through the command):
// a state-B worm root whose integrity.yaml now says local is refused with
// the record's own coordinates; restoring the posture completes it.
func TestSealPostureFlippedToLocalRefusesCompletion(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := wormRoot(t)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_sink")
	code, out := auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code != 1 {
		t.Fatalf("hook: %d\n%s", code, out)
	}
	writeIntegrity(t, ctl, "sink: local\n")
	code, out = auditSeal(t, ctl)
	if code != 1 || out != "audit seal: segment 1 was sealed for a protected copy at s3-object-lock "+f.URL()+"/agenthof; integrity.yaml no longer names it — restore that posture to complete the rotation\n"+sealStateBLine {
		t.Fatalf("flipped: %d\n%s", code, out)
	}
	wormPostureFor(t, ctl, f, "/agenthof", "1d")
	code, out = auditSeal(t, ctl)
	if code != 0 || !strings.HasPrefix(out, "completed rotation of segment 1\nprotected: ") {
		t.Fatalf("restored: %d\n%s", code, out)
	}
}

// TestAuditSealWormThroughTheWriters: after a worm seal the writers append
// as today — the sink never touches the active.
func TestAuditSealWormThroughTheWriters(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root, ctl, _ := wormRoot(t)
	if code, out := auditSeal(t, ctl); code != 0 {
		t.Fatalf("seal: %d\n%s", code, out)
	}
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 || !strings.Contains(buf.String(), "control head: seq=4 ") {
		t.Fatalf("disable after a worm seal: %d\n%s", code, buf.String())
	}
	if _, f := wormSealedRoot(t); len(f.Requests()) == 0 {
		t.Fatal("the fixture reached the fake")
	}
}

// backdateSealLine rewrites the seal line that ends a state-B active so the
// record was sealed at sealedAt with its copy due until retainUntil — the
// shape of a rotation left incomplete until its retention lapsed. Nothing
// chains from the active's last line yet, so only that line changes, and it
// is rewritten in place: the segment name is a hard link to the same inode.
func backdateSealLine(t *testing.T, ctl string, sealedAt, retainUntil time.Time) {
	t.Helper()
	raw, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	var rec map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &rec); err != nil {
		t.Fatal(err)
	}
	rec["time"] = sealedAt.UTC().Format(time.RFC3339)
	rec["seal"].(map[string]any)["sink"].(map[string]any)["retain_until"] = retainUntil.UTC().Format(time.RFC3339)
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	lines[len(lines)-1] = line
	if err := os.WriteFile(ctl, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSealCompletesAfterTheRetentionLapsed (never a permanent wedge):
// a worm root left in state B until its recorded retain_until has passed
// still completes — the sink locks the copy from now, at least the
// configured retention, and verify holds the lock to the recorded date.
func TestSealCompletesAfterTheRetentionLapsed(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	_, ctl, f := wormRoot(t)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_seal_before_sink")
	code, out := auditSeal(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if code != 1 || !strings.HasSuffix(out, sealStateBLine) {
		t.Fatalf("hook: %d\n%s", code, out)
	}
	now := time.Now()
	backdateSealLine(t, ctl, now.Add(-72*time.Hour), now.Add(-48*time.Hour))
	if v, err := control.Read(ctl, ledger.Locked); err != nil || v.State != control.StateSealedNotRotated {
		t.Fatalf("the backdated root reads as state B: %v %+v", err, v.State)
	}
	code, out = auditSeal(t, ctl)
	if code != 0 || !strings.HasPrefix(out, "completed rotation of segment 1\nprotected: s3-object-lock ") {
		t.Fatalf("completion after the retention lapsed: %d\n%s", code, out)
	}
	key := segmentKey(t, ctl, 1)
	vs := f.Versions(key)
	if len(vs) != 1 || vs[0].Mode != "COMPLIANCE" || vs[0].Until.Before(now.Add(24*time.Hour-time.Minute)) {
		t.Fatalf("the copy is locked from now for the configured retention: %+v", vs)
	}
	code, vout := verifyControl(t, "--control-log", ctl)
	if code != 0 || !strings.Contains(vout, "verified — oldest version v-1 compliance until") || !strings.Contains(vout, "protected copies: 1 (1 verified, 0 missing, 0 mismatch, 0 under-locked, 0 unverifiable)") {
		t.Fatalf("verify: %d\n%s", code, vout)
	}
}
