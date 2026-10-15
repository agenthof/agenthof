package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
