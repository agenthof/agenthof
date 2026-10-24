package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// writeIntegrity writes body as integrity.yaml beside ctl and returns its path.
func writeIntegrity(t *testing.T, ctl, body string) string {
	t.Helper()
	p := integrityPath(ctl)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// reservedPosture is the one reserved file every CLI test uses, and
// reservedFault is the exact line a command prints for it (after its own
// "<command>: " prefix). signed is the value still reserved in this build.
const reservedPosture = "anchor: signed\n"

func reservedFault(path string) string {
	return "integrity " + path + `: anchor "signed" is reserved and not yet supported in this build (only none and tlog are implemented)`
}

// wormMisconfigure is a sink: worm posture the build refuses (governance
// mode can be lifted by a privileged user), and wormFault the exact line a
// command prints for it after its own "<command>: " prefix.
const wormMisconfigure = "sink: worm\nsink_backend:\n  kind: s3-object-lock\n  url: https://s3.example/bucket\n  mode: governance\n  retention: 7y\n"

func wormFault(path string) string {
	return "integrity " + path + `: sink_backend.mode "governance" is refused: a governance-mode lock can be bypassed by a privileged user; use compliance`
}

// tlogPosture is a complete, accepted tlog posture naming a log nothing in
// these tests ever dials: the writers must proceed without contacting it.
const tlogPosture = "anchor: tlog\nanchor_backend:\n  url: http://127.0.0.1:9\n"

// TestIntegrityPathIsBesideTheControlLedger: derived from the ledger's
// directory and nowhere else, like installed.lock and verify.pub.
func TestIntegrityPathIsBesideTheControlLedger(t *testing.T) {
	if got := integrityPath("/srv/agenthof/control.jsonl"); got != "/srv/agenthof/integrity.yaml" {
		t.Fatalf("integrityPath = %q", got)
	}
}

// TestLoadIntegrityAbsentIsTheFloor: no file, and no root directory at all
// (a fresh root ledger.Open would create), are both the floor with no error.
func TestLoadIntegrityAbsentIsTheFloor(t *testing.T) {
	for name, ctl := range map[string]string{
		"no file":      filepath.Join(t.TempDir(), "control.jsonl"),
		"no directory": filepath.Join(t.TempDir(), "nope", "control.jsonl"),
	} {
		in, err := loadIntegrity(ctl)
		if err != nil || in.Sink != "" || in.Anchor != "" || len(in.Duplicate) != 0 || in.SinkBackend.IsSet() || in.AnchorBackend.IsSet() {
			t.Fatalf("%s: loadIntegrity = %+v, %v; want the floor, nil", name, in, err)
		}
	}
}

// TestLoadIntegrityFloorFileIsTheFloor: a present file saying the floor
// loads as the floor.
func TestLoadIntegrityFloorFileIsTheFloor(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	writeIntegrity(t, ctl, "sink: local\nanchor: none\n")
	in, err := loadIntegrity(ctl)
	if err != nil || in.Sink != "local" || in.Anchor != "none" {
		t.Fatalf("loadIntegrity = %+v, %v", in, err)
	}
}

// TestLoadIntegrityNamesTheFileOnce: a reserved posture, a shape fault, a
// dangling symlink and an unreadable file are each an error — never the floor
// — naming the path exactly once: the package reports the bare fault, and an
// OS read error's own path (a *fs.PathError) is stripped so it is not named
// twice.
func TestLoadIntegrityNamesTheFileOnce(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	p := writeIntegrity(t, ctl, reservedPosture)
	_, err := loadIntegrity(ctl)
	if err == nil || err.Error() != reservedFault(p) {
		t.Fatalf("reserved: err = %v\nwant %q", err, reservedFault(p))
	}
	if strings.Count(err.Error(), p) != 1 {
		t.Fatalf("the path must appear exactly once: %q", err)
	}

	writeIntegrity(t, ctl, "ancher: tlog\n")
	_, err = loadIntegrity(ctl)
	if want := "integrity " + p + `: line 1: unknown key "ancher" (allowed keys: sink, anchor, duplicate, sink_backend, anchor_backend)`; err == nil || err.Error() != want {
		t.Fatalf("malformed: err = %v\nwant %q", err, want)
	}

	writeIntegrity(t, ctl, "sink: local\n---\nanchor: tlog\n")
	_, err = loadIntegrity(ctl)
	if want := "integrity " + p + ": more than one YAML document; integrity.yaml holds exactly one"; err == nil || err.Error() != want {
		t.Fatalf("multi-document: err = %v\nwant %q", err, want)
	}

	// A dangling symlink is a present directory entry whose read fails: a
	// fault, not a missing file — a broken target never silently floors.
	dctl := filepath.Join(t.TempDir(), "control.jsonl")
	dp := integrityPath(dctl)
	if err := os.Symlink(filepath.Join(filepath.Dir(dctl), "gone.yaml"), dp); err != nil {
		t.Fatal(err)
	}
	_, err = loadIntegrity(dctl)
	if want := "integrity " + dp + ": no such file or directory"; err == nil || err.Error() != want {
		t.Fatalf("dangling symlink: err = %v\nwant %q", err, want)
	}
	if strings.Count(err.Error(), dp) != 1 {
		t.Fatalf("the path must appear exactly once: %q", err)
	}

	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions are not enforced, cannot provoke the read error")
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	_, err = loadIntegrity(ctl)
	if want := "integrity " + p + ": permission denied"; err == nil || err.Error() != want {
		t.Fatalf("unreadable: err = %v\nwant %q", err, want)
	}
	if strings.Count(err.Error(), p) != 1 {
		t.Fatalf("the PathError's own path must be stripped: %q", err)
	}
}

// TestControlWritersRefuseAReservedPosture: with integrity.yaml saying
// anchor: tlog beside the ledger, each CLI writer prints its own prefix, the
// fault naming the file once, and exits 2 — not the ledger-damaged exit 1 —
// before anything is recorded: on a fresh root no ledger and no store are
// created; on an applied root the ledger bytes and the pointer are unchanged.
func TestControlWritersRefuseAReservedPosture(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test") // provision's earlier exit-2 class must not be what fires

	// A fresh root: apply is the bootstrap; nothing may appear.
	root := writeSample(t)
	fresh := filepath.Join(t.TempDir(), "control.jsonl")
	p := writeIntegrity(t, fresh, reservedPosture)
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", fresh, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 2 || !strings.Contains(out.String(), "apply: "+reservedFault(p)+"\n") {
		t.Fatalf("fresh apply: exit %d\n%s", code, out.String())
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("no genesis may be written: stat err = %v", err)
	}
	if _, err := os.Stat(installedStore(fresh)); !os.IsNotExist(err) {
		t.Fatalf("nothing may be installed: stat err = %v", err)
	}

	// An applied root: every writer, ledger and pointer byte-identical after.
	ctl := applied(t, root)
	p = writeIntegrity(t, ctl, reservedPosture)
	before, pointer := ledgerBytes(t, ctl), readPointer(t, ctl)
	for _, c := range []struct {
		name, prefix string
		run          func(out *bytes.Buffer) int
	}{
		{"apply", "apply", func(out *bytes.Buffer) int {
			return cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, out)
		}},
		{"registry disable", "registry disable", func(out *bytes.Buffer) int {
			return cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, out)
		}},
		{"registry enable", "registry enable", func(out *bytes.Buffer) int {
			return cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, out)
		}},
		{"config vouch", "config vouch", func(out *bytes.Buffer) int {
			return cmdConfigVouch([]string{"--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, out)
		}},
		{"gateway provision", "gateway provision", func(out *bytes.Buffer) int {
			return cmdGateway(provisionArgs(ctl, "http://127.0.0.1:0"), out) // never dialed
		}},
		{"runs prune", "runs prune", func(out *bytes.Buffer) int {
			return cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir(), "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, out)
		}},
	} {
		var out bytes.Buffer
		code := c.run(&out)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2\n%s", c.name, code, out.String())
		}
		if want := c.prefix + ": " + reservedFault(p) + "\n"; !strings.Contains(out.String(), want) {
			t.Fatalf("%s: missing %q\n%s", c.name, want, out.String())
		}
		if strings.Contains(out.String(), "control ledger damaged") || strings.Contains(out.String(), "control head:") {
			t.Fatalf("%s: must refuse before the ledger is touched:\n%s", c.name, out.String())
		}
		if !bytes.Equal(before, ledgerBytes(t, ctl)) {
			t.Fatalf("%s: the ledger must be byte-identical", c.name)
		}
		if readPointer(t, ctl) != pointer {
			t.Fatalf("%s: the pointer must not move", c.name)
		}
	}
}

// TestAllWritersRefuseAWormMisconfigure: a sink: worm posture the build cannot
// honour is refused at every loadIntegrity caller exactly as a reserved one is
// — the caller's own prefix, the fault naming the file once, exit 2, nothing
// recorded — never silently read as the floor.
func TestAllWritersRefuseAWormMisconfigure(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")

	root := writeSample(t)
	fresh := filepath.Join(t.TempDir(), "control.jsonl")
	p := writeIntegrity(t, fresh, wormMisconfigure)
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", fresh, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 2 || !strings.Contains(out.String(), "apply: "+wormFault(p)+"\n") {
		t.Fatalf("fresh apply: exit %d\n%s", code, out.String())
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("no genesis may be written: stat err = %v", err)
	}

	ctl := applied(t, root)
	p = writeIntegrity(t, ctl, wormMisconfigure)
	before, pointer := ledgerBytes(t, ctl), readPointer(t, ctl)
	who := []string{"--as", "dana@example.com", "--groups", "platform-eng"}
	for _, c := range []struct {
		name, prefix string
		run          func(out *bytes.Buffer) int
	}{
		{"apply", "apply", func(out *bytes.Buffer) int {
			return cmdApply(append([]string{"--config", root, "--control-log", ctl}, who...), out)
		}},
		{"registry disable", "registry disable", func(out *bytes.Buffer) int {
			return cmdRegistry(append([]string{"disable", "coder", "--config", root, "--control-log", ctl}, who...), out)
		}},
		{"config vouch", "config vouch", func(out *bytes.Buffer) int {
			return cmdConfigVouch(append([]string{"--control-log", ctl}, who...), out)
		}},
		{"gateway provision", "gateway provision", func(out *bytes.Buffer) int {
			return cmdGateway(provisionArgs(ctl, "http://127.0.0.1:0"), out) // never dialed
		}},
		{"runs prune", "runs prune", func(out *bytes.Buffer) int {
			return cmdRuns(append([]string{"prune", "--older-than", "180d", "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir(), "--control-log", ctl}, who...), out)
		}},
		{"audit seal", "audit seal", func(out *bytes.Buffer) int {
			return cmdAuditSeal(append([]string{"--control-log", ctl}, who...), out)
		}},
		{"audit anchor", "audit anchor", func(out *bytes.Buffer) int {
			return cmdAuditAnchor(append([]string{"--control-log", ctl}, who...), out)
		}},
	} {
		var out bytes.Buffer
		if code := c.run(&out); code != 2 {
			t.Fatalf("%s: exit %d, want 2\n%s", c.name, code, out.String())
		}
		if want := c.prefix + ": " + wormFault(p) + "\n"; !strings.Contains(out.String(), want) {
			t.Fatalf("%s: missing %q\n%s", c.name, want, out.String())
		}
		if strings.Count(out.String(), p) != 1 {
			t.Fatalf("%s: the path must appear exactly once:\n%s", c.name, out.String())
		}
		if !bytes.Equal(before, ledgerBytes(t, ctl)) || readPointer(t, ctl) != pointer {
			t.Fatalf("%s: nothing may be recorded", c.name)
		}
	}

	// audit repair control: after authorization, on a torn ledger.
	tctl, torn := tornLedger(t)
	tp := writeIntegrity(t, tctl, wormMisconfigure)
	out.Reset()
	code := cmdAuditRepairControl([]string{"control", "--control-log", tctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 2 || !strings.Contains(out.String(), "audit repair control: "+wormFault(tp)+"\n") {
		t.Fatalf("audit repair control: exit %d\n%s", code, out.String())
	}
	if after, err := os.ReadFile(tctl); err != nil || !bytes.Equal(after, torn) {
		t.Fatalf("the torn tail must be untouched: %v", err)
	}

	// serve refuses to start.
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out.Reset()
	code = cmdServe(ctx, []string{"--addr", "127.0.0.1:0", "--control-log", ctl, "--log-dir", t.TempDir()}, &out, io.Discard)
	if code != 2 || !strings.Contains(out.String(), "serve: "+wormFault(p)+"\n") || strings.Contains(out.String(), "serving on") {
		t.Fatalf("serve: exit %d\n%s", code, out.String())
	}
}

// TestControlWritersProceedOnATlogRoot: with a complete tlog posture beside
// the ledger, apply, both flips, config vouch, gateway provision, runs prune
// and serve's startup all proceed exactly as at the floor — unanchored — and
// write their usual records with no "anchor" key and no mention of the
// posture: anchoring is a separate, operator-triggered action.
func TestControlWritersProceedOnATlogRoot(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	writeIntegrity(t, ctl, tlogPosture)
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	for _, flip := range []string{"disable", "enable"} {
		out.Reset()
		if code := cmdRegistry([]string{flip, "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
			t.Fatalf("%s: %d\n%s", flip, code, out.String())
		}
	}
	crashGap(t, root, ctl)
	vouchAs(t, ctl)
	srv, _ := adminMock(t, 0, "")
	t.Chdir(t.TempDir())
	out.Reset()
	if code := cmdGateway(provisionArgs(ctl, srv.URL), &out); code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir()), &out); code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if logs := startServeOnce(t, ctl); strings.Contains(logs, "integrity") {
		t.Fatalf("serve must start silently on a tlog root:\n%s", logs)
	}
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if strings.Contains(string(r.Raw), `"anchor"`) {
			t.Fatalf("a writer on a tlog root must not emit an anchor key: %s", r.Raw)
		}
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		seen[d.Action] = true
	}
	for _, action := range []string{"apply", "disable", "enable", "vouch", "provision", "prune"} {
		if !seen[action] {
			t.Fatalf("no %q record (saw %v)", action, seen)
		}
	}
}

// TestAuditRepairControlRefusesAReservedPostureAfterAuthz: an authorized
// caller on a torn ledger under a reserved posture is refused with exit 2,
// the torn tail is left exactly as it was, and no fragment is written.
func TestAuditRepairControlRefusesAReservedPostureAfterAuthz(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t) // nothing installed: repair authorizes against --config's roles
	ctl, torn := tornLedger(t)
	p := writeIntegrity(t, ctl, reservedPosture)
	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 2 || !strings.Contains(out.String(), "audit repair control: "+reservedFault(p)+"\n") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	after, err := os.ReadFile(ctl)
	if err != nil || !bytes.Equal(after, torn) {
		t.Fatalf("the torn tail must be untouched: %v\n%s", err, after)
	}
	if matches, _ := filepath.Glob(ctl + ".torn-*"); len(matches) != 0 {
		t.Fatalf("no fragment may be written: %v", matches)
	}
}

// TestAuditRepairControlDisclosesNoPostureBeforeAuthz: the posture is read
// only after authorization succeeds. A caller no role grants repair gets the
// existing not-authorized line and exit 1; a refused token gets the existing
// token line and exit 1; neither output mentions the posture or names the
// root directory, and nothing on disk changes.
func TestAuditRepairControlDisclosesNoPostureBeforeAuthz(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl, torn := tornLedger(t)
	writeIntegrity(t, ctl, reservedPosture)
	dir := filepath.Dir(ctl)

	var out bytes.Buffer
	code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "mallory@example.com", "--groups", "finance"}, &out)
	if code != 1 || !strings.Contains(out.String(), "audit repair control: not authorized: no role grants repair to the invoker") {
		t.Fatalf("unauthorized: exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "integrity") || strings.Contains(out.String(), dir) {
		t.Fatalf("an unauthorized caller must learn nothing about the root:\n%s", out.String())
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := cmdTestOIDCServer(t, key)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	badToken := cmdMintToken(t, otherKey, map[string]any{
		"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-123", "email": "ops@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")
	out.Reset()
	code = cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--token", badToken}, &out)
	if code != 1 || !strings.Contains(out.String(), "token authentication failed") {
		t.Fatalf("refused token: exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "integrity") || strings.Contains(out.String(), dir) {
		t.Fatalf("an unauthenticated caller must learn nothing about the root:\n%s", out.String())
	}
	after, err := os.ReadFile(ctl)
	if err != nil || !bytes.Equal(after, torn) {
		t.Fatalf("nothing may change: %v", err)
	}
}

// TestServeRefusesToStartOnAReservedPosture: serve reads the posture once
// at startup and refuses to start — exit 2, nothing listening — on one it
// cannot honour; with the floor written explicitly it starts exactly as
// before. A server that started at the floor on a reserved root would write
// every API apply unanchored, so warn-and-continue is wrong here.
func TestServeRefusesToStartOnAReservedPosture(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, writeSample(t))
	p := writeIntegrity(t, ctl, reservedPosture)
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test") // set, so the posture is the only fault
	// A bounded context: a serve that wrongly starts must still return (exit
	// 0 on the context ending), so the test fails instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	code := cmdServe(ctx, []string{"--addr", "127.0.0.1:0", "--control-log", ctl, "--log-dir", t.TempDir()}, &out, io.Discard)
	if code != 2 || !strings.Contains(out.String(), "serve: "+reservedFault(p)+"\n") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "serving on") {
		t.Fatalf("nothing may listen:\n%s", out.String())
	}

	writeIntegrity(t, ctl, "sink: local\nanchor: none\n")
	logs := startServeOnce(t, ctl) // fatals unless serve starts and exits 0
	if strings.Contains(logs, "integrity") {
		t.Fatalf("the floor must not be mentioned at startup:\n%s", logs)
	}
}

// floorScenario runs apply, disable, enable, and a vouch of an unrecorded
// re-apply against ctl, with or without a floor integrity.yaml beside it,
// and returns the decoded records with Time zeroed plus the masked reader
// outputs (run against logDir). root must be byte-identical across calls so
// every hash matches.
func floorScenario(t *testing.T, root, ctl, logDir string, floorFile bool) ([]control.DecodedEvent, []string) {
	t.Helper()
	if floorFile {
		writeIntegrity(t, ctl, "sink: local\nanchor: none\nduplicate: []\nsink_backend: {}\n")
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	for _, flip := range []string{"disable", "enable"} {
		out.Reset()
		if code := cmdRegistry([]string{flip, "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
			t.Fatalf("%s: %d\n%s", flip, code, out.String())
		}
	}
	crashGap(t, root, ctl)
	vouchAs(t, ctl)

	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	var events []control.DecodedEvent
	for _, r := range recs {
		if strings.Contains(string(r.Raw), `"anchor"`) {
			t.Fatalf("no floor record may carry an anchor key: %s", r.Raw)
		}
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		d.Time = time.Time{}
		events = append(events, d)
	}
	return events, readerOutputs(t, ctl, logDir)
}

// readerOutputs runs the four readers against ctl (and the run logs under
// logDir — one shared, empty directory per test, so a path printed by any
// reader is the same across the runs being compared) and returns their exit
// codes and outputs with the per-run noise masked: timestamps, 64-hex
// hashes, the ledger's log_id, and the root directory.
func readerOutputs(t *testing.T, ctl, logDir string) []string {
	t.Helper()
	mask := func(s string) string {
		s = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?`).ReplaceAllString(s, "<time>")
		s = regexp.MustCompile(`[0-9a-f]{64}`).ReplaceAllString(s, "<hex>")
		s = regexp.MustCompile(`log_id: [0-9a-f]{32}`).ReplaceAllString(s, "log_id: <id>") // random per ledger
		return strings.ReplaceAll(s, filepath.Dir(ctl), "<root>")
	}
	var got []string
	var out bytes.Buffer
	code := cmdAuditControl([]string{"--control-log", ctl}, &out)
	got = append(got, fmt.Sprintf("audit control exit %d\n%s", code, mask(out.String())))
	out.Reset()
	code = cmdAuditVerify([]string{"control", "--control-log", ctl}, &out)
	got = append(got, fmt.Sprintf("audit verify control exit %d\n%s", code, mask(out.String())))
	out.Reset()
	code = cmdInvestigate([]string{"--log-dir", logDir, "--control-log", ctl}, &out)
	got = append(got, fmt.Sprintf("investigate exit %d\n%s", code, mask(out.String())))
	out.Reset()
	code = cmdConfigPull([]string{"--control-log", ctl}, &out)
	got = append(got, fmt.Sprintf("config pull exit %d\n%s", code, mask(out.String())))
	return got
}

// TestFloorPostureIsByteIdenticalToNoFile: the same scenario on a root with
// no integrity.yaml and on a root with a floor file yields the same number
// of records, record for record equal once Time is zeroed, and identical
// reader output once time and hashes are masked. No record anywhere carries
// an anchor key, and nothing creates the file.
func TestFloorPostureIsByteIdenticalToNoFile(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	rootA := writeSample(t)
	rootB := t.TempDir()
	if err := os.CopyFS(rootB, os.DirFS(rootA)); err != nil { // byte-identical configuration ⇒ identical hashes
		t.Fatal(err)
	}
	ctlA := filepath.Join(t.TempDir(), "control.jsonl")
	ctlB := filepath.Join(t.TempDir(), "control.jsonl")
	logs := t.TempDir() // one empty run-log directory for every reader call
	eventsA, readersA := floorScenario(t, rootA, ctlA, logs, false)
	eventsB, readersB := floorScenario(t, rootB, ctlB, logs, true)
	if len(eventsA) != 4 {
		t.Fatalf("fixture: want apply, disable, enable, vouch; got %d records", len(eventsA))
	}
	if !reflect.DeepEqual(eventsA, eventsB) {
		t.Fatalf("records differ\nno file: %+v\nfloor:   %+v", eventsA, eventsB)
	}
	if !reflect.DeepEqual(readersA, readersB) {
		t.Fatalf("reader output differs\nno file:\n%s\nfloor:\n%s", strings.Join(readersA, "\n"), strings.Join(readersB, "\n"))
	}
	if _, err := os.Stat(integrityPath(ctlA)); !os.IsNotExist(err) {
		t.Fatalf("nothing may create integrity.yaml: stat err = %v", err)
	}
}

// TestReadersIgnoreThePosture: audit control, audit verify control,
// investigate and config pull succeed on a root whose integrity.yaml says
// anchor: tlog, with output identical to the no-file case — readers are the
// recovery path, not a guarantee path, and do not load the file in this
// build.
func TestReadersIgnoreThePosture(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	root := writeSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	logs := t.TempDir()
	_, before := floorScenario(t, root, ctl, logs, false)
	writeIntegrity(t, ctl, reservedPosture)
	after := readerOutputs(t, ctl, logs)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("readers must not consult the posture\nno file:\n%s\nreserved:\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	for _, o := range after {
		if strings.Contains(o, "integrity "+integrityPath(ctl)) || strings.Contains(o, "reserved") {
			t.Fatalf("a reader must not mention the posture:\n%s", o)
		}
	}
}

// TestNoFloorWriterEmitsAnAnchorKey: every writer on the floor path —
// apply, disable, enable, vouch, provision, prune — under an explicit floor
// integrity.yaml writes ledger lines with no "anchor" key. The key is first
// written when an anchor backend exists; until then its absence is the
// floor's byte-identity guarantee.
func TestNoFloorWriterEmitsAnAnchorKey(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	root := budgetedSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	writeIntegrity(t, ctl, "sink: local\nanchor: none\n")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	for _, flip := range []string{"disable", "enable"} {
		out.Reset()
		if code := cmdRegistry([]string{flip, "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
			t.Fatalf("%s: %d\n%s", flip, code, out.String())
		}
	}
	crashGap(t, root, ctl)
	vouchAs(t, ctl)

	srv, _ := adminMock(t, 0, "")
	t.Chdir(t.TempDir())
	out.Reset()
	if code := cmdGateway(provisionArgs(ctl, srv.URL), &out); code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	logs := t.TempDir()
	agedRun(t, logs, "r-old.jsonl")
	out.Reset()
	if code := cmdRuns(pruneArgs(ctl, "--older-than", "180d", "--log-dir", logs, "--artifact-dir", t.TempDir()), &out); code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}

	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if strings.Contains(string(r.Raw), `"anchor"`) {
			t.Fatalf("no floor-path writer may emit an anchor key: %s", r.Raw)
		}
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		seen[d.Action] = true
	}
	for _, action := range []string{"apply", "disable", "enable", "vouch", "provision", "prune"} {
		if !seen[action] {
			t.Fatalf("fixture: no %q record was scanned (saw %v)", action, seen)
		}
	}
}
