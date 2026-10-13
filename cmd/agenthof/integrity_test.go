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
// "<command>: " prefix).
const reservedPosture = "anchor: tlog\n"

func reservedFault(path string) string {
	return "integrity " + path + `: anchor "tlog" is reserved and not yet supported in this build (only none is implemented)`
}

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

// TestLoadIntegrityNamesTheFileOnce: a reserved posture, a shape fault and
// an unreadable file are each an error — never the floor — naming the path
// exactly once: the package reports the bare fault, and an OS read error's
// own path (a *fs.PathError) is stripped so it is not named twice.
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
