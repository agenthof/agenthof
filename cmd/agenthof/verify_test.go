package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/ledger"
)

func TestVerifyPathsAreBesideTheStore(t *testing.T) {
	ctl := "/srv/agenthof/control.jsonl"
	if verifyPubPath(ctl) != "/srv/agenthof/verify.pub" || verifyFloorPath(ctl) != "/srv/agenthof/verify.floor" {
		t.Fatalf("%s %s", verifyPubPath(ctl), verifyFloorPath(ctl))
	}
	if filepath.Dir(verifyPubPath(ctl)) != filepath.Dir(installedStore(ctl)) || verifyPubPath(ctl) == signingPubPath(ctl) {
		t.Fatal("verify.pub lives beside installed/, and is a different file from signing.pub")
	}
}

// pinHostKey copies signing.pub to verify.pub beside ctl: self-verification.
func pinHostKey(t *testing.T, ctl string) {
	t.Helper()
	if err := os.WriteFile(verifyPubPath(ctl), mustRead(t, signingPubPath(ctl)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadVerifyPubNamesTheFileInEveryError(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	pinHostKey(t, ctl)
	p := verifyPubPath(ctl)
	pub, err := loadVerifyPub(p)
	if err != nil || config.KeyID(pub) != config.KeyID(signingPub(t, ctl)) {
		t.Fatalf("pinned host key: %v", err)
	}

	missing := filepath.Join(t.TempDir(), "nowhere.pub")
	if _, err := loadVerifyPub(missing); err == nil || !strings.HasPrefix(err.Error(), "pinned key "+missing+": ") || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("absent: %v", err)
	}
	if err := os.WriteFile(p, []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifyPub(p); err == nil || err.Error() != "pinned key "+p+": signing public key: no PEM block" {
		t.Fatalf("junk: %v", err)
	}
	// A PRIVATE KEY block (the host's own signing.key, copied by mistake) is refused by type.
	if err := os.WriteFile(p, mustRead(t, signingKeyPath(ctl)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifyPub(p); err == nil || !strings.Contains(err.Error(), `PEM block type "PRIVATE KEY"; want "PUBLIC KEY"`) {
		t.Fatalf("private key: %v", err)
	}
	// A public key of another algorithm (ECDSA P-256 — same branch as RSA, generated in microseconds).
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifyPub(p); err == nil || !strings.Contains(err.Error(), "*ecdsa.PublicKey; want Ed25519") {
		t.Fatalf("ecdsa: %v", err)
	}
	// Trailing data after the block.
	if err := os.WriteFile(p, append(mustRead(t, signingPubPath(ctl)), []byte("trailing\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifyPub(p); err == nil || !strings.Contains(err.Error(), "trailing data after the PEM block") {
		t.Fatalf("trailing: %v", err)
	}
	// A directory.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifyPub(p); err == nil || !strings.HasPrefix(err.Error(), "pinned key "+p+": ") {
		t.Fatalf("directory: %v", err)
	}
}

func TestReadAndWriteVerifyFloor(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "sub", "control.jsonl")
	if err := os.MkdirAll(filepath.Dir(ctl), 0o700); err != nil {
		t.Fatal(err)
	}
	logID := strings.Repeat("ab", 16)
	if _, _, present, err := readVerifyFloor(ctl); present || err != nil {
		t.Fatalf("absent: present=%v err=%v", present, err)
	}
	if err := writeVerifyFloor(ctl, logID, 1); err != nil {
		t.Fatal(err)
	}
	p := verifyFloorPath(ctl)
	if b := mustRead(t, p); string(b) != logID+" 1\n" {
		t.Fatalf("floor %q", b)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", info.Mode().Perm())
	}
	gotID, v, present, err := readVerifyFloor(ctl)
	if err != nil || !present || gotID != logID || v != 1 {
		t.Fatalf("read back: %q %d %v %v", gotID, v, present, err)
	}
	// Overwrite advances; the same bytes twice is an idempotent duplicate.
	if err := writeVerifyFloor(ctl, logID, 7); err != nil {
		t.Fatal(err)
	}
	if err := writeVerifyFloor(ctl, logID, 7); err != nil {
		t.Fatal(err)
	}
	if _, v, _, _ := readVerifyFloor(ctl); v != 7 {
		t.Fatalf("version %d, want 7", v)
	}
	for _, e := range mustReadDirNames(t, filepath.Dir(ctl)) {
		if strings.HasPrefix(e, ".verify.floor-") {
			t.Fatalf("temp residue: %s", e)
		}
	}
	// Corrupt floors fail closed with the file named: never "absent".
	for _, bad := range []string{"garbage\n", logID + " 07\n", logID + " 0\n", logID + " 7"} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, present, err := readVerifyFloor(ctl)
		if err == nil || present || !strings.HasPrefix(err.Error(), "verify.floor: ") {
			t.Fatalf("%q: present=%v err=%v", bad, present, err)
		}
	}
	// A floor that is a directory: the read fails (not absent), and a write over it fails and leaves it.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, present, err := readVerifyFloor(ctl); err == nil || present || !strings.HasPrefix(err.Error(), "verify.floor: ") {
		t.Fatalf("directory read: present=%v err=%v", present, err)
	}
	if err := writeVerifyFloor(ctl, logID, 8); err == nil || !strings.HasPrefix(err.Error(), "verify.floor: ") {
		t.Fatalf("directory write: %v", err)
	}
	if info, err := os.Stat(p); err != nil || !info.IsDir() {
		t.Fatal("a failed write must leave whatever was there")
	}
	for _, e := range mustReadDirNames(t, filepath.Dir(ctl)) {
		if strings.HasPrefix(e, ".verify.floor-") {
			t.Fatalf("temp residue after a failed write: %s", e)
		}
	}
	// An unwritable control root (skip as root, who ignores modes): the write fails before the rename.
	if os.Geteuid() != 0 {
		ctl2 := filepath.Join(t.TempDir(), "ro", "control.jsonl")
		if err := os.MkdirAll(filepath.Dir(ctl2), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(ctl2), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(ctl2), 0o700) })
		if err := writeVerifyFloor(ctl2, logID, 1); err == nil || !strings.HasPrefix(err.Error(), "verify.floor: ") || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("unwritable root: %v", err)
		}
	}
}

func TestVerifyRefusalStrings(t *testing.T) {
	for _, c := range []struct {
		r             verifyRefusal
		headline, err string
		transient     bool
	}{
		{verifyRefusal{Kind: verifyUnsigned, Detail: "no signature file for sha256:ab"}, "configuration not verified: unsigned", "configuration not verified: unsigned: no signature file for sha256:ab", false},
		{verifyRefusal{Kind: verifyUnknownKey, Detail: "signature is by key a; configured key is b"}, "configuration not verified: unknown key", "configuration not verified: unknown key: signature is by key a; configured key is b", false},
		{verifyRefusal{Kind: verifyBadSignature}, "configuration not verified: bad signature", "configuration not verified: bad signature", false},
		{verifyRefusal{Kind: verifyStale, Detail: "version 3 is below this root's verified floor 5 (ledger ab)"}, "configuration not verified: stale", "configuration not verified: stale: version 3 is below this root's verified floor 5 (ledger ab)", false},
		{verifyRefusal{Kind: verifyForeignLedger, Detail: "install is of ledger a; this root last verified ledger b (version 5); remove /x/verify.floor to accept the new ledger"}, "configuration not verified: foreign ledger", "configuration not verified: foreign ledger: install is of ledger a; this root last verified ledger b (version 5); remove /x/verify.floor to accept the new ledger", false},
		{*notVerifiable("pinned key /x/verify.pub: signing public key: no PEM block"), "configuration not verifiable", "configuration not verifiable: pinned key /x/verify.pub: signing public key: no PEM block", false},
		{verifyRefusal{Kind: verifyBusy}, msgLockBusy, msgLockBusy, true},
	} {
		if c.r.Headline() != c.headline || c.r.Error() != c.err || c.r.Transient() != c.transient {
			t.Fatalf("%+v: headline %q err %q transient %v", c.r, c.r.Headline(), c.r.Error(), c.r.Transient())
		}
	}
}

func TestRecordedInstall(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := signedRoot(t)
	hash := readPointer(t, ctl)
	facts, refusal := recordedInstall(ctl, hash)
	if refusal != nil || facts.LogID != controlLogID(t, ctl) || facts.Version != 1 || facts.At.Location() != time.UTC || !facts.At.Equal(controlEvents(t, ctl)[0].Time) {
		t.Fatalf("%+v %v", facts, refusal)
	}
	applyAs(t, root, ctl) // identical re-apply: seq 2
	if facts, refusal := recordedInstall(ctl, hash); refusal != nil || facts.Version != 2 {
		t.Fatalf("%+v %v", facts, refusal)
	}
	// Not the recorded hash → not on record (definitive under the shared lock).
	if _, r := recordedInstall(ctl, "sha256:"+strings.Repeat("0", 64)); r == nil || r.Kind != verifyNotVerifiable || r.Detail != "installed configuration is not on record; re-apply, or run audit repair control" {
		t.Fatalf("other hash: %+v", r)
	}
	// Torn tail → damaged, with the repair hint naming the ledger.
	appendFragment(t, ctl)
	if _, r := recordedInstall(ctl, hash); r == nil || r.Kind != verifyNotVerifiable || r.Detail != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl {
		t.Fatalf("torn: %+v", r)
	}
	// No ledger file → an empty chain vouches for nothing: not on record, never damaged.
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if _, r := recordedInstall(ctl, hash); r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "installed configuration is not on record") {
		t.Fatalf("no ledger: %+v", r)
	}
	// Genesis without log_id → not verifiable, named.
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	hash2 := installByHandWithPointer(t, ctl2, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	c, err := ledger.Open(ctl2, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"v":"control/1","seq":1,"time":"2026-10-09T02:12:01Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"h"},"config_hash":"` + hash2 + `","prev":""}`
	if err := c.Append([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, r := recordedInstall(ctl2, hash2); r == nil || r.Kind != verifyNotVerifiable || r.Detail != "control ledger genesis has no log_id" {
		t.Fatalf("no log_id: %+v", r)
	}
}

func TestJudgeFloorRules(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if err := os.MkdirAll(filepath.Dir(ctl), 0o700); err != nil {
		t.Fatal(err)
	}
	L, L2 := strings.Repeat("ab", 16), strings.Repeat("ff", 16)
	floor := func() string { b, _ := os.ReadFile(verifyFloorPath(ctl)); return string(b) }

	// absent + verifyOnly: accept, no floor created.
	if r := judgeFloor(ctl, L, 3, verifyOnly); r != nil || floor() != "" {
		t.Fatalf("verifyOnly: %+v floor=%q", r, floor())
	}
	// absent + verifyAndAdvance: accept, created at (L, 3).
	if r := judgeFloor(ctl, L, 3, verifyAndAdvance); r != nil || floor() != L+" 3\n" {
		t.Fatalf("create: %+v floor=%q", r, floor())
	}
	// equal: accept, no write (mtime unchanged).
	before, _ := os.Stat(verifyFloorPath(ctl))
	time.Sleep(20 * time.Millisecond)
	if r := judgeFloor(ctl, L, 3, verifyAndAdvance); r != nil {
		t.Fatalf("equal: %+v", r)
	}
	if after, _ := os.Stat(verifyFloorPath(ctl)); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the steady state must write nothing")
	}
	// above: advance.
	if r := judgeFloor(ctl, L, 5, verifyAndAdvance); r != nil || floor() != L+" 5\n" {
		t.Fatalf("advance: %+v floor=%q", r, floor())
	}
	// above + verifyOnly: accept, floor unchanged.
	if r := judgeFloor(ctl, L, 9, verifyOnly); r != nil || floor() != L+" 5\n" {
		t.Fatalf("verifyOnly above: %+v floor=%q", r, floor())
	}
	// below: stale, floor unchanged.
	r := judgeFloor(ctl, L, 4, verifyAndAdvance)
	if r == nil || r.Kind != verifyStale || r.Detail != "version 4 is below this root's verified floor 5 (ledger "+L+")" || floor() != L+" 5\n" {
		t.Fatalf("stale: %+v floor=%q", r, floor())
	}
	// another ledger, even at a higher version: foreign ledger — judged BEFORE the version.
	r = judgeFloor(ctl, L2, 9, verifyAndAdvance)
	if r == nil || r.Kind != verifyForeignLedger || r.Detail != "install is of ledger "+L2+"; this root last verified ledger "+L+" (version 5); remove "+verifyFloorPath(ctl)+" to accept the new ledger" || floor() != L+" 5\n" {
		t.Fatalf("foreign: %+v floor=%q", r, floor())
	}
	// reset: remove the floor; the foreign ledger is accepted and the floor re-created at its (L2, 1) — an older version too.
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if r := judgeFloor(ctl, L2, 1, verifyAndAdvance); r != nil || floor() != L2+" 1\n" {
		t.Fatalf("reset: %+v floor=%q", r, floor())
	}
	// corrupt floor: not verifiable, named, never "absent" — and never rewritten.
	for _, bad := range []string{"garbage\n", L2 + " 07\n", L2 + " 0\n"} {
		if err := os.WriteFile(verifyFloorPath(ctl), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		r := judgeFloor(ctl, L2, 2, verifyAndAdvance)
		if r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "verify.floor: ") || floor() != bad {
			t.Fatalf("%q: %+v floor=%q", bad, r, floor())
		}
	}
	// a floor that is a directory: a READ fault (EISDIR), not verifiable, named.
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(verifyFloorPath(ctl), 0o700); err != nil {
		t.Fatal(err)
	}
	if r := judgeFloor(ctl, L2, 2, verifyAndAdvance); r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "verify.floor: ") {
		t.Fatalf("directory: %+v", r)
	}
	// the WRITE fault after a pass: an unwritable control root (skip as root) — the advance cannot be remembered, so it refuses.
	if os.Geteuid() != 0 {
		if err := os.Remove(verifyFloorPath(ctl)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(ctl), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(ctl), 0o700) })
		r := judgeFloor(ctl, L2, 2, verifyAndAdvance)
		if r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "verify.floor: ") || !strings.Contains(r.Detail, "permission denied") {
			t.Fatalf("unwritable root: %+v", r)
		}
		if r := judgeFloor(ctl, L2, 2, verifyOnly); r != nil {
			t.Fatalf("verifyOnly never writes, so an unwritable root is no fault for it: %+v", r)
		}
	}
}
