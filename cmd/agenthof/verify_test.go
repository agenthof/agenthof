package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/serve"
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
		{verifyRefusal{Kind: verifyNotOnRecord, Detail: "last recorded install is sha256:ab (apply); re-apply (for a torn ledger, audit repair control first)"}, "configuration not on record", "configuration not on record: last recorded install is sha256:ab (apply); re-apply (for a torn ledger, audit repair control first)", false},
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
	if _, r := recordedInstall(ctl, "sha256:"+strings.Repeat("0", 64)); r == nil || r.Kind != verifyNotOnRecord || r.Detail != "last recorded install is "+hash+" (apply); re-apply (for a torn ledger, audit repair control first)" {
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
	if _, r := recordedInstall(ctl, hash); r == nil || r.Kind != verifyNotOnRecord || r.Detail != "no install on record; re-apply (for a torn ledger, audit repair control first)" {
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

// TestVouchInstalledIsLastInstallingPlusHashEquality: the vouch every
// execution read performs — a clean ledger vouches the pointer and returns
// the install; a re-aimed pointer is not on record with the last install
// named and labelled; after a flip the label is the flip's.
func TestVouchInstalledIsLastInstallingPlusHashEquality(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := signedRoot(t)
	hashA := readPointer(t, ctl)
	records, last, refusal := vouchInstalled(ctl, hashA)
	if refusal != nil || len(records) != 1 || last.ConfigHash != hashA || last.Seq != 1 || last.Action != "apply" {
		t.Fatalf("clean: refusal=%v records=%d last=%+v", refusal, len(records), last)
	}
	// apply B (a different directory), then re-aim the pointer at A: A's
	// bytes still hash as A, the ledger's last install is B.
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	applyAs(t, root, ctl)
	hashB := readPointer(t, ctl)
	if hashB == hashA {
		t.Fatal("B must differ from A")
	}
	if _, _, refusal := vouchInstalled(ctl, hashB); refusal != nil {
		t.Fatalf("B vouches: %v", refusal)
	}
	repointTo(t, ctl, hashA)
	_, _, refusal = vouchInstalled(ctl, hashA)
	if refusal == nil || refusal.Kind != verifyNotOnRecord || refusal.Detail != "last recorded install is "+hashB+" (apply); re-apply (for a torn ledger, audit repair control first)" {
		t.Fatalf("re-aimed: %+v", refusal)
	}
	if refusal.Headline() != "configuration not on record" || refusal.Error() != "configuration not on record: "+refusal.Detail {
		t.Fatalf("texts: %q %q", refusal.Headline(), refusal.Error())
	}
	// A flip against the installed B is an install; re-aim at B afterwards
	// and the label names the flip.
	repointTo(t, ctl, hashB)
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("flip: %d\n%s", code, out.String())
	}
	hashF := readPointer(t, ctl)
	if _, last, refusal := vouchInstalled(ctl, hashF); refusal != nil || last.Action != "disable" || last.Agent != "coder" {
		t.Fatalf("flip vouches: %v %+v", refusal, last)
	}
	repointTo(t, ctl, hashB)
	if _, _, refusal := vouchInstalled(ctl, hashB); refusal == nil || refusal.Kind != verifyNotOnRecord || refusal.Detail != "last recorded install is "+hashF+" (disable agent coder); re-apply (for a torn ledger, audit repair control first)" {
		t.Fatalf("re-aimed after a flip: %+v", refusal)
	}
}

// repointTo hand-aims installed/current at hash — the pointer write a
// hostile or careless hand makes, with no lock and no record.
func repointTo(t *testing.T, ctl, hash string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(installedStore(ctl), config.InstalledPointer), []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestVouchInstalledClassifiesTheLedgerAsThePullDoes: the switch is on
// ReadVerify's error alone — no file → not on record (never damaged); torn →
// damaged with the repair hint; a mid-file chain break → damaged; an
// unreadable file → not verifiable naming the OS error, NO repair hint; the
// ledger flock held → busy; and a torn ledger REPAIRED → tainted, chain
// verifies, vouches (IsTainted is a verdict about history, not the pointer).
func TestVouchInstalledClassifiesTheLedgerAsThePullDoes(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := signedRoot(t)
	hash := readPointer(t, ctl)
	clean := mustRead(t, ctl)

	// torn tail after the install record: damaged, with the hint.
	appendFragment(t, ctl)
	if _, _, r := vouchInstalled(ctl, hash); r == nil || r.Kind != verifyNotVerifiable || r.Detail != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl {
		t.Fatalf("torn: %+v", r)
	}
	// repaired: tainted, verifies, vouches.
	repairAs(t, root, ctl)
	records, _, r := vouchInstalled(ctl, hash)
	if r != nil {
		t.Fatalf("repaired must vouch: %+v", r)
	}
	if tainted, _ := control.IsTainted(records); !tainted {
		t.Fatal("the fixture must be tainted for this to prove anything")
	}
	// broken mid-file: flip one byte of the genesis record's hash chain.
	if err := os.WriteFile(ctl, clean, 0o600); err != nil {
		t.Fatal(err)
	}
	applyAs(t, root, ctl) // seq 2, so a break at seq 1 is mid-file
	broken := mustRead(t, ctl)
	i := bytes.Index(broken, []byte(`"outcome":"success"`))
	if i < 0 {
		t.Fatal("fixture")
	}
	broken[i+len(`"outcome":"`)] = 'S'
	if err := os.WriteFile(ctl, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, r := vouchInstalled(ctl, hash); r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "control ledger damaged; run: agenthof audit repair control") {
		t.Fatalf("broken: %+v", r)
	}
	if err := os.WriteFile(ctl, clean, 0o600); err != nil {
		t.Fatal(err)
	}
	// S4: unreadable (0000) — the OS error, no repair hint (skip as root).
	if os.Geteuid() != 0 {
		if err := os.Chmod(ctl, 0); err != nil {
			t.Fatal(err)
		}
		_, _, r := vouchInstalled(ctl, hash)
		if err := os.Chmod(ctl, 0o600); err != nil {
			t.Fatal(err)
		}
		if r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "control ledger "+ctl+": ") || !strings.Contains(r.Detail, "permission denied") || strings.Contains(r.Detail, "repair") {
			t.Fatalf("unreadable: %+v", r)
		}
	}
	// S4: the ledger path is a directory — ReadVerify reads it as an empty
	// chain (open succeeds, the first read yields no record and no error),
	// so the switch, which is on ReadVerify's error alone, classifies it as
	// not on record (an empty chain vouches for nothing), never damaged.
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ctl, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, r := vouchInstalled(ctl, hash); r == nil || r.Kind != verifyNotOnRecord || r.Detail != "no install on record; re-apply (for a torn ledger, audit repair control first)" {
		t.Fatalf("EISDIR: %+v", r)
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	// no file, pointer present: an empty chain vouches for nothing — not on record, never damaged.
	if _, _, r := vouchInstalled(ctl, hash); r == nil || r.Kind != verifyNotOnRecord || r.Detail != "no install on record; re-apply (for a torn ledger, audit repair control first)" {
		t.Fatalf("no ledger: %+v", r)
	}
}

// TestVouchInstalledRepairedInstallRecordNeedsReapply: the torn fragment
// WAS the install's own success record. Damaged first; after repair the
// chain verifies but the last install is the PREVIOUS one, so the verdict is
// not on record with the remedy in the right order (re-apply; repair first
// only for a torn ledger — which the operator just did); a re-apply heals it
// through CommitSnapshot's identical-snapshot branch, and the ledger stays
// tainted while it vouches.
func TestVouchInstalledRepairedInstallRecordNeedsReapply(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := signedRoot(t)
	hashA := readPointer(t, ctl)
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	applyAs(t, root, ctl)
	hashB := readPointer(t, ctl)
	// Tear B's own record: drop the trailing bytes of the last line.
	raw := mustRead(t, ctl)
	if err := os.WriteFile(ctl, raw[:len(raw)-10], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, r := vouchInstalled(ctl, hashB); r == nil || r.Kind != verifyNotVerifiable || !strings.HasPrefix(r.Detail, "control ledger damaged") {
		t.Fatalf("torn install record: %+v", r)
	}
	repairAs(t, root, ctl)
	_, _, r := vouchInstalled(ctl, hashB)
	if r == nil || r.Kind != verifyNotOnRecord || r.Detail != "last recorded install is "+hashA+" (apply); re-apply (for a torn ledger, audit repair control first)" {
		t.Fatalf("after repair the install is not on record: %+v", r)
	}
	applyAs(t, root, ctl) // identical snapshot B: re-points, records
	if _, last, r := vouchInstalled(ctl, hashB); r != nil || last.ConfigHash != hashB {
		t.Fatalf("re-apply heals: %v %+v", r, last)
	}
	if recs, _, err := ledger.ReadVerify(ctl, ledger.Locked); err != nil {
		t.Fatal(err)
	} else if tainted, _ := control.IsTainted(recs); !tainted {
		t.Fatal("still tainted, still vouches")
	}
}

// TestVouchInstalledGenesisWithoutLogIDVouchesUnpinned: a control root
// older than the genesis log_id vouches (the vouch stops at LastInstalling);
// the pinned layer still refuses it by name.
func TestVouchInstalledGenesisWithoutLogIDVouchesUnpinned(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	hash := installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	c, err := ledger.Open(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"v":"control/1","seq":1,"time":"2026-10-09T02:12:01Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"h"},"config_hash":"` + hash + `","prev":""}`
	if err := c.Append([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, last, r := vouchInstalled(ctl, hash); r != nil || last.ConfigHash != hash {
		t.Fatalf("unpinned vouches: %v %+v", r, last)
	}
	if _, r := recordedInstall(ctl, hash); r == nil || r.Kind != verifyNotVerifiable || r.Detail != "control ledger genesis has no log_id" {
		t.Fatalf("pinned layer: %+v", r)
	}
}

// TestVouchInstalledPreR14FlipRootRefusesUntilApply pins the one admitted
// behavior change: a root whose last installing event is a kill-switch record
// carrying a directory hash with no Bootstrap marker (the shape written
// before flips re-snapshotted the install) refuses every run as not on
// record — labelled with the flip — until one apply.
func TestVouchInstalledPreR14FlipRootRefusesUntilApply(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := signedRoot(t)
	hash := readPointer(t, ctl)
	dirHash := "sha256:" + strings.Repeat("d", 64)
	if _, err := control.Append(ctl, control.Event{Action: "disable", Agent: "coder", Outcome: "success", Invoker: admin, Witness: control.CaptureWitness(), ConfigHash: dirHash}); err != nil {
		t.Fatal(err)
	}
	_, _, r := vouchInstalled(ctl, hash)
	if r == nil || r.Kind != verifyNotOnRecord || r.Detail != "last recorded install is "+dirHash+" (disable agent coder); re-apply (for a torn ledger, audit repair control first)" {
		t.Fatalf("pre-R1.4 root: %+v", r)
	}
	if _, mismatch := installedPointerLine(ctl, controlRecords(t, ctl)); !mismatch {
		t.Fatal("the audit readers must say the same")
	}
	applyAs(t, root, ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r != nil {
		t.Fatalf("one apply heals: %v", r)
	}
}

// controlRecords is the verified chain, for the audit readers' line.
func controlRecords(t *testing.T, ctl string) []ledger.Record {
	t.Helper()
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return recs
}

// TestVouchInstalledAgreesWithTheAuditReaders is the seam pin: over every
// fixture ReadVerify accepts, vouchInstalled refuses ⇔ installedPointerLine
// reports mismatch — the vouch is a pure consumer of control.Installing, so a
// future Installing change (an adopted record) propagates with no edit here.
// Fixtures: bootstrap apply; a bootstrap-era flip then the first apply; a flip
// against the install; rm current + re-bootstrap; a hand-aimed pointer; a
// dropped-in snapshot; the crash gap and its re-apply; a removed ledger.
func TestVouchInstalledAgreesWithTheAuditReaders(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	agree := func(name, ctl string) {
		t.Helper()
		hash := readPointer(t, ctl)
		_, _, r := vouchInstalled(ctl, hash)
		_, mismatch := installedPointerLine(ctl, controlRecords(t, ctl))
		if (r == nil) == mismatch {
			t.Fatalf("%s: vouch refusal=%v, audit mismatch=%v — one judgment", name, r, mismatch)
		}
		if r != nil && r.Kind != verifyNotOnRecord {
			t.Fatalf("%s: over an accepted chain the only refusal is not on record: %+v", name, r)
		}
	}

	// bootstrap apply: vouched.
	root := writeSample(t)
	ctl := applied(t, root)
	agree("bootstrap apply", ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r != nil {
		t.Fatalf("a bootstrap apply IS an install: %v", r)
	}

	// bootstrap-era flip (nothing installed: edits the directory, records
	// the directory's hash, Bootstrap: true) then the first apply: vouched.
	root2 := writeSample(t)
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root2, "--control-log", ctl2, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("bootstrap flip: %d\n%s", code, out.String())
	}
	if code := cmdRegistry([]string{"enable", "coder", "--config", root2, "--control-log", ctl2, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("bootstrap flip back: %d\n%s", code, out.String())
	}
	applyAs(t, root2, ctl2)
	agree("bootstrap-era flips then first apply", ctl2)
	if _, _, r := vouchInstalled(ctl2, readPointer(t, ctl2)); r != nil {
		t.Fatalf("first apply after bootstrap flips vouches: %v", r)
	}

	// flip against the install: vouched (the flip is the install).
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("flip: %d\n%s", code, out.String())
	}
	agree("flip against the install", ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r != nil {
		t.Fatalf("a flip against the install vouches: %v", r)
	}

	// rm current + re-bootstrap: vouched.
	if err := os.Remove(filepath.Join(installedStore(ctl), config.InstalledPointer)); err != nil {
		t.Fatal(err)
	}
	applyAs(t, root, ctl)
	agree("rm current + re-bootstrap", ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r != nil {
		t.Fatalf("re-bootstrap vouches: %v", r)
	}

	// hand-aimed: apply B, repoint A.
	hashA := readPointer(t, ctl)
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	applyAs(t, root, ctl)
	repointTo(t, ctl, hashA)
	agree("hand-aimed", ctl)
	if _, _, r := vouchInstalled(ctl, hashA); r == nil {
		t.Fatal("a hand-aimed pointer must be refused")
	}

	// dropped-in: a snapshot nothing applied.
	installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	agree("dropped-in", ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r == nil {
		t.Fatal("a dropped-in snapshot must be refused")
	}

	// crash gap: pointer moved, no record; then the re-apply heals.
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan hardest\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	if code, s := applyCode(t, root, ctl); code != 1 || !strings.Contains(s, msgInstalledNotRecorded) {
		t.Fatalf("crash hook: %d\n%s", code, s)
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	agree("crash gap", ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r == nil {
		t.Fatal("the install→record gap must be refused")
	}
	applyAs(t, root, ctl)
	agree("re-apply after the gap", ctl)
	if _, _, r := vouchInstalled(ctl, readPointer(t, ctl)); r != nil {
		t.Fatalf("re-apply heals: %v", r)
	}

	// removed ledger, pointer present: not on record.
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	agree("removed ledger", ctl)
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

// pinnedRoot is signedRoot with signing.pub pinned as verify.pub: the
// self-verification setup. It returns ctl, root, the pinned key's id.
func pinnedRoot(t *testing.T) (ctl, root, keyID string) {
	t.Helper()
	ctl, root, keyID = signedRoot(t)
	pinHostKey(t, ctl)
	return ctl, root, keyID
}

// resolveAdvance is resolveRunConfig(ctl, "", verifyAndAdvance) with the
// control ledger asserted byte-identical afterwards: no verify outcome ever
// writes a control event.
func resolveAdvance(t *testing.T, ctl string) (cfg config.Config, reg *registry.Registry, hash string, installed bool, errs []error, unverified *verifyRefusal) {
	t.Helper()
	before := ledgerBytes(t, ctl)
	cfg, reg, hash, installed, errs, unverified = resolveRunConfig(ctl, "", verifyAndAdvance)
	if after := ledgerBytes(t, ctl); !bytes.Equal(before, after) {
		t.Fatal("the pinned verify must never write the control ledger")
	}
	return
}

func floorBytes(t *testing.T, ctl string) string {
	t.Helper()
	b, err := os.ReadFile(verifyFloorPath(ctl))
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestResolveRunConfigStateANeverTouchesTheLockOrTheFloor: with no pin the
// function is today's body — it never opens or creates installed.lock (applyAs
// created it; remove it and it must stay absent) and never reads or writes a
// floor.
func TestResolveRunConfigStateANeverTouchesTheLockOrTheFloor(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, _ := signedRoot(t)
	if err := os.Remove(installedLock(ctl)); err != nil {
		t.Fatal(err)
	}
	_, reg, hash, installed, errs, unverified := resolveAdvance(t, ctl)
	if reg == nil || !installed || hash != readPointer(t, ctl) || len(errs) != 0 || unverified != nil {
		t.Fatalf("state A: reg=%v installed=%v errs=%v unverified=%v", reg, installed, errs, unverified)
	}
	if _, err := os.Stat(installedLock(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("state A must never create installed.lock: %v", err)
	}
	if floorBytes(t, ctl) != "" {
		t.Fatal("state A must never create verify.floor")
	}
	// A floor left behind by an earlier pin is inert without the pin.
	if err := os.WriteFile(verifyFloorPath(ctl), []byte(strings.Repeat("f", 32)+" 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reg, _, _, errs, unverified := resolveAdvance(t, ctl); reg == nil || len(errs) != 0 || unverified != nil {
		t.Fatalf("an unpinned root ignores the floor: %v %v", errs, unverified)
	}
}

// TestPinnedVerifyPassesAndAdvancesTheFloor: self-verification passes;
// verifyAndAdvance creates verify.floor = "<log_id> 1\n" (0600) and a second
// pass writes nothing; verifyOnly on a fresh pinned root creates no floor and
// no verify outcome writes the control ledger.
func TestPinnedVerifyPassesAndAdvancesTheFloor(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, _ := pinnedRoot(t)
	logID := controlLogID(t, ctl)

	if _, reg, _, installed, errs, unverified := resolveRunConfig(ctl, "", verifyOnly); reg == nil || !installed || len(errs) != 0 || unverified != nil || floorBytes(t, ctl) != "" {
		t.Fatalf("verifyOnly: reg=%v errs=%v unverified=%v floor=%q", reg, errs, unverified, floorBytes(t, ctl))
	}
	_, reg, hash, installed, errs, unverified := resolveAdvance(t, ctl)
	if reg == nil || !installed || hash != readPointer(t, ctl) || len(errs) != 0 || unverified != nil {
		t.Fatalf("pass: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
	if floorBytes(t, ctl) != logID+" 1\n" {
		t.Fatalf("floor %q", floorBytes(t, ctl))
	}
	if info, _ := os.Stat(verifyFloorPath(ctl)); info.Mode().Perm() != 0o600 {
		t.Fatalf("floor mode %o", info.Mode().Perm())
	}
	before, _ := os.Stat(verifyFloorPath(ctl))
	time.Sleep(20 * time.Millisecond)
	if _, reg, _, _, _, unverified := resolveAdvance(t, ctl); reg == nil || unverified != nil {
		t.Fatalf("second pass: %v", unverified)
	}
	if after, _ := os.Stat(verifyFloorPath(ctl)); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the steady state must write nothing")
	}
	for _, e := range mustReadDirNames(t, filepath.Dir(ctl)) {
		if strings.HasPrefix(e, ".verify.floor-") {
			t.Fatalf("temp residue: %s", e)
		}
	}
	if _, err := os.Stat(installedLock(ctl)); err != nil {
		t.Fatalf("a pinned run opens installed.lock shared: %v", err)
	}
}

// TestPinnedVerifyJudgedKinds: each of the five judged kinds, by kind AND
// detail text; a verdict returns cfg loaded, reg nil, hash set, installed
// true, errs nil, and never writes the floor or the control ledger.
func TestPinnedVerifyJudgedKinds(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, id := pinnedRoot(t)
	hash := readPointer(t, ctl)
	logID := controlLogID(t, ctl)
	store := installedStore(ctl)
	sigPath := config.SignaturePath(store, hash)
	priv := hostPriv(t, ctl)
	valid1 := mustRead(t, sigPath)
	at1 := controlEvents(t, ctl)[0].Time.UTC()

	expect := func(name string, kind verifyKind, detail string) {
		t.Helper()
		cfg, reg, h, installed, errs, unverified := resolveAdvance(t, ctl)
		if unverified == nil {
			t.Fatalf("%s: want a verdict, got reg=%v errs=%v", name, reg, errs)
		}
		if unverified.Kind != kind || unverified.Detail != detail {
			t.Fatalf("%s: kind %d detail %q\nwant kind %d detail %q", name, unverified.Kind, unverified.Detail, kind, detail)
		}
		if reg != nil || h != hash || !installed || errs != nil || len(cfg.Roles) == 0 || unverified.Transient() {
			t.Fatalf("%s: a verdict ⇒ cfg loaded, reg nil, hash set, installed, errs nil: reg=%v h=%q installed=%v errs=%v roles=%d", name, reg, h, installed, errs, len(cfg.Roles))
		}
	}

	// unsigned: no .sig.
	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	expect("no .sig", verifyUnsigned, "no signature file for "+hash)
	if floorBytes(t, ctl) != "" {
		t.Fatal("a verdict must not create the floor")
	}
	// unsigned: a .sig with first line foo/v9 — named as format, never as a key.
	if err := os.WriteFile(sigPath, bytes.Replace(valid1, []byte(config.SignatureFormatV1+"\n"), []byte("foo/v9\n"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("foreign format", verifyUnsigned, `unsupported signature format "foo/v9"`)
	// unsigned: a .sig hand-written at seq 2 against a ledger at seq 1 — the sigNewer rendering, never "retry".
	newer, _ := config.SignaturePayload(hash, logID, 2, at1, id)
	writeSigAt(t, ctl, newer, config.Sign(priv, newer))
	expect("newer than the install", verifyUnsigned, "signature is for version 2, installed is 1")
	// unknown key: the golden key's id, before any verify — and the underlying verdict still satisfies errNotSigned.
	foreign, _ := config.SignaturePayload(hash, logID, 1, at1, goldenKeyID)
	writeSigAt(t, ctl, foreign, config.Sign(priv, foreign))
	expect("unknown key", verifyUnknownKey, "signature is by key "+goldenKeyID+"; configured key is "+id)
	if _, err := verifySignatureFile(store, hash, logID, 1, at1, signingPub(t, ctl)); !errors.Is(err, errNotSigned) {
		t.Fatalf("the verdict beneath unknown key is still not-signed: %v", err)
	}
	// bad signature: flip one base64 character of the valid file's trailer.
	f, err := config.ParseSignatureFile(valid1)
	if err != nil {
		t.Fatal(err)
	}
	flipped := []byte(f.Sig)
	if flipped[0] == 'A' {
		flipped[0] = 'B'
	} else {
		flipped[0] = 'A'
	}
	writeSigAt(t, ctl, f.Payload, string(flipped))
	expect("bad signature", verifyBadSignature, "")
	// unsigned: the seq-1 .sig after an identical re-apply to seq 2.
	applyAs(t, root, ctl)
	if err := os.WriteFile(sigPath, valid1, 0o600); err != nil {
		t.Fatal(err)
	}
	expect("stale .sig", verifyUnsigned, "signature is for version 1, installed is 2")
	// back to valid: a further identical re-apply (seq 3) signs the current install.
	applyAs(t, root, ctl) // seq 3, signed
	if _, reg, _, _, errs, unverified := resolveAdvance(t, ctl); reg == nil || errs != nil || unverified != nil {
		t.Fatalf("restored: %v %v", errs, unverified)
	}
	if floorBytes(t, ctl) != logID+" 3\n" {
		t.Fatalf("floor after the pass: %q", floorBytes(t, ctl))
	}
	// stale: floor hand-written above the install.
	if err := os.WriteFile(verifyFloorPath(ctl), []byte(logID+" 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("stale", verifyStale, "version 3 is below this root's verified floor 5 (ledger "+logID+")")
	if floorBytes(t, ctl) != logID+" 5\n" {
		t.Fatal("a stale verdict leaves the floor")
	}
	// foreign ledger: the floor names another log_id — judged before the version.
	if err := os.WriteFile(verifyFloorPath(ctl), []byte(strings.Repeat("f", 32)+" 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("foreign ledger", verifyForeignLedger, "install is of ledger "+logID+"; this root last verified ledger "+strings.Repeat("f", 32)+" (version 1); remove "+verifyFloorPath(ctl)+" to accept the new ledger")
	// ORDER: .sig removed AND the floor foreign → unsigned (the signature is judged before the floor).
	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	expect("unsigned before foreign", verifyUnsigned, "no signature file for "+hash)
}

// TestPinnedVerifyNotVerifiableCauses: every permanent fault is a recorded
// "not verifiable" naming its cause — never "unsigned", never state A, never
// a silent pass.
func TestPinnedVerifyNotVerifiableCauses(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := pinnedRoot(t)
	logID := controlLogID(t, ctl)
	pin := verifyPubPath(ctl)
	pubPEM := mustRead(t, pin)

	expectRefusal := func(name string, kind verifyKind, detailPrefix string, key string) *verifyRefusal {
		t.Helper()
		before := ledgerBytes(t, ctl)
		cfg, reg, h, installed, errs, unverified := resolveRunConfig(ctl, key, verifyAndAdvance)
		if !bytes.Equal(before, ledgerBytes(t, ctl)) {
			t.Fatalf("%s: wrote the control ledger", name)
		}
		if unverified == nil || unverified.Kind != kind || !strings.HasPrefix(unverified.Detail, detailPrefix) {
			t.Fatalf("%s: want kind %d %q…, got unverified=%v reg=%v errs=%v", name, kind, detailPrefix, unverified, reg, errs)
		}
		if reg != nil || errs != nil {
			t.Fatalf("%s: reg=%v errs=%v", name, reg, errs)
		}
		_, _, _ = cfg, h, installed
		return unverified
	}
	expectNV := func(name, detailPrefix string, key string) *verifyRefusal {
		t.Helper()
		return expectRefusal(name, verifyNotVerifiable, detailPrefix, key)
	}

	// The pin, judged before any lock: unreadable; junk; a PRIVATE KEY block; a named path that is absent.
	if os.Geteuid() != 0 {
		if err := os.Chmod(pin, 0); err != nil {
			t.Fatal(err)
		}
		_ = expectNV("pin unreadable", "pinned key "+pin+": ", "")
		if err := os.Chmod(pin, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(pin, []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = expectNV("pin junk", "pinned key "+pin+": signing public key: no PEM block", "")
	if err := os.WriteFile(pin, mustRead(t, signingKeyPath(ctl)), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = expectNV("pin is a private key", "pinned key "+pin+": signing public key: PEM block type \"PRIVATE KEY\"", "")
	if err := os.WriteFile(pin, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "absent.pub")
	r := expectNV("--verify-key names a missing file", "pinned key "+missing+": ", missing)
	if !strings.Contains(r.Detail, "no such file") {
		t.Fatalf("F: %q", r.Detail)
	}
	// Never state A: the pass with the conventional pin, but the flag's path absent, still refuses.
	if floorBytes(t, ctl) != "" {
		t.Fatal("a refused pin must not advance the floor")
	}

	// The floor: garbage, 07, 0, a directory — read faults; an unwritable root — the write fault after a verified signature.
	for _, bad := range []string{"garbage\n", logID + " 07\n", logID + " 0\n"} {
		if err := os.WriteFile(verifyFloorPath(ctl), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = expectNV("floor "+strings.TrimSpace(bad), "verify.floor: ", "")
		if floorBytes(t, ctl) != bad {
			t.Fatal("a corrupt floor is never rewritten")
		}
	}
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(verifyFloorPath(ctl), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = expectNV("floor is a directory", "verify.floor: ", "")
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Dir(ctl), 0o500); err != nil {
			t.Fatal(err)
		}
		r := expectNV("floor unwritable", "verify.floor: ", "")
		if err := os.Chmod(filepath.Dir(ctl), 0o700); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.Detail, "permission denied") || floorBytes(t, ctl) != "" {
			t.Fatalf("unwritable: %q floor=%q", r.Detail, floorBytes(t, ctl))
		}
	}

	// The ledger: the crash hook (pointer moved, no record); the ledger removed; torn; genesis without log_id.
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	_, _ = applyCode(t, root, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	_ = expectRefusal("crash in the install→record gap", verifyNotOnRecord, "last recorded install is ", "")
	applyAs(t, root, ctl) // re-apply records and signs it; the pass advances the floor
	if _, reg, _, _, _, unverified := resolveAdvance(t, ctl); reg == nil || unverified != nil {
		t.Fatalf("re-apply heals: %v", unverified)
	}
	appendFragment(t, ctl)
	_ = expectNV("torn ledger", "control ledger damaged; run: agenthof audit repair control --control-log "+ctl, "")
	ledgerSaved := mustRead(t, ctl)
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	_ = expectRefusal("ledger removed", verifyNotOnRecord, "no install on record", "")
	// ORDER: ledger removed AND .sig removed → not on record (the ledger is read first).
	hash := readPointer(t, ctl)
	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	_ = expectRefusal("no ledger, no .sig", verifyNotOnRecord, "no install on record", "")
	if err := os.WriteFile(ctl, ledgerSaved, 0o600); err != nil {
		t.Fatal(err)
	}

	// Genesis without log_id, on its own pinned root.
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl2)
	pinHostKey(t, ctl2)
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
	if _, _, _, _, _, unverified := resolveRunConfig(ctl2, "", verifyAndAdvance); unverified == nil || unverified.Kind != verifyNotVerifiable || unverified.Detail != "control ledger genesis has no log_id" {
		t.Fatalf("genesis without log_id: %v", unverified)
	}
}

// TestPinnedVerifyOrderAgainstTheStoreChecks: bytes-vs-pointer still runs
// first (a tampered snapshot is "configuration invalid", unverified nil); a
// corrupt pin is judged before the lock is taken (a held lock does not make
// it wait); a .sig that cannot be read (EISDIR) is a store fault in errs,
// never a verdict.
func TestPinnedVerifyOrderAgainstTheStoreChecks(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, _ := pinnedRoot(t)

	// corrupt pin + held lock: returns at once with the pin fault (the lock is never taken).
	holdLock(t, "file", installedLock(ctl), 9000)
	pubPEM := mustRead(t, verifyPubPath(ctl))
	if err := os.WriteFile(verifyPubPath(ctl), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, _, _, _, unverified := resolveRunConfig(ctl, "", verifyAndAdvance)
	if unverified == nil || unverified.Kind != verifyNotVerifiable || !strings.HasPrefix(unverified.Detail, "pinned key ") {
		t.Fatalf("pin before lock: %v", unverified)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("a pin fault must not wait on the lock")
	}
	if err := os.WriteFile(verifyPubPath(ctl), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// (the holder keeps the lock ~9 s; the rows below need it released — use a fresh root)
	ctl, _, _ = pinnedRoot(t)
	hash := readPointer(t, ctl)
	store := installedStore(ctl)

	// tamper + pin: VerifyInstalled's mismatch, alone, unverified nil, no floor.
	coder := filepath.Join(config.SnapshotDir(store, hash), "agents", "coder.yaml")
	data := mustRead(t, coder)
	if err := os.WriteFile(coder, append(data, []byte("enabled: false\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reg, _, installed, errs, unverified := resolveAdvance(t, ctl); reg != nil || !installed || len(errs) != 1 || !strings.Contains(errs[0].Error(), "not as its pointer") || unverified != nil || floorBytes(t, ctl) != "" {
		t.Fatalf("tamper: reg=%v errs=%v unverified=%v floor=%q", reg, errs, unverified, floorBytes(t, ctl))
	}
	if err := os.WriteFile(coder, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// .sig unreadable (a directory): a store fault, reported as LoadInstalled's I/O faults are.
	sigPath := config.SignaturePath(store, hash)
	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sigPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, reg, _, installed, errs, unverified := resolveAdvance(t, ctl); reg != nil || !installed || len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "installed config "+hash+": ") || unverified != nil {
		t.Fatalf("EISDIR: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
}

// TestPinnedVerifyFloorRules: the floor across installs — an identical
// re-apply advances it; a partial rollback (ledger + .sig restored, floor
// left) is stale; removing the floor re-accepts the older install and
// re-creates the floor at it; a re-created control root under the same key
// is a foreign ledger until the floor is removed.
func TestPinnedVerifyFloorRules(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := pinnedRoot(t)
	hash := readPointer(t, ctl)
	logID := controlLogID(t, ctl)
	sigPath := config.SignaturePath(installedStore(ctl), hash)
	if _, reg, _, _, _, unverified := resolveAdvance(t, ctl); reg == nil || unverified != nil {
		t.Fatal(unverified)
	}
	ledger1, sig1 := mustRead(t, ctl), mustRead(t, sigPath)

	applyAs(t, root, ctl) // identical re-apply: seq 2, signed
	if _, reg, _, _, _, unverified := resolveAdvance(t, ctl); reg == nil || unverified != nil || floorBytes(t, ctl) != logID+" 2\n" {
		t.Fatalf("advance: %v floor=%q", unverified, floorBytes(t, ctl))
	}
	// partial rollback: the seq-1 ledger and .sig put back, floor left at 2.
	if err := os.WriteFile(ctl, ledger1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig1, 0o600); err != nil {
		t.Fatal(err)
	}
	_, reg, _, _, _, unverified := resolveAdvance(t, ctl)
	if reg != nil || unverified == nil || unverified.Kind != verifyStale || unverified.Detail != "version 1 is below this root's verified floor 2 (ledger "+logID+")" {
		t.Fatalf("stale: reg=%v %v", reg, unverified)
	}
	// reset: the documented gesture re-accepts the older install.
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if _, reg, _, _, _, unverified := resolveAdvance(t, ctl); reg == nil || unverified != nil || floorBytes(t, ctl) != logID+" 1\n" {
		t.Fatalf("reset: %v floor=%q", unverified, floorBytes(t, ctl))
	}
	// foreign ledger: a re-created control root (new genesis) under the same key.
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(installedStore(ctl), config.InstalledPointer)); err != nil {
		t.Fatal(err)
	}
	applyAs(t, root, ctl) // bootstrap: seq 1 of a NEW ledger, signed
	newLogID := controlLogID(t, ctl)
	if newLogID == logID {
		t.Fatal("a re-created root must have a new log_id")
	}
	_, reg, _, _, _, unverified = resolveAdvance(t, ctl)
	if reg != nil || unverified == nil || unverified.Kind != verifyForeignLedger || unverified.Detail != "install is of ledger "+newLogID+"; this root last verified ledger "+logID+" (version 1); remove "+verifyFloorPath(ctl)+" to accept the new ledger" {
		t.Fatalf("foreign: reg=%v %v", reg, unverified)
	}
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if _, reg, _, _, _, unverified := resolveAdvance(t, ctl); reg == nil || unverified != nil || floorBytes(t, ctl) != newLogID+" 1\n" {
		t.Fatalf("accept the new ledger: %v floor=%q", unverified, floorBytes(t, ctl))
	}
}

// TestPinnedVerifyWholeRootRestoreIsNotSeen is the honest limit, pinned
// as a fact: restoring control.jsonl, the .sig AND verify.floor together as
// of seq 1 — a whole-root restore — PASSES; the floor cannot see a rollback
// it was rolled back with. Only the partial restore (floor left) is stale.
func TestPinnedVerifyWholeRootRestoreIsNotSeen(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := pinnedRoot(t)
	hash := readPointer(t, ctl)
	logID := controlLogID(t, ctl)
	sigPath := config.SignaturePath(installedStore(ctl), hash)
	if _, _, _, _, _, unverified := resolveAdvance(t, ctl); unverified != nil {
		t.Fatal(unverified)
	}
	ledger1, sig1, floor1 := mustRead(t, ctl), mustRead(t, sigPath), mustRead(t, verifyFloorPath(ctl))
	applyAs(t, root, ctl)
	if _, _, _, _, _, unverified := resolveAdvance(t, ctl); unverified != nil || floorBytes(t, ctl) != logID+" 2\n" {
		t.Fatalf("at 2: %v %q", unverified, floorBytes(t, ctl))
	}
	for p, b := range map[string][]byte{ctl: ledger1, sigPath: sig1, verifyFloorPath(ctl): floor1} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, reg, _, _, errs, unverified := resolveAdvance(t, ctl)
	if reg == nil || errs != nil || unverified != nil {
		t.Fatalf("the whole-root restore is accepted — the documented limit: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
	if floorBytes(t, ctl) != logID+" 1\n" {
		t.Fatalf("the floor came back at 1 too: %q", floorBytes(t, ctl))
	}
}

// TestPinnedVerifyAdvancesTheFloorEvenWhenBuildFails: the floor tracks
// verified signatures, not valid configurations — a signed kill-switch flip
// that disables an agent a workflow needs installs a snapshot that does not
// Build; the run is refused "configuration invalid", and the floor advanced.
func TestPinnedVerifyAdvancesTheFloorEvenWhenBuildFails(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := pinnedRoot(t)
	logID := controlLogID(t, ctl)
	if _, _, _, _, _, unverified := resolveAdvance(t, ctl); unverified != nil {
		t.Fatal(unverified)
	}
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 || !strings.Contains(out.String(), "signed: key_id") {
		t.Fatalf("flip: %d\n%s", code, out.String())
	}
	_, reg, _, installed, errs, unverified := resolveAdvance(t, ctl)
	if reg != nil || !installed || unverified != nil || len(errs) == 0 || !strings.Contains(errs[0].Error(), "disabled") {
		t.Fatalf("flip: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
	if floorBytes(t, ctl) != logID+" 2\n" {
		t.Fatalf("the verified flip advances the floor: %q", floorBytes(t, ctl))
	}
}

// TestRunRefusesAnUnsignedInstallWhenPinned wires cmdRun: the detail line,
// the result line with the headline, the run ledger's run_refused.reason as
// the full reason, exit 1, no control event.
func TestRunRefusesAnUnsignedInstallWhenPinned(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := pinnedRoot(t)
	hash := readPointer(t, ctl)
	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	events := len(controlEvents(t, ctl))
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "hi", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
	reason := "configuration not verified: unsigned: no signature file for " + hash
	if code != 1 || !strings.Contains(out.String(), "run: "+reason+"\n") {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused: configuration not verified: unsigned\n`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("result line with the headline:\n%s", out.String())
	}
	ev, _, err := engine.ReadLog(logs, m[1])
	if err != nil || len(ev) != 1 || ev[0].Type != "run_refused" || ev[0].Reason != reason {
		t.Fatalf("ledger: %+v %v", ev, err)
	}
	if len(controlEvents(t, ctl)) != events {
		t.Fatal("a refusal writes no control event")
	}
}

// TestRunHostPrepareMapsAVerdictToTheTypedError wires serve's Prepare: a
// verdict is *serve.ConfigNotVerifiedError{Headline, Reason}; a pass prepares.
func TestRunHostPrepareMapsAVerdictToTheTypedError(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, _ := pinnedRoot(t)
	hash := readPointer(t, ctl)
	// The real host's shape (cmdServe, serve.go:114); newRunDeps only stores the broker, but build it as serve does.
	h := &runHost{controlLog: ctl, logDir: t.TempDir(), artifactDir: t.TempDir(), logger: obs.New(io.Discard, slog.LevelDebug, obs.FormatText), broker: newBroker(subjectTokenTypeFromEnv(os.Getenv))}
	if _, err := h.Prepare(identity.Invoker{}, ""); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if floorBytes(t, ctl) != controlLogID(t, ctl)+" 1\n" {
		t.Fatalf("Prepare is an execution read: it advances the floor: %q", floorBytes(t, ctl))
	}
	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	_, err := h.Prepare(identity.Invoker{}, "")
	var nv *serve.ConfigNotVerifiedError
	if !errors.As(err, &nv) || nv.Headline != "configuration not verified: unsigned" || nv.Reason != "configuration not verified: unsigned: no signature file for "+hash || err.Error() != nv.Reason {
		t.Fatalf("%T %v", err, err)
	}
	if errors.Is(err, serve.ErrConfigInvalid) || errors.Is(err, serve.ErrNoConfigInstalled) {
		t.Fatal("a verdict is neither invalid nor not-installed")
	}
}

// TestPinnedRunBusyIsUnrecordedAndWaitsBehindAShortHold: a writer
// holding installed.lock exclusively for LESS than lockTimeout → the run
// waits, sees the consistent triple the writer published, and passes
// (nothing recorded); for LONGER → busy: cmdRun prints the busy line, exits
// 1, mints no run id, writes no run ledger file and no control event; the
// holder of only the ledger flock → the same busy from the inner ReadVerify;
// Prepare → serve.ErrConfigBusy. One parent sets the env; the 5 s rows run in
// parallel.
func TestPinnedRunBusyIsUnrecordedAndWaitsBehindAShortHold(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")

	t.Run("short hold: wait and pass", func(t *testing.T) {
		t.Parallel()
		ctl, _, _ := pinnedRoot(t)
		hash := readPointer(t, ctl)
		logID := controlLogID(t, ctl)
		// Simulate a writer: under the exclusive lock, swap in a .sig for a
		// version the ledger does not vouch for yet, then (still under the
		// lock) put the valid one back — the run must never see the middle.
		valid := mustRead(t, config.SignaturePath(installedStore(ctl), hash))
		unlock, err := ledger.LockFile(installedLock(ctl))
		if err != nil {
			t.Fatal(err)
		}
		priv := hostPriv(t, ctl)
		newer, _ := config.SignaturePayload(hash, logID, 2, controlEvents(t, ctl)[0].Time.UTC(), config.KeyID(signingPub(t, ctl)))
		writeSigAt(t, ctl, newer, config.Sign(priv, newer))
		go func() {
			time.Sleep(1500 * time.Millisecond)
			if err := os.WriteFile(config.SignaturePath(installedStore(ctl), hash), valid, 0o600); err != nil {
				panic(err)
			}
			unlock()
		}()
		start := time.Now()
		_, reg, _, _, errs, unverified := resolveAdvance(t, ctl)
		if elapsed := time.Since(start); elapsed < time.Second {
			t.Fatalf("the run must wait behind the writer, not read through it (%v)", elapsed)
		}
		if reg == nil || errs != nil || unverified != nil {
			t.Fatalf("after the writer released, the consistent triple passes: errs=%v unverified=%v", errs, unverified)
		}
		if floorBytes(t, ctl) != logID+" 1\n" {
			t.Fatalf("floor %q", floorBytes(t, ctl))
		}
	})

	for _, c := range []struct{ name, kind string }{{"installed.lock held", "file"}, {"ledger lock held", "ledger"}} {
		t.Run("long hold: "+c.name, func(t *testing.T) {
			t.Parallel()
			ctl, root, _ := pinnedRoot(t)
			path := installedLock(ctl)
			if c.kind == "ledger" {
				path = ctl
			}
			ledgerBefore := mustRead(t, ctl)
			// Three reads follow, and each waits out the lock timeout, so the
			// hold has to outlast all of them.
			holdLock(t, c.kind, path, 20000)

			// The resolution itself: busy ⇒ nothing else is set.
			cfg, reg, hash, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance)
			if unverified == nil || !unverified.Transient() || reg != nil || hash != "" || installed || errs != nil || len(cfg.Roles) != 0 {
				t.Fatalf("busy: unverified=%v reg=%v hash=%q installed=%v errs=%v", unverified, reg, hash, installed, errs)
			}
			if floorBytes(t, ctl) != "" {
				t.Fatal("busy must not touch the floor")
			}

			// cmdRun: the busy line, exit 1, no run id, no run ledger file.
			logs := t.TempDir()
			var out bytes.Buffer
			code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "hi", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
			if code != 1 || out.String() != "run: "+msgLockBusy+"\n" {
				t.Fatalf("code %d out %q", code, out.String())
			}
			if entries, _ := os.ReadDir(logs); len(entries) != 0 {
				t.Fatalf("busy mints no run and writes no run ledger: %v", entries)
			}
			if !bytes.Equal(ledgerBefore, mustRead(t, ctl)) {
				t.Fatal("busy writes no control event")
			}

			// Prepare: the busy sentinel.
			h := &runHost{controlLog: ctl, logDir: t.TempDir(), artifactDir: t.TempDir(), logger: obs.New(io.Discard, slog.LevelDebug, obs.FormatText), broker: newBroker(subjectTokenTypeFromEnv(os.Getenv))}
			if _, err := h.Prepare(identity.Invoker{}, ""); !errors.Is(err, serve.ErrConfigBusy) {
				t.Fatalf("Prepare under a held lock: %v", err)
			}
		})
	}
}

// TestServeStartupSaysNothingWhenTheLockIsHeld: a lock held past the timeout
// at startup is not a verdict — no Warn about the pinned key, serve starts,
// no floor. (Startup waits out lockTimeout first, so the address-file
// deadline is widened.)
func TestServeStartupSaysNothingWhenTheLockIsHeld(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, _ := pinnedRoot(t)
	holdLock(t, "file", installedLock(ctl), 9000)
	logs := startServeOnceWithin(t, ctl, 12*time.Second)
	if strings.Contains(logs, "pinned key") || strings.Contains(logs, "level=WARN") {
		t.Fatalf("busy at startup says nothing:\n%s", logs)
	}
	if !strings.Contains(logs, "serve started") {
		t.Fatalf("serve starts:\n%s", logs)
	}
	if _, err := os.Stat(verifyFloorPath(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no floor at startup")
	}
}

// TestRunRefusalMatrixWhenPinned: every recorded kind through cmdRun — exit
// 1, "run: <reason>" then "run r-… refused: <headline>", the run ledger's
// run_refused.reason the full reason, and no control event. (Unsigned is
// pinned in TestRunRefusesAnUnsignedInstallWhenPinned.)
func TestRunRefusalMatrixWhenPinned(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, id := pinnedRoot(t)
	hash := readPointer(t, ctl)
	logID := controlLogID(t, ctl)
	store := installedStore(ctl)
	sigPath := config.SignaturePath(store, hash)
	priv := hostPriv(t, ctl)
	at := controlEvents(t, ctl)[0].Time.UTC()
	valid := mustRead(t, sigPath)
	events := len(controlEvents(t, ctl))

	run := func(name, wantReason, wantHeadline string) {
		t.Helper()
		logs := t.TempDir()
		var out bytes.Buffer
		code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "hi", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", logs}, &out, io.Discard)
		if code != 1 || !strings.Contains(out.String(), "run: "+wantReason+"\n") {
			t.Fatalf("%s: code %d\n%s", name, code, out.String())
		}
		m := regexp.MustCompile(`run (r-[0-9a-f]{16}) refused: ` + regexp.QuoteMeta(wantHeadline) + `\n`).FindStringSubmatch(out.String())
		if m == nil {
			t.Fatalf("%s: result line:\n%s", name, out.String())
		}
		ev, _, err := engine.ReadLog(logs, m[1])
		if err != nil || len(ev) != 1 || ev[0].Type != "run_refused" || ev[0].Reason != wantReason {
			t.Fatalf("%s: ledger %+v %v", name, ev, err)
		}
		if len(controlEvents(t, ctl)) != events {
			t.Fatalf("%s: wrote a control event", name)
		}
	}

	foreign, _ := config.SignaturePayload(hash, logID, 1, at, goldenKeyID)
	writeSigAt(t, ctl, foreign, config.Sign(priv, foreign))
	run("unknown key", "configuration not verified: unknown key: signature is by key "+goldenKeyID+"; configured key is "+id, "configuration not verified: unknown key")

	good, _ := config.SignaturePayload(hash, logID, 1, at, id)
	writeSigAt(t, ctl, good, config.Sign(priv, foreign))
	run("bad signature", "configuration not verified: bad signature", "configuration not verified: bad signature")

	if err := os.WriteFile(sigPath, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verifyFloorPath(ctl), []byte(logID+" 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("stale", "configuration not verified: stale: version 1 is below this root's verified floor 5 (ledger "+logID+")", "configuration not verified: stale")

	if err := os.WriteFile(verifyFloorPath(ctl), []byte(strings.Repeat("f", 32)+" 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("foreign ledger", "configuration not verified: foreign ledger: install is of ledger "+logID+"; this root last verified ledger "+strings.Repeat("f", 32)+" (version 1); remove "+verifyFloorPath(ctl)+" to accept the new ledger", "configuration not verified: foreign ledger")

	if err := os.WriteFile(verifyFloorPath(ctl), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("not verifiable: floor", "configuration not verifiable: verify.floor: 1 fields; want <log_id> <version>", "configuration not verifiable")
	if err := os.Remove(verifyFloorPath(ctl)); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(verifyPubPath(ctl), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("not verifiable: pin", "configuration not verifiable: pinned key "+verifyPubPath(ctl)+": signing public key: no PEM block", "configuration not verifiable")
	pinHostKey(t, ctl)

	// And the pass, for the matrix's sake: exit 0, floor created.
	var out bytes.Buffer
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "hi", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir()}, &out, io.Discard); code != 0 || !strings.Contains(out.String(), "finished: succeeded") {
		t.Fatalf("pass: %d\n%s", code, out.String())
	}
	if floorBytes(t, ctl) != logID+" 1\n" {
		t.Fatalf("floor %q", floorBytes(t, ctl))
	}
}

// TestRunVerifyKeyFlag: --verify-key reads the pin from the named path (the
// floor stays beside --control-log); a named path that is absent fails closed
// — never state A; with --server the flag is ignored and said so on stderr
// only when it was given.
func TestRunVerifyKeyFlag(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	ctl, root, _ := signedRoot(t) // signed, NOT pinned at the conventional path
	keyDir := t.TempDir()
	key := filepath.Join(keyDir, "operator.pub")
	if err := os.WriteFile(key, mustRead(t, signingPubPath(ctl)), 0o600); err != nil {
		t.Fatal(err)
	}
	args := func(extra ...string) []string {
		return append([]string{"software-engineer", "fix-bug", "--input", "hi", "--as", "dana@example.com", "--config", root, "--control-log", ctl, "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir()}, extra...)
	}
	var out, stderr bytes.Buffer
	if code := cmdRun(args("--verify-key", key), &out, &stderr); code != 0 || !strings.Contains(out.String(), "finished: succeeded") {
		t.Fatalf("pinned by flag: %d\n%s", code, out.String())
	}
	if floorBytes(t, ctl) != controlLogID(t, ctl)+" 1\n" {
		t.Fatalf("the floor lives beside --control-log, wherever the key is: %q", floorBytes(t, ctl))
	}
	if _, err := os.Stat(filepath.Join(keyDir, "verify.floor")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no floor beside the key")
	}
	if _, err := os.Stat(verifyPubPath(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("agenthof never writes verify.pub")
	}

	// State F: the flag names a missing file — refused, recorded; never today's unverified run.
	out.Reset()
	missing := filepath.Join(keyDir, "nowhere.pub")
	code := cmdRun(args("--verify-key", missing), &out, &stderr)
	if code != 1 || !strings.Contains(out.String(), "run: configuration not verifiable: pinned key "+missing+": ") || !strings.Contains(out.String(), "no such file") || !strings.Contains(out.String(), "refused: configuration not verifiable\n") {
		t.Fatalf("F: %d\n%s", code, out.String())
	}

	// --server: the flag is ignored, said on stderr only when given.
	out.Reset()
	stderr.Reset()
	_ = cmdRun([]string{"software-engineer", "fix-bug", "--input", "hi", "--server", "http://127.0.0.1:1", "--token", "x", "--verify-key", key}, &out, &stderr)
	if !strings.Contains(stderr.String(), "run: --verify-key is ignored with --server") {
		t.Fatalf("stderr:\n%s", stderr.String())
	}
	stderr.Reset()
	_ = cmdRun([]string{"software-engineer", "fix-bug", "--input", "hi", "--server", "http://127.0.0.1:1", "--token", "x"}, &out, &stderr)
	if strings.Contains(stderr.String(), "verify-key") {
		t.Fatalf("the default prints nothing:\n%s", stderr.String())
	}

	// usage names the flag on the run line; serve has no such flag.
	if !strings.Contains(usage, "agenthof run <role> <workflow> --input <text>") || !strings.Contains(usage, "[--verify-key <path>]") {
		t.Fatalf("usage:\n%s", usage)
	}
	var sout bytes.Buffer
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test")
	if code := cmdServe(context.Background(), []string{"--verify-key", key}, &sout, io.Discard); code != 2 || !strings.Contains(sout.String(), "flag provided but not defined: -verify-key") {
		t.Fatalf("serve must not grow the flag: %d\n%s", code, sout.String())
	}
}
