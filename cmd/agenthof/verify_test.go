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
		_ = time.Now() // keeps the time import live for the next task's tests
	}
}
