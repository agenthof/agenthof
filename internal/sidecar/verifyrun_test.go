package sidecar_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/sidecar"
)

// anchoredRun writes a finished run and a stub-minted sidecar beside it.
func anchoredRun(t *testing.T, dir string, stub *anchortest.Stub) {
	t.Helper()
	chain := finishedRun(t, dir, testRun)
	if err := sidecar.Append(sidecar.Path(dir, testRun), testRun, headRecord(t, stub, testRun, chain)); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRunTouchesNothingWithoutASidecar: a run with no sidecar is not
// anchored, and neither the pin nor the ledger is read to say so; a name that
// is not a run id is not anchored either and never joined into a path.
func TestVerifyRunTouchesNothingWithoutASidecar(t *testing.T) {
	dir := t.TempDir()
	finishedRun(t, dir, testRun)
	key := func() (*ecdsa.PublicKey, error) {
		t.Fatal("the pin was resolved for an unanchored run")
		return nil, nil
	}
	if v, pinned := sidecar.VerifyRun(dir, testRun, key, nil, true, 0); v.Found || pinned || v.State() != sidecar.StateNotAnchored {
		t.Fatalf("%+v pinned=%v", v, pinned)
	}
	for _, id := range []string{"../r-0123456789abcdef", "r-child", "", "r-0123456789ABCDEF"} {
		if v, _ := sidecar.VerifyRun(dir, id, key, nil, true, 0); v.Found {
			t.Fatalf("%q: %+v", id, v)
		}
	}
}

func TestVerifyRunPinnedFlagFollowsTheResolvedKey(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	dir := t.TempDir()
	anchoredRun(t, dir, stub)
	factory := stubOpts(stub).Factory
	pub, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		key        func() (*ecdsa.PublicKey, error)
		wantPinned bool
		wantState  string
	}{
		{"no key func", nil, false, sidecar.StateVerified},
		{"unpinned", func() (*ecdsa.PublicKey, error) { return nil, nil }, false, sidecar.StateVerified},
		{"pinned", func() (*ecdsa.PublicKey, error) { return &pub.PublicKey, nil }, true, sidecar.StateVerified},
		{"pin unreadable", func() (*ecdsa.PublicKey, error) { return nil, errors.New("pinned log key x: no such file") }, false, sidecar.StateUnverifiable},
	} {
		v, pinned := sidecar.VerifyRun(dir, testRun, c.key, factory, true, 0)
		if pinned != c.wantPinned || v.State() != c.wantState || !v.Found {
			t.Errorf("%s: pinned=%v state=%s %+v", c.name, pinned, v.State(), v)
		}
	}
	// The pin is resolved once per call however many records there are.
	calls := 0
	_, _ = sidecar.VerifyRun(dir, testRun, func() (*ecdsa.PublicKey, error) { calls++; return nil, nil }, factory, true, 0)
	if calls != 1 {
		t.Errorf("key resolved %d times", calls)
	}
}

// TestVerifyRunUnreadableErrorsHideTheLogDirPath: both found-but-unreadable
// branches — a sidecar that cannot be statted, and a sidecar beside a ledger
// that cannot be read — name the file by its base name and never leak the
// absolute <log-dir> path to the (authenticated) reader.
func TestVerifyRunUnreadableErrorsHideTheLogDirPath(t *testing.T) {
	// A log dir that is a regular file: Lstat of the sidecar beneath it is a
	// found-but-unreadable fault (not ErrNotExist), carrying the joined path.
	notDir := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, _ := sidecar.VerifyRun(notDir, testRun, nil, nil, true, 0)
	if !v.Found || v.Err == nil || v.State() != sidecar.StateUnverifiable {
		t.Fatalf("lstat branch: %+v", v)
	}
	if msg := v.Err.Error(); strings.Contains(msg, notDir) || !strings.Contains(msg, testRun+sidecar.Suffix) {
		t.Errorf("lstat branch leaks path or drops base name: %q", msg)
	}

	// A sidecar beside a removed ledger: the ledger-read fault must not leak
	// the path either.
	stub := anchortest.NewStub([]byte("s"))
	dir := t.TempDir()
	anchoredRun(t, dir, stub)
	if err := os.Remove(filepath.Join(dir, testRun+".jsonl")); err != nil {
		t.Fatal(err)
	}
	v, _ = sidecar.VerifyRun(dir, testRun, nil, stubOpts(stub).Factory, true, 0)
	if !v.Found || v.Err == nil || v.State() != sidecar.StateUnverifiable {
		t.Fatalf("ledger branch: %+v", v)
	}
	if msg := v.Err.Error(); strings.Contains(msg, dir) || !strings.Contains(msg, testRun) {
		t.Errorf("ledger branch leaks path or drops base name: %q", msg)
	}
}

// TestVerifyRunUnreadableIsUnverifiableNeverNotAnchored: a sidecar beside a
// ledger that cannot be read, or a sidecar that is not a file, is a found
// verdict that is unverifiable — absence is the only way to read not anchored.
func TestVerifyRunUnreadableIsUnverifiableNeverNotAnchored(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	dir := t.TempDir()
	anchoredRun(t, dir, stub)
	if err := os.Remove(filepath.Join(dir, testRun+".jsonl")); err != nil {
		t.Fatal(err)
	}
	v, _ := sidecar.VerifyRun(dir, testRun, nil, stubOpts(stub).Factory, true, 0)
	if !v.Found || v.Err == nil || v.State() != sidecar.StateUnverifiable || !strings.Contains(sidecar.Lines(v, sidecar.RenderOptions{}), "ledger anchor: unverifiable — ") {
		t.Fatalf("%+v", v)
	}
}
