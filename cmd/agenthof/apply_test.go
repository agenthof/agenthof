package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

const zeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// admin is the invoker writeSample's platform-admin role grants apply to.
var admin = identity.Invoker{Subject: "dana@example.com", Issuer: "local", Method: "asserted", Groups: []string{"platform-eng"}}

// controlEvents reads every decoded control event.
func controlEvents(t *testing.T, controlLog string) []control.DecodedEvent {
	t.Helper()
	recs, _, err := ledger.ReadVerify(controlLog, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	var out []control.DecodedEvent
	for _, r := range recs {
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// noStagingResidue fails if any dot-prefixed entry — a .staging-* or
// .current-* or .sig-* temp — is left under the store.
func noStagingResidue(t *testing.T, controlLog string) {
	t.Helper()
	ents, _ := os.ReadDir(installedStore(controlLog))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temp residue: %s", e.Name())
		}
	}
}

func TestApplyIfInstalledLocal(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	base := []string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}
	var out bytes.Buffer

	if code := cmdApply(append(base, "--if-installed", "garbage"), &out); code != 2 || !strings.Contains(out.String(), "--if-installed must be") {
		t.Fatalf("bad flag: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := cmdApply(append(base, "--if-installed", "none"), &out); code != 0 {
		t.Fatalf("bootstrap with none: code %d\n%s", code, out.String())
	}
	h0 := readPointer(t, ctl)
	if ev := controlEvents(t, ctl); len(ev) != 1 || !ev[0].Bootstrap {
		t.Fatalf("want one bootstrap record: %+v", ev)
	}

	out.Reset()
	code := cmdApply(append(base, "--if-installed", "none"), &out)
	if code != 1 || out.String() != "apply: precondition failed: installed configuration is "+h0+", not none\n" {
		t.Fatalf("stale none: code %d out %q", code, out.String())
	}
	out.Reset()
	code = cmdApply(append(base, "--if-installed", zeroHash), &out)
	if code != 1 || out.String() != "apply: precondition failed: installed configuration is "+h0+", not "+zeroHash+"\n" {
		t.Fatalf("stale hash: code %d out %q", code, out.String())
	}
	if len(controlEvents(t, ctl)) != 1 || readPointer(t, ctl) != h0 {
		t.Fatal("a failed precondition records nothing and moves nothing")
	}

	// the matching hash installs an edit
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	out.Reset()
	if code := cmdApply(append(base, "--if-installed", h0), &out); code != 0 || !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 2 roles") {
		t.Fatalf("matching hash: code %d\n%s", code, out.String())
	}
	if h1 := readPointer(t, ctl); h1 == h0 {
		t.Fatal("pointer must move")
	}
	if len(controlEvents(t, ctl)) != 2 {
		t.Fatal("the install must be recorded")
	}

	// on a fresh root, a hash precondition fails as "nothing"
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	out.Reset()
	code = cmdApply([]string{"--config", root, "--control-log", ctl2, "--as", "dana@example.com", "--if-installed", h0}, &out)
	if code != 1 || out.String() != "apply: precondition failed: installed configuration is nothing, not "+h0+"\n" {
		t.Fatalf("fresh root: code %d out %q", code, out.String())
	}
	if _, err := os.Stat(ctl2); err == nil {
		recs, _, _ := ledger.ReadVerify(ctl2, ledger.Locked)
		if len(recs) != 0 {
			t.Fatal("nothing may be recorded")
		}
	}
}

func writeFileIn(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// blockingSource parks an apply INSIDE the critical section: Stage closes
// entered, then waits for release, then delegates. Everything before Stage
// (the lock, the authorize-read, the precondition) has already run.
type blockingSource struct {
	inner   applySource
	entered chan struct{}
	release chan struct{}
}

func (b blockingSource) Stage(store string) (string, error) {
	close(b.entered)
	<-b.release
	return b.inner.Stage(store)
}

func (b blockingSource) Hash() (string, error) { return b.inner.Hash() }

func (b blockingSource) verifyStaged() bool { return b.inner.verifyStaged() }

// bootstrapped installs root under a fresh control root through applyConfig
// and returns the control log and the installed hash.
func bootstrapped(t *testing.T, root string) (string, string) {
	t.Helper()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	res := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(root), AllowBootstrap: true}, io.Discard)
	if res.Kind != applyInstalled {
		t.Fatalf("bootstrap: %+v", res)
	}
	return ctl, res.ConfigHash
}

// TestApplyConfigCriticalSectionIsSerialized is the deterministic TOCTOU
// proof. W1 passes authorize + precondition against H0 and is parked in
// Stage, holding the writer lock. W2, with the same (now soon-stale)
// precondition, must block on the lock — not run to completion — and, once
// W1 installs H1, must read H1 and fail its precondition with CurrentHash
// == H1. Remove the lock from applyConfig and W2 reads H0, passes, and
// installs over H1: this test then fails at the "ran to completion" check
// (or at the precondition assertion), which is what proves the guard.
func TestApplyConfigCriticalSectionIsSerialized(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	rootA := writeSample(t)
	ctl, h0 := bootstrapped(t, rootA)
	rootB := writeSample(t)
	writeFileIn(t, rootB, "agents/coder.yaml", "name: coder\nmodel: fast\ninstruction: code carefully\noutput: patch\nendpoint: http://127.0.0.1:1\n")
	rootC := writeSample(t)
	writeFileIn(t, rootC, "agents/coder.yaml", "name: coder\nmodel: fast\ninstruction: code fast\noutput: patch\nendpoint: http://127.0.0.1:1\n")

	w1src := blockingSource{inner: dirSource(rootB), entered: make(chan struct{}), release: make(chan struct{})}
	w1 := make(chan applyOutcome, 1)
	go func() {
		w1 <- applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: w1src,
			Precondition: &applyPrecondition{ExpectInstalled: h0}, AllowBootstrap: true}, io.Discard)
	}()
	<-w1src.entered // W1 holds the lock and has passed its precondition against h0

	w2 := make(chan applyOutcome, 1)
	go func() {
		w2 <- applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(rootC),
			Precondition: &applyPrecondition{ExpectInstalled: h0}, AllowBootstrap: true}, io.Discard)
	}()
	select {
	case res := <-w2:
		t.Fatalf("W2 ran to completion (%+v) while W1 held the critical section: the writer lock is missing", res)
	case <-time.After(300 * time.Millisecond):
	}
	close(w1src.release)

	r1 := <-w1
	if r1.Kind != applyInstalled || r1.ConfigHash == h0 {
		t.Fatalf("W1: %+v", r1)
	}
	r2 := <-w2
	if r2.Kind != applyPreconditionFailed || r2.CurrentHash != r1.ConfigHash {
		t.Fatalf("W2 must fail its precondition against W1's install: %+v (W1 installed %s)", r2, r1.ConfigHash)
	}
	if readPointer(t, ctl) != r1.ConfigHash {
		t.Fatal("the pointer must name W1's install, never W2's")
	}
	// W2 re-run with the current hash installs.
	r3 := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(rootC),
		Precondition: &applyPrecondition{ExpectInstalled: r1.ConfigHash}, AllowBootstrap: true}, io.Discard)
	if r3.Kind != applyInstalled || readPointer(t, ctl) != r3.ConfigHash {
		t.Fatalf("W2 retry: %+v", r3)
	}
	noStagingResidue(t, ctl)
	line, mismatch := installedPointerLine(ctl, mustRecords(t, ctl))
	if mismatch {
		t.Fatalf("pointer and ledger disagree: %s", line)
	}
}

func mustRecords(t *testing.T, ctl string) []ledger.Record {
	t.Helper()
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// TestApplyConfigBootstrapRaceIsSerialized: the same seam with ExpectNone —
// two bootstraps on a fresh root; the second sees the first's install and
// fails its precondition.
func TestApplyConfigBootstrapRaceIsSerialized(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	rootA, rootB := writeSample(t), writeSample(t)
	writeFileIn(t, rootB, "roles/se.yaml", "name: software-engineer\nworkflows: [fix-bug]\nallowed_groups: [\"*\"]\ndescription: b\n")
	src := blockingSource{inner: dirSource(rootA), entered: make(chan struct{}), release: make(chan struct{})}
	w1 := make(chan applyOutcome, 1)
	go func() {
		w1 <- applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: src, Precondition: &applyPrecondition{ExpectNone: true}, AllowBootstrap: true}, io.Discard)
	}()
	<-src.entered
	w2 := make(chan applyOutcome, 1)
	go func() {
		w2 <- applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(rootB), Precondition: &applyPrecondition{ExpectNone: true}, AllowBootstrap: true}, io.Discard)
	}()
	select {
	case res := <-w2:
		t.Fatalf("W2 ran to completion (%+v) while W1 held the lock", res)
	case <-time.After(300 * time.Millisecond):
	}
	close(src.release)
	r1, r2 := <-w1, <-w2
	if r1.Kind != applyInstalled || r1.Installed {
		t.Fatalf("W1: %+v", r1)
	}
	if r2.Kind != applyPreconditionFailed || r2.CurrentHash != r1.ConfigHash || !r2.Installed {
		t.Fatalf("W2: %+v", r2)
	}
	if ev := controlEvents(t, ctl); len(ev) != 1 || !ev[0].Bootstrap {
		t.Fatalf("exactly one bootstrap recorded: %+v", ev)
	}
}

// TestApplyBundleSourceInstallsOnlyTheHashedBytes: step 9a. The staged
// copy hashes (through the hashConfigDir seam) to something other than the
// proposal's own HashFiles → recorded error/io_error "staged copy differs
// from the proposal", nothing installed, no residue. Without 9a the zero
// hash would be installed.
func TestApplyBundleSourceInstallsOnlyTheHashedBytes(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl, h0 := bootstrapped(t, root)
	bundle, err := config.ReadBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	bundle["agents/coder.yaml"] = []byte("name: coder\nmodel: fast\ninstruction: changed\noutput: patch\nendpoint: http://127.0.0.1:1\n")
	orig := hashConfigDir
	hashConfigDir = func(string) (string, error) { return zeroHash, nil }
	t.Cleanup(func() { hashConfigDir = orig })

	var out bytes.Buffer
	res := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: bundleSource(bundle), AllowBootstrap: true}, &out)
	if res.Kind != applyError || res.Reason == nil || res.Reason.Code != control.CodeIOError || res.Reason.Message != msgStagedDiffers {
		t.Fatalf("%+v\n%s", res, out.String())
	}
	if !strings.Contains(out.String(), msgStagedDiffers) || !strings.Contains(out.String(), "control head: seq=2") {
		t.Fatalf("out: %s", out.String())
	}
	if readPointer(t, ctl) != h0 {
		t.Fatal("pointer must not move")
	}
	if _, err := os.Stat(config.SnapshotDir(installedStore(ctl), zeroHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the mismatched copy must not be installed: %v", err)
	}
	noStagingResidue(t, ctl)
	hashConfigDir = orig
	ok := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: bundleSource(bundle), AllowBootstrap: true}, io.Discard)
	want, _ := config.HashFiles(bundle)
	if ok.Kind != applyInstalled || ok.ConfigHash != want || readPointer(t, ctl) != want {
		t.Fatalf("a bundle whose staged copy hashes as proposed installs under that hash: %+v want %s", ok, want)
	}
}

func TestApplyConfigBootstrapDisabledIsRecordedRefusal(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	res := applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(root), AllowBootstrap: false}, &out)
	if res.Kind != applyRefused || res.Reason == nil || res.Reason.Code != control.CodeNotAuthorized || res.Reason.Message != msgBootstrapDisabled {
		t.Fatalf("%+v", res)
	}
	want, _ := config.HashDir(root)
	if res.ConfigHash != want {
		t.Fatalf("the refusal carries the proposal's hash: %q want %q", res.ConfigHash, want)
	}
	if out.String() != "apply: "+msgBootstrapDisabled+"\ncontrol head: seq=1 sha256="+res.Head.Hash+"\n" {
		t.Fatalf("out %q", out.String())
	}
	if ev := controlEvents(t, ctl); len(ev) != 1 || ev[0].Outcome != "refused" || ev[0].ConfigHash != want {
		t.Fatalf("%+v", ev)
	}
	if _, installed, _ := config.InstalledHash(installedStore(ctl)); installed {
		t.Fatal("nothing may be installed")
	}
}

// holdLock starts a helper process (script_test.go's TestMain) that holds
// the named lock for ms milliseconds and returns once it reports "held".
// kind is "file" (ledger.LockFile on path) or "ledger" (ledger.Open Locked).
func holdLock(t *testing.T, kind, path string, ms int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestNothing")
	cmd.Env = append(os.Environ(), "AGENTHOF_TEST_HOLD_LOCK="+path, "AGENTHOF_TEST_HOLD_KIND="+kind, "AGENTHOF_TEST_HOLD_MS="+strconv.Itoa(ms))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var line [5]byte
	if _, err := io.ReadFull(stdout, line[:]); err != nil || string(line[:]) != "held\n" {
		t.Fatalf("helper never reported the lock held: %q err=%v", line[:], err)
	}
}

// TestApplyBusyWhenAnotherProcessHoldsALock waits the real ~5 s lockTimeout
// ONCE: the parent (sequential, so it may t.Setenv — cmdApply falls back to
// AGENTHOF_TOKEN, which a developer may have exported) blanks the env, and
// the two cases run as parallel subtests. A helper process holds the lock;
// apply prints the busy line, exits 1, records and installs nothing — and
// step-1 contention on a healthy ledger is busy, never the "control ledger
// damaged" repair hint.
func TestApplyBusyWhenAnotherProcessHoldsALock(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	for _, c := range []struct{ name, kind string }{{"writer lock", "file"}, {"ledger lock", "ledger"}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			root := writeSample(t)
			ctl := filepath.Join(t.TempDir(), "control.jsonl")
			path := installedLock(ctl)
			if c.kind == "ledger" {
				path = ctl
			}
			holdLock(t, c.kind, path, 9000)
			var out bytes.Buffer
			code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
			if code != 1 || out.String() != "apply: "+msgLockBusy+"\n" {
				t.Fatalf("code %d out %q", code, out.String())
			}
			if _, err := os.Stat(ctl); err == nil {
				if recs, _, _ := ledger.ReadVerify(ctl, ledger.Locked); len(recs) != 0 {
					t.Fatal("busy must record nothing")
				}
			}
			if _, installed, _ := config.InstalledHash(installedStore(ctl)); installed {
				t.Fatal("busy must install nothing")
			}
		})
	}
}

// TestApplyConfigStressSmoke: N goroutines alternating two proposals; every
// outcome is installed or busy, the pointer always names a snapshot the
// last Installing event carries, and no staging residue remains.
func TestApplyConfigStressSmoke(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	rootA, rootB := writeSample(t), writeSample(t)
	writeFileIn(t, rootB, "roles/se.yaml", "name: software-engineer\nworkflows: [fix-bug]\nallowed_groups: [\"*\"]\ndescription: b\n")
	ctl, _ := bootstrapped(t, rootA)
	var wg sync.WaitGroup
	results := make(chan applyOutcome, 12)
	for i := 0; i < 12; i++ {
		src := rootA
		if i%2 == 1 {
			src = rootB
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- applyConfig(applyRequest{ControlLog: ctl, Invoker: admin, Source: dirSource(src), AllowBootstrap: true}, io.Discard)
		}()
	}
	wg.Wait()
	close(results)
	for res := range results {
		if res.Kind != applyInstalled && res.Kind != applyBusy {
			t.Fatalf("unexpected outcome %+v", res)
		}
	}
	if line, mismatch := installedPointerLine(ctl, mustRecords(t, ctl)); mismatch {
		t.Fatalf("pointer and ledger disagree: %s", line)
	}
	noStagingResidue(t, ctl)
}

func TestNothing(t *testing.T) {}
