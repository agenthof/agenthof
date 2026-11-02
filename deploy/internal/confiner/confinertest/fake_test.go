package confinertest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

var (
	_ confiner.Confiner    = (*Fake)(nil)
	_ confiner.Compartment = (*fakeCompartment)(nil)
)

func TestFakeLaunchWaitRecordsAndCaptures(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	c, err := f.Launch(ctx, confiner.Spec{Name: "n1", Argv: []string{"sh", "-c", "printf hi; exit 3"}, Scratch: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Exit != 3 || string(res.Output) != "hi" || res.OutputBytes != 2 || !slices.Equal(res.EnvNames, []string{"TMPDIR"}) {
		t.Fatal(res)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done must be closed after exit")
	}
	if !slices.Equal(f.OpsSnapshot(), []string{"launch n1", "wait n1"}) {
		t.Fatal(f.OpsSnapshot())
	}
}

func TestFakeEnvNamesAreTheSortedIntersectionPlusTmpdir(t *testing.T) {
	ctx := context.Background()
	t.Setenv("FAKE_ZED", "z")
	t.Setenv("FAKE_ALPHA", "a")
	f := New(t.TempDir())
	c, err := f.Launch(ctx, confiner.Spec{
		Name:     "env",
		Argv:     []string{"sh", "-c", `printf '%s|%s|%s' "$FAKE_ALPHA" "$FAKE_ZED" "$FAKE_NOT_ASKED"`},
		Scratch:  true,
		EnvNames: []string{"FAKE_ZED", "FAKE_ALPHA", "FAKE_ABSENT_FROM_HOST"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"FAKE_ALPHA", "FAKE_ZED", "TMPDIR"}; !slices.Equal(res.EnvNames, want) {
		t.Fatalf("EnvNames = %v, want %v", res.EnvNames, want)
	}
	if string(res.Output) != "a|z|" {
		t.Fatalf("output = %q", res.Output)
	}
}

func TestFakeScratchIsExportedAsTmpdirAndRemovedAfterExit(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	c, err := f.Launch(ctx, confiner.Spec{Name: "scr", Argv: []string{"sh", "-c", `printf %s "$TMPDIR"; touch "$TMPDIR/x"`}, Scratch: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(ctx)
	if err != nil || res.Exit != 0 {
		t.Fatal(res, err)
	}
	if len(res.Output) == 0 {
		t.Fatal("TMPDIR was not exported")
	}
	if _, err := os.Stat(string(res.Output)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch dir must be gone after exit, stat err = %v", err)
	}
}

func TestFakeCallerOutputSinkReceivesOutput(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	var sink bytes.Buffer
	c, err := f.Launch(ctx, confiner.Spec{Name: "sink", Argv: []string{"sh", "-c", "printf out; printf err >&2"}, Output: &sink})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != nil || res.OutputBytes != 0 {
		t.Fatalf("a caller sink means no capture, got %+v", res)
	}
	if got := sink.String(); got != "outerr" && got != "errout" {
		t.Fatalf("sink = %q", got)
	}
}

func TestFakeDidNotLaunchOn125(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	c, err := f.Launch(ctx, confiner.Spec{Name: "d", Argv: []string{"sh", "-c", "exit 125"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wait(ctx); !errors.Is(err, confiner.ErrDidNotLaunch) {
		t.Fatalf("err = %v, want ErrDidNotLaunch", err)
	}
}

func TestFakeLaunchErrIsReturnedBeforeAnythingStarts(t *testing.T) {
	boom := errors.New("boom")
	f := New(t.TempDir())
	f.LaunchErr = boom
	if _, err := f.Launch(context.Background(), confiner.Spec{Name: "x", Argv: []string{"true"}}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeWaitHonoursContext(t *testing.T) {
	f := New(t.TempDir())
	c, err := f.Launch(context.Background(), confiner.Spec{Name: "slow", Argv: []string{"sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Remove(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	select {
	case <-c.Done():
		t.Fatal("a Wait that gave up must not stop the process")
	default:
	}
}

func TestFakeRemoveUnblocksWait(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	c, err := f.Launch(ctx, confiner.Spec{Name: "r", Argv: []string{"sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.PID() <= 0 {
		t.Fatalf("PID = %d", c.PID())
	}
	type out struct {
		res confiner.Result
		err error
	}
	waited := make(chan out, 1)
	go func() {
		res, err := c.Wait(ctx)
		waited <- out{res, err}
	}()
	time.Sleep(50 * time.Millisecond)
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-waited:
		if o.err != nil || o.res.Exit == 0 {
			t.Fatalf("want a non-zero exit and no error, got %+v, %v", o.res, o.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Remove did not unblock Wait")
	}
	if !slices.Contains(f.OpsSnapshot(), "remove r") {
		t.Fatal(f.OpsSnapshot())
	}
}

func TestFakeRemoveKillsTheProcessGroup(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	// The shell backgrounds a grandchild that holds the output pipe open; only a
	// group kill lets Wait return promptly.
	c, err := f.Launch(ctx, confiner.Spec{Name: "grp", Argv: []string{"sh", "-c", "sleep 30 & wait"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the process group survived Remove")
	}
}

func TestFakeStoreLifecycleAndInUse(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	f := New(root)
	if err := f.CreateStore(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(root, "s1"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("store dir: %v %v", fi, err)
	}
	if got := f.StorePath("s1"); got != filepath.Join(root, "s1") {
		t.Fatalf("StorePath = %q", got)
	}
	f.InUse = map[string]bool{"s1": true}
	if err := f.RemoveStore(ctx, "s1", false); !errors.Is(err, confiner.ErrStoreInUse) {
		t.Fatalf("err = %v, want ErrStoreInUse", err)
	}
	if _, err := os.Stat(filepath.Join(root, "s1")); err != nil {
		t.Fatalf("a refused removal must leave the store: %v", err)
	}
	if err := f.RemoveStore(ctx, "s1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "s1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forced removal must delete the store, stat err = %v", err)
	}
	want := []string{"create-store s1", "store-path s1", "remove-store s1 force=false", "remove-store s1 force=true"}
	if !slices.Equal(f.OpsSnapshot(), want) {
		t.Fatalf("ops = %v, want %v", f.OpsSnapshot(), want)
	}
}

func TestFakeRejectsAnIllegalStoreName(t *testing.T) {
	f := New(t.TempDir())
	if err := f.CreateStore(context.Background(), "../escape"); err == nil {
		t.Fatal("a name that is not a legal store name must be refused")
	}
}

func TestFakeProbeAndReapErrors(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	if f.Tier() != "fake" {
		t.Fatalf("default tier = %q", f.Tier())
	}
	f.OptTokens = []string{"b-opt", "a-opt"}
	if got := f.Opts(); !slices.Equal(got, []string{"a-opt", "b-opt"}) {
		t.Fatalf("Opts = %v, want sorted", got)
	}
	if got := New(t.TempDir()).Opts(); got != nil {
		t.Fatalf("Opts = %v, want nil", got)
	}
	probeErr, reapErr := errors.New("probe-fail"), errors.New("reap-fail")
	f.ProbeErr, f.ReapErr = probeErr, reapErr
	if err := f.Probe(ctx); err != probeErr {
		t.Fatalf("Probe = %v", err)
	}
	if err := f.Reap(ctx, "refexec-"); err != reapErr {
		t.Fatalf("Reap = %v", err)
	}
	if want := []string{"probe", "reap refexec-"}; !slices.Equal(f.OpsSnapshot(), want) {
		t.Fatalf("ops = %v, want %v", f.OpsSnapshot(), want)
	}
}

func TestFakeChildGetsAnEmptyEnvironmentWhenNoNameApplies(t *testing.T) {
	ctx := context.Background()
	t.Setenv("FAKE_HOST_ONLY", "leak")
	f := New(t.TempDir())
	c, err := f.Launch(ctx, confiner.Spec{Name: "noenv", Argv: []string{"sh", "-c", `echo ${FAKE_HOST_ONLY:-absent}`}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Output) != "absent\n" {
		t.Fatalf("a host variable not named in EnvNames leaked into the child: %q", res.Output)
	}
	if len(res.EnvNames) != 0 {
		t.Fatalf("EnvNames = %v, want empty", res.EnvNames)
	}
}

func TestFakeTmpdirInEnvNamesWithScratchIsAttestedOnceAndIsTheScratchDir(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir()) // before the Setenv: t.TempDir itself reads TMPDIR
	t.Setenv("TMPDIR", "/host/tmp")
	c, err := f.Launch(ctx, confiner.Spec{
		Name:     "tmpdir",
		Argv:     []string{"sh", "-c", `printf %s "$TMPDIR"`},
		Scratch:  true,
		EnvNames: []string{"TMPDIR"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.EnvNames, []string{"TMPDIR"}) {
		t.Fatalf("EnvNames = %v, want TMPDIR exactly once", res.EnvNames)
	}
	if got := string(res.Output); got == "" || got == "/host/tmp" {
		t.Fatalf("TMPDIR = %q, want the scratch dir, not the host value", got)
	}
}

func TestFakeOpsSnapshotIsACopy(t *testing.T) {
	f := New(t.TempDir())
	_ = f.Probe(context.Background())
	s := f.OpsSnapshot()
	s[0] = "tampered"
	if got := f.OpsSnapshot(); got[0] != "probe" {
		t.Fatalf("ops mutated through the snapshot: %v", got)
	}
}
