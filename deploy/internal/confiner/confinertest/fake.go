// Package confinertest holds an in-process fake confiner.Confiner for driving
// runtime orchestration in tests without podman or a sandbox. The fake does NOT
// confine anything: it runs the command directly on the host.
package confinertest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"syscall"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

// exitDidNotLaunch is the exit status the fake reads as the backend failing to
// run the command (podman's own "container never ran" status).
const exitDidNotLaunch = 125

// Fake is an in-process Confiner: Launch runs spec.Argv directly on the host
// (Program, Store, Paths, Limits and Timeout are ignored), stores are
// directories under Root, and every call is appended to Ops as "<op> <name>":
// "probe", "launch NAME", "wait NAME", "remove NAME", "create-store NAME",
// "remove-store NAME force=BOOL", "reap PREFIX", "store-path NAME". Safe for
// concurrent use.
//
// Set the exported fields before first use; Ops is read through OpsSnapshot.
type Fake struct {
	TierName  confiner.Tier // default "fake"
	OptTokens []string
	Root      string // store directory root (t.TempDir())
	ProbeErr  error  // returned by Probe
	LaunchErr error  // returned by Launch before anything starts
	ReapErr   error
	InUse     map[string]bool // RemoveStore(name, false) is ErrStoreInUse while InUse[name]

	mu  sync.Mutex
	Ops []string
}

var _ confiner.Confiner = (*Fake)(nil)

// New returns a Fake whose stores live under root.
func New(root string) *Fake { return &Fake{TierName: "fake", Root: root} }

// OpsSnapshot returns a copy of the recorded calls.
func (f *Fake) OpsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.Ops)
}

func (f *Fake) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Ops = append(f.Ops, fmt.Sprintf(format, args...))
}

// Tier returns TierName, or "fake" when unset.
func (f *Fake) Tier() confiner.Tier {
	if f.TierName == "" {
		return "fake"
	}
	return f.TierName
}

// Opts returns the OptTokens, sorted; nil when none.
func (f *Fake) Opts() []string {
	if len(f.OptTokens) == 0 {
		return nil
	}
	opts := slices.Clone(f.OptTokens)
	sort.Strings(opts)
	return opts
}

// Probe records the call and returns ProbeErr.
func (f *Fake) Probe(context.Context) error {
	f.record("probe")
	return f.ProbeErr
}

// ValidateProgram accepts anything: the fake ignores Program.
func (f *Fake) ValidateProgram(string) error { return nil }

// CreateStore makes Root/name with mode 0700.
func (f *Fake) CreateStore(_ context.Context, name string) error {
	f.record("create-store %s", name)
	if !confiner.ValidStoreName(name) {
		return fmt.Errorf("confinertest: %q is not a legal store name", name)
	}
	return os.Mkdir(filepath.Join(f.Root, name), 0o700)
}

// RemoveStore deletes Root/name, or returns ErrStoreInUse without force while
// InUse[name] is set.
func (f *Fake) RemoveStore(_ context.Context, name string, force bool) error {
	f.record("remove-store %s force=%t", name, force)
	if !confiner.ValidStoreName(name) {
		return fmt.Errorf("confinertest: %q is not a legal store name", name)
	}
	f.mu.Lock()
	busy := f.InUse[name]
	f.mu.Unlock()
	if busy && !force {
		return confiner.ErrStoreInUse
	}
	return os.RemoveAll(filepath.Join(f.Root, name))
}

// StorePath is Root/name.
func (f *Fake) StorePath(name string) string {
	f.record("store-path %s", name)
	return filepath.Join(f.Root, name)
}

// Reap records the call and returns ReapErr.
func (f *Fake) Reap(_ context.Context, prefix string) error {
	f.record("reap %s", prefix)
	return f.ReapErr
}

// Launch starts spec.Argv on the host in its own process group. The child sees
// only the spec.EnvNames that are set on the host, plus TMPDIR (a run-private
// directory removed after exit) when spec.Scratch is set; Wait reports exactly
// those names.
func (f *Fake) Launch(_ context.Context, spec confiner.Spec) (confiner.Compartment, error) {
	f.record("launch %s", spec.Name)
	if f.LaunchErr != nil {
		return nil, f.LaunchErr
	}
	if len(spec.Argv) == 0 {
		return nil, errors.New("confinertest: empty Argv")
	}

	var env, names []string
	for _, n := range spec.EnvNames {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
			names = append(names, n)
		}
	}
	var scratch string
	if spec.Scratch {
		dir, err := os.MkdirTemp(f.Root, ".scratch-")
		if err != nil {
			return nil, err
		}
		scratch = dir
		env = append(env, "TMPDIR="+dir)
		names = append(names, "TMPDIR")
	}
	sort.Strings(names)

	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var capture *confiner.CapWriter
	sink := spec.Output
	if sink == nil {
		capture = confiner.NewCapWriter(confiner.MaxOutput)
		sink = capture
	}
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Start(); err != nil {
		if scratch != "" {
			_ = os.RemoveAll(scratch)
		}
		return nil, err
	}

	c := &fakeCompartment{f: f, name: spec.Name, pid: cmd.Process.Pid, done: make(chan struct{})}
	go func() {
		waitErr := cmd.Wait()
		if scratch != "" {
			_ = os.RemoveAll(scratch)
		}
		var exitErr *exec.ExitError
		switch {
		case waitErr != nil && !errors.As(waitErr, &exitErr):
			c.err = waitErr
		case cmd.ProcessState.ExitCode() == exitDidNotLaunch:
			c.err = confiner.ErrDidNotLaunch
		default:
			c.res = confiner.Result{Exit: cmd.ProcessState.ExitCode(), EnvNames: names}
			if capture != nil {
				c.res.Output, c.res.Truncated = capture.Output()
				c.res.OutputBytes = capture.Total()
			}
		}
		close(c.done)
	}()
	return c, nil
}

type fakeCompartment struct {
	f    *Fake
	name string
	pid  int
	done chan struct{}
	// res and err are written once, before done is closed.
	res confiner.Result
	err error
}

func (c *fakeCompartment) Wait(ctx context.Context) (confiner.Result, error) {
	c.f.record("wait %s", c.name)
	select {
	case <-c.done:
		return c.res, c.err
	case <-ctx.Done():
		return confiner.Result{}, ctx.Err()
	}
}

func (c *fakeCompartment) Done() <-chan struct{} { return c.done }

func (c *fakeCompartment) PID() int { return c.pid }

// Remove kills the whole process group, which unblocks a pending Wait, and
// returns once the process has been reaped or ctx is done.
func (c *fakeCompartment) Remove(ctx context.Context) error {
	c.f.record("remove %s", c.name)
	select {
	case <-c.done:
		return nil
	default:
	}
	if err := syscall.Kill(-c.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
