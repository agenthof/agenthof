package confiner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// podmanProbeFormat asks the engine the three facts the backend requires: the
// host OS, whether it runs rootless, and whether the client talks to a remote
// service (podman-machine).
const podmanProbeFormat = "{{.Host.OS}} {{.Host.Security.Rootless}} {{.Host.ServiceIsRemote}}"

// imageRE is the shape of a Program the podman backend accepts: an OCI image
// ref, or an absolute path (the hermetic stub's leading "/"). It starts with
// an alphanumeric or "/", so a Program can never be read as a podman flag.
var imageRE = regexp.MustCompile(`^[A-Za-z0-9/][A-Za-z0-9._/:@-]*$`)

// PodmanConfig configures the rootless podman backend.
type PodmanConfig struct {
	// Argv is the podman client's argv prefix; nil means {"podman"}. Tests pass
	// a fake.
	Argv []string
	// GuestWorkspace is where every store is visible inside a container, and
	// the container's working directory; "" means "/work".
	GuestWorkspace string
	// Environ returns the podman CLIENT's environment (its storage, PATH, and
	// the values `-e NAME` copies); nil means os.Environ. The command's own
	// environment is only what `-e` names.
	Environ func() []string
	// Logger receives operational events; nil discards.
	Logger *slog.Logger
}

// Podman is the rootless-podman Confiner: a shared-kernel container per
// compartment, no network, a read-only root, every capability dropped, no new
// privileges, and the host user's id (--userns=keep-id).
type Podman struct {
	cfg PodmanConfig
}

var _ Confiner = (*Podman)(nil)

// NewPodman returns a Podman backend. It runs nothing: Probe checks the engine.
func NewPodman(c PodmanConfig) *Podman {
	if len(c.Argv) == 0 {
		c.Argv = []string{"podman"}
	} else {
		c.Argv = slices.Clone(c.Argv)
	}
	if c.GuestWorkspace == "" {
		c.GuestWorkspace = "/work"
	}
	if c.Environ == nil {
		c.Environ = os.Environ
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return &Podman{cfg: c}
}

// Tier is TierPodman.
func (p *Podman) Tier() Tier { return TierPodman }

// Opts is nil: the podman backend has no confiner_opts.
func (p *Podman) Opts() []string { return nil }

// StorePath is where every store is visible inside a container.
func (p *Podman) StorePath(string) string { return p.cfg.GuestWorkspace }

// ValidateProgram requires an OCI image ref (or absolute path); "" is
// ErrEmptyProgram.
func (p *Podman) ValidateProgram(program string) error {
	if program == "" {
		return ErrEmptyProgram
	}
	if !imageRE.MatchString(program) {
		return fmt.Errorf("confiner: %q is not an image reference", program)
	}
	return nil
}

// argv is the client program and its full argument list for args.
func (p *Podman) argv(args []string) (string, []string) {
	return p.cfg.Argv[0], append(slices.Clone(p.cfg.Argv[1:]), args...)
}

// output runs one podman command to completion under a bound and returns its
// stdout. A failure carries podman's stderr, which may name a container or a
// volume but never carries a value.
func (p *Podman) output(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	name, full := p.argv(args)
	cmd := exec.CommandContext(ctx, name, full...)
	cmd.Env = p.cfg.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("podman %s: %w: %s", strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Probe requires a LOCAL, rootless, Linux engine. A client pointed at a
// remote engine (podman-machine) is refused on every OS: the host paths a
// compartment is given would not be the engine's.
func (p *Podman) Probe(ctx context.Context) error {
	out, err := p.output(ctx, 30*time.Second, "info", "--format", podmanProbeFormat)
	if err != nil {
		return fmt.Errorf("confiner: podman info probe failed: %w", err)
	}
	got := strings.TrimSpace(string(out))
	fields := strings.Fields(got)
	if len(fields) == 3 && fields[2] == "true" {
		return fmt.Errorf("%w (podman info reports %q)", ErrNotLocalEngine, got)
	}
	if got != "linux true false" {
		return fmt.Errorf("confiner: podman info probe: want %q (linux, rootless, local engine), got %q", "linux true false", got)
	}
	return nil
}

// runArgs builds the one `podman run` for a compartment: no network, a
// read-only root, an optional tmpfs scratch, every capability dropped, no new
// privileges, the host user's id, the resource caps, the wall clock as a
// backstop to the caller's own deadline, the workspace store — and nothing
// else writable — mounted at the guest workspace path (also the working
// directory), the allow-listed host paths at their own path, the requested
// environment names, then the image and the argv. --pull=never: the operator
// fetches the image; a compartment is offline by construction. applied is the
// environment-variable NAME list the run carries, sorted; never nil.
func (p *Podman) runArgs(spec Spec) (args []string, applied []string) {
	secs := int(spec.Timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	guest := p.cfg.GuestWorkspace
	args = []string{"run", "--rm", "--name", spec.Name, "--pull=never", "--network", "none", "--read-only"}
	if spec.Scratch {
		args = append(args, "--tmpfs", "/tmp")
	}
	args = append(args,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges",
		"--userns=keep-id", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--memory="+spec.Limits.Memory, "--cpus="+spec.Limits.CPUs, "--pids-limit="+strconv.Itoa(spec.Limits.PIDs),
		"--timeout="+strconv.Itoa(secs),
		"-v", spec.Store+":"+guest, "-w", guest,
	)
	for _, path := range spec.Paths {
		mount := path.Path + ":" + path.Path
		if !path.RW {
			mount += ":ro"
		}
		args = append(args, "-v", mount)
	}

	// `-e NAME` makes podman copy the value from the client's environment, so
	// a value never appears in an argv or a log.
	have := map[string]bool{}
	for _, kv := range p.cfg.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		have[name] = true
	}
	applied = []string{}
	for _, name := range spec.EnvNames {
		if spec.Scratch && name == "TMPDIR" {
			continue // the scratch dir supplies TMPDIR below, exactly once
		}
		if have[name] && !slices.Contains(applied, name) {
			applied = append(applied, name)
		}
	}
	sort.Strings(applied)
	for _, name := range applied {
		args = append(args, "-e", name)
	}
	if spec.Scratch {
		args = append(args, "-e", "TMPDIR=/tmp")
		applied = append(applied, "TMPDIR")
		sort.Strings(applied)
	}
	args = append(args, spec.Program)
	return append(args, spec.Argv...), applied
}

// Launch starts one container. The client is started with exec.Command, not
// CommandContext: killing the client would leave the container running under
// conmon, so a runtime ends a compartment with Remove (`podman rm -f`), which
// the client then exits on its own; WaitDelay bounds how long its pipes are
// waited for.
func (p *Podman) Launch(_ context.Context, spec Spec) (Compartment, error) {
	if err := p.ValidateProgram(spec.Program); err != nil {
		return nil, err
	}
	args, applied := p.runArgs(spec)
	name, full := p.argv(args)
	cmd := exec.Command(name, full...)
	cmd.Env = p.cfg.Environ()
	cmd.WaitDelay = 10 * time.Second
	var capture *CapWriter
	sink := spec.Output
	if sink == nil {
		capture = NewCapWriter(MaxOutput)
		sink = capture
	}
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("confiner: start podman: %w", err)
	}
	c := &podmanCompartment{p: p, name: spec.Name, cmd: cmd, done: make(chan struct{})}
	go func() {
		waitErr := cmd.Wait()
		var ee *exec.ExitError
		switch {
		case waitErr != nil && !errors.As(waitErr, &ee):
			c.err = fmt.Errorf("confiner: podman: %w", waitErr)
		case cmd.ProcessState.ExitCode() == 125:
			// 125 is podman's own reserved code for "podman itself failed" (the
			// image is absent under --pull=never, a storage error, a bad flag):
			// the command never ran, so a runtime must not attest it. A command
			// that itself exits 125 is indistinguishable and treated the same.
			c.res = Result{Exit: 125}
			c.err = ErrDidNotLaunch
		default:
			c.res = Result{Exit: cmd.ProcessState.ExitCode(), EnvNames: applied}
			if capture != nil {
				c.res.Output, c.res.Truncated = capture.Output()
				c.res.OutputBytes = capture.Total()
			}
		}
		close(c.done)
	}()
	return c, nil
}

type podmanCompartment struct {
	p    *Podman
	name string
	cmd  *exec.Cmd
	done chan struct{}
	// res and err are written once, before done is closed.
	res Result
	err error
}

func (c *podmanCompartment) Wait(ctx context.Context) (Result, error) {
	select {
	case <-c.done:
		return c.res, c.err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

func (c *podmanCompartment) Done() <-chan struct{} { return c.done }

// PID is the podman CLIENT's pid, which the runtime holds first-hand; the
// container's own process is conmon's child, not ours.
func (c *podmanCompartment) PID() int { return c.cmd.Process.Pid }

// Remove runs `podman rm -f` under its own bounded context, so a cancelled
// caller still removes the container. The client then exits on its own; if it
// has not within 10s it is killed. Remove returns once the client has exited.
// A container that already exited under --rm is gone and podman's complaint
// about it is returned for the caller to treat as noise.
func (c *podmanCompartment) Remove(context.Context) error {
	_, rmErr := c.p.output(context.Background(), 30*time.Second, "rm", "-f", c.name)
	if rmErr != nil {
		c.p.cfg.Logger.Warn("compartment not removed", "compartment", c.name, "error", rmErr)
	}
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case <-c.done:
	case <-t.C:
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	return rmErr
}

// CreateStore creates a named volume.
func (p *Podman) CreateStore(ctx context.Context, name string) error {
	if !ValidStoreName(name) {
		return fmt.Errorf("confiner: %q is not a legal store name", name)
	}
	_, err := p.output(ctx, 30*time.Second, "volume", "create", name)
	return err
}

// RemoveStore removes a volume. Without force, any failure is ErrStoreInUse
// wrapping podman's text: podman does not distinguish "in use" from other
// failures by exit code, so the caller retries.
func (p *Podman) RemoveStore(ctx context.Context, name string, force bool) error {
	if !ValidStoreName(name) {
		return fmt.Errorf("confiner: %q is not a legal store name", name)
	}
	args := []string{"volume", "rm"}
	if force {
		args = append(args, "-f")
	}
	if _, err := p.output(ctx, 30*time.Second, append(args, name)...); err != nil {
		if force {
			return err
		}
		return fmt.Errorf("%w: %w", ErrStoreInUse, err)
	}
	return nil
}

// Reap removes every container and volume whose name starts with prefix: the
// leftovers of a previous run that died with compartments in flight. A failed
// listing is returned (the caller decides whether to refuse or warn); a
// leftover that cannot be removed is logged and does not stop the sweep.
func (p *Podman) Reap(ctx context.Context, prefix string) error {
	if prefix == "" {
		return errors.New("confiner: reap needs a name prefix (an empty one would match everything)")
	}
	filter := "name=^" + prefix
	var errs []error
	if out, err := p.output(ctx, 30*time.Second, "ps", "-aq", "--filter", filter); err != nil {
		errs = append(errs, err)
	} else {
		for _, name := range strings.Fields(string(out)) {
			p.cfg.Logger.Info("reaping leftover compartment", "compartment", name)
			if _, err := p.output(ctx, 30*time.Second, "rm", "-f", name); err != nil {
				p.cfg.Logger.Warn("leftover compartment not removed", "compartment", name, "error", err)
			}
		}
	}
	if out, err := p.output(ctx, 30*time.Second, "volume", "ls", "-q", "--filter", filter); err != nil {
		errs = append(errs, err)
	} else {
		for _, name := range strings.Fields(string(out)) {
			p.cfg.Logger.Info("reaping leftover volume", "volume", name)
			// -f, unlike an ordered teardown: a leftover may still be mounted by
			// a container nothing here names, and nothing is left running to
			// release it.
			if _, err := p.output(ctx, 30*time.Second, "volume", "rm", "-f", name); err != nil {
				p.cfg.Logger.Warn("leftover volume not removed", "volume", name, "error", err)
			}
		}
	}
	return errors.Join(errs...)
}
