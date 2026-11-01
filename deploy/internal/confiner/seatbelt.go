package confiner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultSandboxExec = "/usr/bin/sandbox-exec"

// sandbox-exec's own exit codes (sysexits.h): EX_DATAERR when it rejects the
// profile, EX_OSERR when execvp of the program fails. Neither means the
// program ran.
const (
	exitProfileRejected = 65
	exitExecFailed      = 71
)

// procRef names a live process by pid AND the start time it was seen with, so
// a signal to it can be withheld once the pid belongs to something else.
type procRef struct {
	pid   int
	start int64
}

// SeatbeltConfig configures the macOS Seatbelt backend.
type SeatbeltConfig struct {
	// SandboxExec is the sandbox-exec binary; "" means /usr/bin/sandbox-exec.
	SandboxExec string
	// StoreRoot holds every workspace store as <StoreRoot>/<name>, and the
	// backend's own <StoreRoot>/.scratch/<compartment>. Required, absolute;
	// NewSeatbelt resolves it through its symlinks.
	StoreRoot string
	// PIDDir holds one <name>.pid record per live compartment. Required,
	// absolute; resolved like StoreRoot.
	PIDDir string
	// DenyRead are the operator's extra read-denied subtrees, absolute.
	DenyRead []string
	// SpawnRoot is refspawn's own root, read-denied like StoreRoot; "" when
	// the runtime has none.
	SpawnRoot string
	// Home is the home directory whose credential stores are read-denied;
	// "" means the backend process's own (HOME, else its user record).
	Home string
	// SharedHostScratch lets every compartment read and write the shared host
	// /private/tmp; reported by Opts.
	SharedHostScratch bool
	// Environ returns the backend's environment, the source of the values
	// Spec.EnvNames copies; nil means os.Environ.
	Environ func() []string
	// Logger receives operational events; nil discards.
	Logger *slog.Logger
}

// Seatbelt is the macOS Confiner: each compartment is one process started by
// sandbox-exec under a generated SBPL profile (direct network denied, writes
// scoped to the store, the RW paths and the scratch dir, reads host-wide
// minus the deny list), in its own session, with a PID record that a later
// process can match against the live process's start time.
type Seatbelt struct {
	cfg SeatbeltConfig
	// owner is this process's stamp, written into every PID record this
	// backend creates so a later Reap can tell the compartments of a running
	// instance from the leftovers of one that is gone.
	owner ownerRef
	// denyRead are the read-denied subtrees in profile order, each resolved
	// and sbplSafe.
	denyRead []string
	// traverse are the denied roots a compartment resolves paths through (the
	// store root, the spawn root when set), re-opened for metadata only.
	traverse []string
	// compiled holds the SHA-256 of every profile text this backend's
	// sandbox-exec has accepted in a dry-run.
	compiled sync.Map
}

var _ Confiner = (*Seatbelt)(nil)

// NewSeatbelt validates and resolves the configuration and logs, once, that
// resource limits are not enforced on this tier. It runs nothing: Probe
// checks sandbox-exec.
func NewSeatbelt(c SeatbeltConfig) (*Seatbelt, error) {
	if c.SandboxExec == "" {
		c.SandboxExec = defaultSandboxExec
	}
	if c.Environ == nil {
		c.Environ = os.Environ
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	home := c.Home
	if home == "" {
		h, err := processHome()
		if err != nil {
			return nil, fmt.Errorf("confiner: seatbelt: home directory: %w", err)
		}
		home = h
	}
	var err error
	if home, err = resolveProfilePath("home", home); err != nil {
		return nil, err
	}
	if c.StoreRoot, err = resolveProfilePath("store_root", c.StoreRoot); err != nil {
		return nil, err
	}
	if c.PIDDir, err = resolveProfilePath("pid_dir", c.PIDDir); err != nil {
		return nil, err
	}
	// The profile's deny order: the fixed home set, the store root, the PID
	// dir, the spawn root, then the operator's list.
	var deny []string
	for _, p := range fixedHomeDenies(home) {
		r, err := resolveProfilePath("home deny", p)
		if err != nil {
			return nil, err
		}
		deny = append(deny, r)
	}
	deny = append(deny, c.StoreRoot, c.PIDDir)
	// The roots the compartment must resolve a path through: its store sits
	// under the store root and refspawn's socket dir under the spawn root.
	// The PID dir is never traversed.
	traverse := []string{c.StoreRoot}
	if c.SpawnRoot != "" {
		if c.SpawnRoot, err = resolveProfilePath("spawn_root", c.SpawnRoot); err != nil {
			return nil, err
		}
		deny = append(deny, c.SpawnRoot)
		traverse = append(traverse, c.SpawnRoot)
	}
	resolvedDeny := make([]string, 0, len(c.DenyRead))
	for _, p := range c.DenyRead {
		r, err := resolveProfilePath("deny_read", p)
		if err != nil {
			return nil, err
		}
		resolvedDeny = append(resolvedDeny, r)
	}
	c.DenyRead = resolvedDeny
	deny = append(deny, resolvedDeny...)
	owner, err := selfOwner()
	if err != nil {
		return nil, fmt.Errorf("confiner: seatbelt: %w", err)
	}

	c.Logger.Warn("limits not enforced on this tier", "tier", TierSeatbelt)
	return &Seatbelt{cfg: c, owner: owner, denyRead: deny, traverse: traverse}, nil
}

// processHome is the backend process's own home: HOME, else its user record.
func processHome() (string, error) {
	if h, err := os.UserHomeDir(); err == nil {
		return h, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" {
		return "", errors.New("the user record has no home directory")
	}
	return u.HomeDir, nil
}

// resolveProfilePath prepares one path for the sandbox profile: it must be
// absolute, it is resolved through its symlinks (the kernel matches a rule
// against the real path, so a rule naming /tmp/x never matches
// /private/tmp/x), and the result must be safe to place in SBPL text. A path
// that does not exist keeps its name under its longest existing, resolved
// ancestor, so a deny on a path that appears later still names the real
// location. key names the setting in the error.
func resolveProfilePath(key, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("confiner: seatbelt %s must be an absolute path, got %q", key, p)
	}
	resolved, err := resolveExisting(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("confiner: seatbelt %s: %w", key, err)
	}
	if err := sbplSafe(resolved); err != nil {
		return "", fmt.Errorf("confiner: seatbelt %s: %w", key, err)
	}
	return resolved, nil
}

// resolveExisting is EvalSymlinks that tolerates a missing tail: the longest
// existing ancestor is resolved and the rest of the path is re-appended.
func resolveExisting(p string) (string, error) {
	r, err := filepath.EvalSymlinks(p)
	if err == nil {
		return r, nil
	}
	parent := filepath.Dir(p)
	if !errors.Is(err, fs.ErrNotExist) || parent == p {
		return "", err
	}
	rp, err := resolveExisting(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(rp, filepath.Base(p)), nil
}

// Tier is TierSeatbelt.
func (s *Seatbelt) Tier() Tier { return TierSeatbelt }

// Opts reports the shared-host-scratch loosening when it is on.
func (s *Seatbelt) Opts() []string {
	if s.cfg.SharedHostScratch {
		return []string{OptSharedHostScratch}
	}
	return nil
}

// StorePath is the store's host directory, which the compartment sees at the
// same path and has as its working directory.
func (s *Seatbelt) StorePath(name string) string { return filepath.Join(s.cfg.StoreRoot, name) }

// scratchDir is a compartment's private scratch dir, exported as TMPDIR.
func (s *Seatbelt) scratchDir(name string) string {
	return filepath.Join(s.cfg.StoreRoot, ".scratch", name)
}

// pidFile is a compartment's PID record.
func (s *Seatbelt) pidFile(name string) string { return filepath.Join(s.cfg.PIDDir, name+".pid") }

// ValidateProgram accepts "" (the program is Argv[0]) or an absolute path.
func (s *Seatbelt) ValidateProgram(program string) error {
	if program == "" {
		return nil
	}
	if !filepath.IsAbs(program) {
		return fmt.Errorf("confiner: program %q is not an absolute path", program)
	}
	return nil
}

// profile renders one compartment's profile over the backend's deny list.
func (s *Seatbelt) profile(scratch string, paths []Path) string {
	return sbplProfile(profileInput{Scratch: scratch, SharedHostScratch: s.cfg.SharedHostScratch, Paths: paths, DenyRead: s.denyRead, Traverse: s.traverse})
}

// sandboxArgs is sandbox-exec's argument list for running program under
// profile with work bound to the WORK parameter. WORK is a Scheme parameter
// VALUE, not text spliced into the profile, so it needs no sbplSafe check; it
// must be the real path, because the kernel matches the real path.
func sandboxArgs(profile, work, program string, args ...string) []string {
	return append([]string{"-D", "WORK=" + work, "-p", profile, program}, args...)
}

// compile dry-runs a profile once per distinct text: sandbox-exec compiles it
// and execs /usr/bin/true. Exit 65 means the installed sandbox-exec rejects
// the generated profile, which is reported as such; a later compartment under
// the same text skips the dry-run.
func (s *Seatbelt) compile(ctx context.Context, profile, work string) error {
	sum := sha256.Sum256([]byte(profile))
	if _, ok := s.compiled.Load(sum); ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.SandboxExec, sandboxArgs(profile, work, "/usr/bin/true")...)
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		s.compiled.Store(sum, true)
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == exitProfileRejected {
		return fmt.Errorf("the installed sandbox-exec rejects the generated profile: %s", strings.TrimSpace(stderr.String()))
	}
	return fmt.Errorf("profile dry-run: %w: %s", err, strings.TrimSpace(stderr.String()))
}

// sandboxedOutput runs program under profile to completion with an empty
// environment and work as the working directory, returning its combined
// output and exit code. An error means it could not be run at all.
func (s *Seatbelt) sandboxedOutput(ctx context.Context, profile, work, program string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.SandboxExec, sandboxArgs(profile, work, program, args...)...)
	cmd.Env = []string{}
	cmd.Dir = work
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return out.Bytes(), -1, err
	}
	return out.Bytes(), cmd.ProcessState.ExitCode(), nil
}

// Probe requires sandbox-exec and proves, against an unsandboxed control,
// that the generated baseline profile is accepted and enforced here: a write
// outside the workspace is denied and leaves no file, a write and read inside
// the workspace (a directory under the read-denied store root, re-opened by
// the WORK allow) succeed. The control comes first: when the unsandboxed
// write itself cannot succeed, Probe fails on that and a later denial is
// never read as enforcement.
func (s *Seatbelt) Probe(ctx context.Context) error {
	fi, err := os.Stat(s.cfg.SandboxExec)
	if err != nil {
		return fmt.Errorf("confiner: seatbelt: sandbox-exec is not available: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("confiner: seatbelt: sandbox-exec at %s is not a regular file", s.cfg.SandboxExec)
	}
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	outside := filepath.Join(s.cfg.PIDDir, ".probe-"+suffix)
	work := filepath.Join(s.cfg.StoreRoot, ".probe-"+suffix)
	if err := os.Mkdir(outside, 0o700); err != nil {
		return fmt.Errorf("confiner: seatbelt probe control: %w", err)
	}
	defer func() { _ = os.RemoveAll(outside) }()
	if err := os.Mkdir(work, 0o700); err != nil {
		return fmt.Errorf("confiner: seatbelt probe control: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	target := filepath.Join(outside, "out")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		return fmt.Errorf("confiner: seatbelt probe control: the unsandboxed write failed, so no denial below would prove enforcement: %w", err)
	}
	if err := os.Remove(target); err != nil {
		return fmt.Errorf("confiner: seatbelt probe control: %w", err)
	}

	profile := s.profile("", nil)
	if err := s.compile(ctx, profile, work); err != nil {
		return fmt.Errorf("confiner: seatbelt probe: %w", err)
	}

	// The path is a positional argument, never spliced into shell text.
	out, code, err := s.sandboxedOutput(ctx, profile, work, "/bin/sh", "-c", `echo x > "$1"`, "sh", target)
	if err != nil {
		return fmt.Errorf("confiner: seatbelt probe: %w", err)
	}
	if err := denialVerdict(code, out, target); err != nil {
		return err
	}

	inside := filepath.Join(work, "in")
	out, code, err = s.sandboxedOutput(ctx, profile, work, "/bin/sh", "-c", `echo x > "$1" && cat "$1"`, "sh", inside)
	if err != nil {
		return fmt.Errorf("confiner: seatbelt probe: %w", err)
	}
	if code != 0 || string(out) != "x\n" {
		return fmt.Errorf("confiner: seatbelt probe: write and read inside the workspace failed (exit %d): %s", code, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(inside); err != nil {
		return fmt.Errorf("confiner: seatbelt probe: the write inside the workspace left no file: %w", err)
	}
	return nil
}

// denialVerdict decides whether the probe's outside write was DENIED: only a
// non-zero exit that is the command's own (not sandbox-exec's 65/71, and not
// a signalled child with no exit code) together with an absent file counts.
// Anything else is a probe error, so enforcement is never inferred from a
// failure that is not a denial.
func denialVerdict(code int, out []byte, target string) error {
	switch {
	case code == 0:
		return fmt.Errorf("confiner: seatbelt probe: the sandbox did not deny a write outside the workspace (%s)", target)
	case code == exitProfileRejected || code == exitExecFailed:
		return fmt.Errorf("confiner: seatbelt probe: sandbox-exec did not run the probe command (exit %d): %s", code, strings.TrimSpace(string(out)))
	case code < 0:
		return fmt.Errorf("confiner: seatbelt probe: the probe command did not run to completion (signalled, no exit code): %s", strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("confiner: seatbelt probe: the sandbox reported a denial but %s exists (%v)", target, err)
	}
	return nil
}

func randomSuffix() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("confiner: seatbelt probe: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// lookProgram resolves program in the backend's own environment (the child's
// environment carries no PATH unless asked for) and requires a regular file
// with an execute bit, so a program sandbox-exec could not exec is refused
// here instead of surfacing as its exit 71.
func lookProgram(program string) (string, error) {
	abs, err := exec.LookPath(program)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s is not an executable file", abs)
	}
	return abs, nil
}

// Launch starts one compartment: sandbox-exec under the compartment's
// profile, exec'ing the program in place in its own session, with the store as
// working directory and WORK, only the named environment (plus TMPDIR when
// Scratch), and a PID record of its pid, start time, store and owner. The
// record is claimed, pending, before anything else exists under the name, and
// completed once the process is running. It never creates the store.
func (s *Seatbelt) Launch(ctx context.Context, spec Spec) (Compartment, error) {
	if !ValidStoreName(spec.Name) {
		return nil, fmt.Errorf("confiner: %q is not a legal compartment name", spec.Name)
	}
	if !ValidStoreName(spec.Store) {
		return nil, fmt.Errorf("confiner: %q is not a legal store name", spec.Store)
	}
	if err := s.ValidateProgram(spec.Program); err != nil {
		return nil, err
	}
	argv := spec.Argv
	if spec.Program != "" {
		argv = append([]string{spec.Program}, spec.Argv...)
	}
	if len(argv) == 0 {
		return nil, errors.New("confiner: a seatbelt compartment needs a program (Program or Argv[0])")
	}
	abs, err := lookProgram(argv[0])
	if err != nil {
		return nil, fmt.Errorf("%w: program not found or not executable: %v", ErrDidNotLaunch, err)
	}
	store := s.StorePath(spec.Store)
	if fi, err := os.Stat(store); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("confiner: store %q does not exist at %s; Launch never creates it", spec.Store, store)
	}
	paths := make([]Path, len(spec.Paths))
	for i, p := range spec.Paths {
		r, err := resolveProfilePath("path", p.Path)
		if err != nil {
			return nil, err
		}
		paths[i] = Path{Path: r, RW: p.RW}
	}
	var scratch string
	if spec.Scratch {
		scratch = s.scratchDir(spec.Name)
		if err := sbplSafe(scratch); err != nil {
			return nil, err
		}
	}
	profile := s.profile(scratch, paths)
	if err := s.compile(ctx, profile, store); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDidNotLaunch, err)
	}
	c := &seatbeltCompartment{s: s, name: spec.Name, pidFile: s.pidFile(spec.Name), scratch: scratch, done: make(chan struct{})}

	// Claim the name first: a PENDING record (no pid yet) that carries the
	// owner. From here until the record is completed below, another
	// instance's Reap sees a name a running instance owns and leaves the
	// scratch dir created next alone; without the claim it would see an
	// unaccounted-for scratch dir and remove it from under the command. An
	// existing record means a compartment may be live under this name, so the
	// launch is refused before anything is started or created.
	rec := pidRecord{Store: spec.Store, OwnerPID: s.owner.pid, OwnerStartUnixMicro: s.owner.start}
	if err := writePIDRecord(c.pidFile, rec); err != nil {
		return nil, fmt.Errorf("confiner: compartment %q: %w", spec.Name, err)
	}
	if scratch != "" {
		if err := os.MkdirAll(filepath.Dir(scratch), 0o700); err != nil {
			c.removeFiles()
			return nil, fmt.Errorf("confiner: scratch dir: %w", err)
		}
		if err := os.Mkdir(scratch, 0o700); err != nil {
			c.removeFiles()
			return nil, fmt.Errorf("confiner: scratch dir: %w", err)
		}
	}

	env, applied := childEnv(s.cfg.Environ(), spec.EnvNames, scratch)
	cmd := exec.Command(s.cfg.SandboxExec, sandboxArgs(profile, store, abs, argv[1:]...)...)
	cmd.Dir = store
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// A descendant that outlives the program can hold its output pipe open;
	// Wait gives up on the pipe this long after the program itself exited.
	cmd.WaitDelay = 5 * time.Second
	var capture *CapWriter
	sink := spec.Output
	if sink == nil {
		capture = NewCapWriter(MaxOutput)
		sink = capture
	}
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Start(); err != nil {
		// The claim above is this launch's own, so the record goes with the
		// scratch dir.
		c.removeFiles()
		return nil, fmt.Errorf("confiner: start sandbox-exec: %w", err)
	}
	c.cmd, c.pid = cmd, cmd.Process.Pid

	// abandon ends a process this launch started but cannot keep: it is this
	// exec.Cmd's own un-reaped child, so its pid cannot have been reused and
	// the ungated kill is safe. Its record and scratch dir go with it.
	abandon := func(reason error) (Compartment, error) {
		killSession(c.pid)
		_ = cmd.Wait()
		c.removeFiles()
		return nil, fmt.Errorf("confiner: compartment %q: %w", spec.Name, reason)
	}
	// The record pairs the pid with its start time so a later process can
	// tell this process from a reused pid. A process whose start time cannot
	// be read could never be matched by a later Timeout, Remove or Reap, so it
	// is not allowed to run: fail closed rather than run unrecorded.
	start, err := processStart(c.pid)
	if err != nil {
		return abandon(fmt.Errorf("start time unavailable, refusing to run it unrecorded: %w", err))
	}
	c.start = start
	rec.PID, rec.StartUnixMicro = c.pid, start
	if err := replacePIDRecord(c.pidFile, rec); err != nil {
		return abandon(err)
	}

	var timer *time.Timer
	if spec.Timeout > 0 {
		timer = time.AfterFunc(spec.Timeout, func() {
			s.cfg.Logger.Warn("compartment timed out", "compartment", spec.Name, "pid", c.pid, "timeout", spec.Timeout)
			c.kill()
		})
	}
	go func() {
		waitErr := cmd.Wait()
		if timer != nil {
			timer.Stop()
		}
		c.removeFiles()
		var ee *exec.ExitError
		switch {
		case waitErr != nil && !errors.As(waitErr, &ee) && !errors.Is(waitErr, exec.ErrWaitDelay):
			c.err = fmt.Errorf("confiner: sandbox-exec: %w", waitErr)
		case cmd.ProcessState == nil:
			c.err = fmt.Errorf("confiner: sandbox-exec: %w", waitErr)
		case cmd.ProcessState.ExitCode() == exitProfileRejected || cmd.ProcessState.ExitCode() == exitExecFailed:
			// sandbox-exec's own failure: the program never ran, so a runtime
			// must not attest it. A program that itself exits 65 or 71 is
			// indistinguishable and treated the same.
			c.res = Result{Exit: cmd.ProcessState.ExitCode()}
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

type seatbeltCompartment struct {
	s    *Seatbelt
	name string
	cmd  *exec.Cmd
	pid  int
	// start is the recorded start time of pid; 0 when it could not be read.
	start   int64
	pidFile string
	scratch string
	done    chan struct{}
	// res and err are written once, before done is closed.
	res Result
	err error
}

// kill tears the session down only while pid is still the process this
// compartment started: the kernel's start time for pid must equal the one
// recorded at Launch. Once the program has been reaped its pid can belong to
// anything, and a reused pid never has the same start time, so a late timer
// or a Remove after exit signals nothing.
func (c *seatbeltCompartment) kill() {
	if start, err := processStart(c.pid); err == nil && start == c.start {
		killSession(c.pid)
	}
}

// removeFiles removes the PID record this compartment wrote and its scratch
// dir; both the exit goroutine and Remove call it, so a file already gone is
// not an error. It is only reached once the claim (writePIDRecord) has
// succeeded, so the record it removes is this compartment's own.
func (c *seatbeltCompartment) removeFiles() {
	if err := os.Remove(c.pidFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		c.s.cfg.Logger.Warn("pid record not removed", "compartment", c.name, "error", err)
	}
	c.removeScratch()
}

// removeScratch removes the scratch dir, if any.
func (c *seatbeltCompartment) removeScratch() {
	if c.scratch != "" {
		if err := os.RemoveAll(c.scratch); err != nil {
			c.s.cfg.Logger.Warn("scratch dir not removed", "compartment", c.name, "error", err)
		}
	}
}

func (c *seatbeltCompartment) Wait(ctx context.Context) (Result, error) {
	select {
	case <-c.done:
		return c.res, c.err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

func (c *seatbeltCompartment) Done() <-chan struct{} { return c.done }

// PID is the sandboxed program's own pid: sandbox-exec applies the profile and
// execs the program in place.
func (c *seatbeltCompartment) PID() int { return c.pid }

// Remove kills the compartment's session and the descendants the walk can
// see, removes its PID record and scratch dir, and waits, bounded, for the
// exit. A descendant that left the session and whose parent is gone is not
// reached: teardown on this tier is best-effort.
func (c *seatbeltCompartment) Remove(context.Context) error {
	c.kill()
	c.removeFiles()
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case <-c.done:
		return nil
	case <-t.C:
		// Gated by the runtime rather than a start time: os.Process refuses
		// with ErrProcessDone once wait4 has returned, so this can never reach
		// a reused pid.
		_ = c.cmd.Process.Kill()
		return fmt.Errorf("confiner: compartment %q did not exit within 10s of removal", c.name)
	}
}

// CreateStore creates <StoreRoot>/<name>; an existing store is an error.
func (s *Seatbelt) CreateStore(_ context.Context, name string) error {
	if !ValidStoreName(name) {
		return fmt.Errorf("confiner: %q is not a legal store name", name)
	}
	if err := os.Mkdir(s.StorePath(name), 0o700); err != nil {
		return fmt.Errorf("confiner: create store: %w", err)
	}
	return nil
}

// storeInUse reports whether a PID record names store and its process is
// still the one the record was written for (its start time matches). A
// record whose process is gone or reused does not count, nor does a pending
// one (no process yet); an unreadable one is left for Reap.
func (s *Seatbelt) storeInUse(store string) (bool, error) {
	entries, err := os.ReadDir(s.cfg.PIDDir)
	if err != nil {
		return false, fmt.Errorf("confiner: pid dir: %w", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pid") {
			continue
		}
		rec, err := readPIDRecord(filepath.Join(s.cfg.PIDDir, e.Name()))
		if err != nil || rec.Store != store || rec.PID == 0 {
			continue
		}
		if start, err := processStart(rec.PID); err == nil && start == rec.StartUnixMicro {
			return true, nil
		}
	}
	return false, nil
}

// RemoveStore removes a store. Without force, a store a live compartment runs
// on is ErrStoreInUse; "live" is a PID record naming the store whose process
// still has the recorded start time. With force the directory goes regardless.
func (s *Seatbelt) RemoveStore(_ context.Context, name string, force bool) error {
	if !ValidStoreName(name) {
		return fmt.Errorf("confiner: %q is not a legal store name", name)
	}
	if !force {
		busy, err := s.storeInUse(name)
		if err != nil {
			return err
		}
		if busy {
			return fmt.Errorf("%w: a compartment is running on store %q", ErrStoreInUse, name)
		}
	}
	if err := os.RemoveAll(s.StorePath(name)); err != nil {
		return fmt.Errorf("confiner: remove store: %w", err)
	}
	return nil
}

// Reap sweeps the LEFTOVERS of compartments whose names start with prefix:
// every <PIDDir>/<prefix>*.pid record, then every <StoreRoot>/<prefix>* store
// and <StoreRoot>/.scratch/<prefix>* scratch dir — except what a compartment
// of another RUNNING instance accounts for. A record names its owner (the
// process that launched the compartment); when that owner is still running
// and is not the caller, the record, its process, its scratch dir and the
// store it names are left exactly as they are: several instances may share
// one store root and pid dir, and a sibling's command in flight is not a
// leftover. An owner that is gone, the caller itself (sweeping its own
// leftovers on the way out) or a record with no owner stamp marks a leftover.
// A leftover's process is signalled ONLY when the kernel's start time for its
// pid equals the recorded one: a stale record from a crash or a reboot whose
// pid now belongs to some other process (an editor, a terminal, a backup) is
// deleted without a signal. An unreadable record, a pending record, a missing
// process and a start-time mismatch are all "already gone". A listing failure
// is returned; a leftover that cannot be removed is logged and does not stop
// the sweep.
func (s *Seatbelt) Reap(_ context.Context, prefix string) error {
	if prefix == "" {
		return errors.New("confiner: reap needs a name prefix (an empty one would match everything)")
	}
	entries, err := os.ReadDir(s.cfg.PIDDir)
	if err != nil {
		return fmt.Errorf("confiner: reap: %w", err)
	}
	// What another running instance owns: compartment names (their scratch
	// dirs stay) and the stores those compartments run on (they stay too).
	liveNames, liveStores := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".pid") {
			continue
		}
		comp := strings.TrimSuffix(name, ".pid")
		path := filepath.Join(s.cfg.PIDDir, name)
		rec, err := readPIDRecord(path)
		switch {
		case err != nil:
			s.cfg.Logger.Info("removing an unreadable pid record", "file", path, "error", err)
		case !rec.owner().reapableBy(s.owner):
			s.cfg.Logger.Info("leaving a compartment another running instance owns", "compartment", comp, "owner_pid", rec.OwnerPID)
			liveNames[comp] = true
			liveStores[rec.Store] = true
			continue
		case rec.PID > 0:
			start, err := processStart(rec.PID)
			if err == nil && start == rec.StartUnixMicro {
				s.cfg.Logger.Info("reaping leftover compartment", "compartment", comp, "pid", rec.PID)
				killSession(rec.PID)
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.cfg.Logger.Warn("leftover pid record not removed", "file", path, "error", err)
		}
	}
	s.removePrefixed(s.cfg.StoreRoot, prefix, "store", true, liveStores)
	s.removePrefixed(filepath.Join(s.cfg.StoreRoot, ".scratch"), prefix, "scratch dir", false, liveNames)
	return nil
}

// removePrefixed removes every directory in dir whose name starts with prefix
// and is not in keep. With storesOnly, a name that is not a legal store name
// (the backend's own .scratch, a probe's leftover) is never touched.
func (s *Seatbelt) removePrefixed(dir, prefix, what string, storesOnly bool, keep map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.cfg.Logger.Warn("leftovers not listed", "dir", dir, "error", err)
		}
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, prefix) || keep[name] || (storesOnly && !ValidStoreName(name)) {
			continue
		}
		s.cfg.Logger.Info("reaping leftover "+what, "name", name)
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			s.cfg.Logger.Warn("leftover "+what+" not removed", "name", name, "error", err)
		}
	}
}
