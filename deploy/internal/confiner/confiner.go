// Package confiner is the backend-neutral seam between the operator-side
// runtimes (refexec, refspawn) and whatever confines a compartment on the
// host: a rootless podman container on Linux, a macOS Seatbelt profile, or a
// future tier. A runtime describes a compartment in neutral terms (Spec) and
// the selected Confiner applies the hardening; the runtime never builds a
// backend's command line itself.
package confiner

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"
)

// Tier is the ledger name of a confinement backend. It is an additive,
// grow-only set: readers shape-validate a tier and record it verbatim; they
// never reject an unknown one.
type Tier string

const (
	// TierPodman is rootless podman with --userns=keep-id: a SHARED-KERNEL
	// container tier (Linux). The compartment shares the host kernel.
	TierPodman Tier = "podman"
	// TierSeatbelt is macOS Seatbelt (sandbox-exec, SBPL): a SHARED-KERNEL
	// OS-sandbox tier. The compartment shares the host kernel, and what it may
	// read is a per-tier property, not a podman-equivalent guarantee.
	TierSeatbelt Tier = "seatbelt"
)

// reserved are tier VALUES with no backend yet; the factory refuses to select
// them. They are kept so a later backend can claim the name without a schema
// change.
//
//	"none"     uncontained
//	"landlock" Linux LSM
//	"wsl2"     podman over podman-machine/WSL2 on Windows
//	"microvm"  a micro-VM tier
var reserved = map[Tier]bool{"none": true, "landlock": true, "wsl2": true, "microvm": true}

// Reserved reports whether t is a reserved value that no backend implements.
func Reserved(t Tier) bool { return reserved[t] }

// Path is a host path the compartment may see AT ITS OWN PATH (no remap),
// read-only unless RW. podman: a same-path bind mount; Seatbelt: a
// file-read*/file-write* subpath rule. refspawn passes its child socket
// directory RW; refexec passes none.
type Path struct {
	Path string
	RW   bool
}

// Limits are the per-compartment resource caps, in podman's format for now.
// podman enforces them; Seatbelt consumes them without enforcing.
type Limits struct {
	Memory, CPUs string
	PIDs         int
}

// Spec describes one compartment in backend-neutral terms. Hardening
// invariants (direct network denied, nothing writable outside the
// workspace/scratch/allow-listed RW paths, no privilege gain, the host user's
// identity) are the backend's to apply, not caller toggles. The ONLY
// filesystem the compartment may WRITE beyond the backend's own baseline is
// the workspace store, the RW Paths and the scratch dir; what it may READ is
// per tier.
type Spec struct {
	// Name is the compartment name and ledger session key (podman: container
	// name; Seatbelt: PID-file and log key).
	Name string
	// Program is the backend-interpreted "what runs": a container backend
	// takes an OCI image ref (its ENTRYPOINT is the program); a host backend
	// takes an executable path, or "" to mean Argv[0].
	Program string
	// Argv is appended AFTER Program (refspawn: "-socket <sock>"; refexec: the
	// agent's command).
	Argv []string
	// Store is the PRE-PROVISIONED workspace store the caller already
	// created; Launch never creates it. It is visible at StorePath(Store).
	Store string
	// Paths are allow-listed host paths at their own path (refspawn's child
	// directory, RW).
	Paths []Path
	// Scratch asks for a run-private writable scratch dir, exported to the
	// program as TMPDIR by every backend. No path is promised.
	Scratch bool
	// EnvNames are variable NAMES the caller asks to pass through from the
	// host environment (never values). The APPLIED list comes back in
	// Result.EnvNames.
	EnvNames []string
	// Limits are memory/cpus/pids caps. podman enforces; Seatbelt consumes
	// them without enforcing.
	Limits Limits
	// Timeout is the per-compartment wall-clock deadline (podman: --timeout,
	// enforced out of process by conmon; Seatbelt: the backend's own
	// in-process kill timer, with best-effort teardown).
	Timeout time.Duration
	// Output is the combined-output sink; nil means capture and cap into
	// Result.
	Output io.Writer
}

// Result is what Wait returns. EnvNames is the environment-variable NAME list
// the backend ACTUALLY applied: the caller's EnvNames plus anything the
// backend added (TMPDIR when Scratch is set), sorted. A runtime attests this
// list, never its own pre-Launch computation.
type Result struct {
	Exit        int
	Output      []byte // captured and capped when Spec.Output was nil
	Truncated   bool
	OutputBytes int64
	EnvNames    []string
}

// Confiner launches and manages compartments for one backend. It is safe for
// concurrent use and stateless beyond its construction-time inputs.
type Confiner interface {
	Tier() Tier
	// Opts returns the applied confiner_opts tokens, sorted; nil when none.
	Opts() []string
	// Probe checks startup availability and fails closed.
	Probe(ctx context.Context) error
	// ValidateProgram checks a Spec.Program for this backend. podman: an OCI
	// ref, and "" is ErrEmptyProgram; Seatbelt: "" is fine, otherwise an
	// absolute path.
	ValidateProgram(program string) error
	// Launch starts one compartment. It never creates the Spec.Store.
	Launch(ctx context.Context, spec Spec) (Compartment, error)
	// CreateStore creates a workspace store; only the set owner calls it.
	CreateStore(ctx context.Context, name string) error
	// RemoveStore removes a store. Without force it returns ErrStoreInUse
	// when the store is busy.
	RemoveStore(ctx context.Context, name string, force bool) error
	// StorePath is where a store is visible inside a compartment.
	StorePath(name string) string
	// Reap removes leftovers whose names start with prefix. It is scoped to
	// names the caller owns; the semantics are per backend.
	Reap(ctx context.Context, prefix string) error
}

// Compartment is one launched compartment.
type Compartment interface {
	// Wait blocks until the process exits and returns its Result. A backend
	// failure to run the command returns ErrDidNotLaunch. If ctx is done
	// first it returns (Result{}, ctx.Err()) and removes nothing. Remove
	// unblocks a pending Wait.
	Wait(ctx context.Context) (Result, error)
	// Done is closed when the process has exited.
	Done() <-chan struct{}
	// Remove stops and deletes the compartment under its own bounded context.
	Remove(ctx context.Context) error
	// PID is the host pid the runtime holds first-hand, for the attestation.
	PID() int
}

var (
	// ErrDidNotLaunch means the backend failed to run the command, so no
	// first-hand attestation of it may be made. podman: exit 125; Seatbelt:
	// sandbox-exec's exit 65 or 71. A program may itself exit with such a
	// code; that ambiguity is accepted.
	ErrDidNotLaunch = errors.New("confiner: the compartment did not run the command")
	// ErrStoreInUse is returned by RemoveStore without force when the store is busy.
	ErrStoreInUse = errors.New("confiner: store is in use")
	// ErrEmptyProgram is returned by a container backend for an empty Program.
	ErrEmptyProgram = errors.New("confiner: a container compartment needs an image")
	// ErrNotImplemented is returned for a tier that has no backend on this build.
	ErrNotImplemented = errors.New("confiner: backend not implemented")
	// ErrUnconsumedKeys is returned when config sets keys the selected
	// backend does not consume.
	ErrUnconsumedKeys = errors.New("confiner: config keys the selected backend does not consume")
	// ErrNotLocalEngine is returned when podman is pointed at a podman-machine.
	ErrNotLocalEngine = errors.New("confiner: podman-machine is the reserved `wsl2`-class backend, not built")
)

// OptSharedHostScratch is the confiner_opts token that accepts a scratch
// directory shared with the host.
const OptSharedHostScratch = "shared-host-scratch"

var (
	tokenRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	storeNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// ValidToken reports whether s has the shape of a tier name or a
// confiner_opts token.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// ValidStoreName reports whether s is a legal workspace store name. A name
// must start with a letter or digit, which also excludes ".scratch", the
// Seatbelt backend's own directory under its store root.
func ValidStoreName(s string) bool { return storeNameRE.MatchString(s) }
