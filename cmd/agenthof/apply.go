package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/registry"
)

// hashConfigDir computes a config directory's join-key hash for
// applyConfig and cmdRegistryFlip. It is a var (rather than a direct
// config.HashDir call) so tests can force a hash failure independently of
// LoadDir/Build's own read of the same files — the two read the same
// bytes via the same enumeration, so there is no way to make one fail
// without the other through the filesystem alone.
var hashConfigDir = config.HashDir

// msgInstalledNotRecorded is apply's analogue of the kill switch's "state
// changed; event NOT recorded": the snapshot is installed and the pointer
// flipped, but the success event could not be appended. audit control and
// audit verify control surface the resulting pointer-vs-ledger mismatch.
const msgInstalledNotRecorded = "installed; event NOT recorded"

// msgLockBusy is printed, after the command's own prefix, when another
// process holds the installed-configuration writer lock (or, at the
// ledger-writable check, the ledger's own flock) past the lock timeout.
// Nothing was read, nothing is recorded: contention, not a denial.
const msgLockBusy = "another agenthof process holds the installed-configuration lock; retry"

// msgBootstrapDisabled is the recorded not_authorized reason for an apply
// that arrives while nothing is installed and the caller did not permit a
// bootstrap (the server without --allow-api-bootstrap).
const msgBootstrapDisabled = "not authorized: nothing is installed and bootstrap over the API is not enabled (serve --allow-api-bootstrap); apply locally first"

// msgStagedDiffers is the recorded io_error reason when a bundle's staged
// copy does not hash as the bundle itself: the filesystem changed a name or
// the bytes between staging and hashing, and nothing is installed.
const msgStagedDiffers = "staged copy differs from the proposal"

// applySource is the proposed configuration: the --config directory (CLI)
// or a bundle received over the API. Stage copies it into a fresh
// .staging-* temp under store; Hash is its config hash WITHOUT staging —
// the forensic hash a refused record carries (the directory is hashed
// before any copy, as it always was: an unauthorized caller causes no
// write to the store).
type applySource interface {
	Stage(store string) (temp string, err error)
	Hash() (string, error)
}

// dirSource is a configuration directory, read once by StageSnapshot.
type dirSource string

func (d dirSource) Stage(store string) (string, error) { return config.StageSnapshot(store, string(d)) }
func (d dirSource) Hash() (string, error)              { return hashConfigDir(string(d)) }

// bundleSource is an in-memory proposal whose bytes the client already
// hashed; applyConfig requires the staged copy to hash exactly as the
// bundle before it commits (step 9a).
type bundleSource map[string][]byte

func (b bundleSource) Stage(store string) (string, error) { return config.StageFiles(store, b) }
func (b bundleSource) Hash() (string, error)              { return config.HashFiles(b) }

// applyPrecondition is the compare-and-swap on the installed pointer. nil
// means none (the CLI without --if-installed). ExpectNone: proceed only if
// nothing is installed. Otherwise ExpectInstalled must equal the pointer
// read under the writer lock.
type applyPrecondition struct {
	ExpectInstalled string
	ExpectNone      bool
}

// applyRequest is everything one apply needs.
type applyRequest struct {
	ControlLog   string
	Invoker      identity.Invoker
	AssertedAs   string
	Source       applySource
	Precondition *applyPrecondition
	// AllowBootstrap permits an apply while nothing is installed. The CLI
	// always passes true (the caller owns the filesystem); the server passes
	// its --allow-api-bootstrap flag.
	AllowBootstrap bool
	// Origin is nil on the CLI; via:"api" from the server.
	Origin *origin.Origin
}

// applyKind is the terminal outcome of applyConfig.
type applyKind int

const (
	applyInstalled            applyKind = iota // success recorded (Bootstrap when nothing was installed)
	applyLedgerDamaged                         // ledger.Open failed; nothing recorded; the caller prints the repair hint
	applyBusy                                  // the writer lock (or the ledger flock) is held elsewhere; nothing recorded
	applyRefused                               // recorded refused/not_authorized
	applyPreconditionFailed                    // CAS mismatch; nothing recorded
	applyRejected                              // recorded rejected/validation_failed
	applyError                                 // recorded error/io_error
	applyAppendFailed                          // a terminal append itself failed (printed, exit 1)
	applyInstalledNotRecorded                  // committed; the success append failed
)

// applyOutcome is what both callers read; every line the CLI prints was
// already written to out by applyConfig.
type applyOutcome struct {
	Kind        applyKind
	ConfigHash  string          // the hash recorded (installed / rejected / refused), else ""
	CurrentHash string          // the pointer read under the lock; "" when nothing was installed
	Installed   bool            // something was installed when the apply began
	Head        ledger.Head     // the control head after the recorded event (zero when none)
	Reason      *control.Reason // refused / rejected / error
	Errors      []error         // rejected: every load error, then every validation error, in print order
	Agents      int             // installed: the registry ok counts
	Workflows   int
	Roles       int
}

// applyRun carries one apply's state through its recording helpers.
type applyRun struct {
	req applyRequest
	out io.Writer
	res applyOutcome
}

// applyConfig is THE apply — the CLI and the server both call it. Order,
// pinned: (1) ledger writable; (2) writer lock, held through the success
// append; (3) InstalledRoles; (4) authorize against the installed roles
// (or refuse a bootstrap the caller did not permit); (5) precondition; (6)
// stage; (7) load; (8) build + no-apply-floor; (9) hash, and 9a for a
// bundle: the staged copy must hash as the proposal; (10) commit; (11)
// registry ok, the crash hook, the success append. It writes to out
// exactly the lines cmdApply printed before it existed; the CLI passes
// stdout, the server io.Discard, and both read the outcome.
func applyConfig(req applyRequest, out io.Writer) applyOutcome {
	a := &applyRun{req: req, out: out}

	// 1. The control chain must be writable before anything is recorded.
	// Contention on a healthy ledger is busy, never damage.
	c, err := ledger.Open(req.ControlLog, ledger.Locked)
	if err != nil {
		if errors.Is(err, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "apply: %s\n", msgLockBusy)
			return a.done(applyBusy)
		}
		return a.done(applyLedgerDamaged)
	}
	_ = c.Close()

	// 2. The writer lock: every pointer writer — this apply, a concurrent
	// apply in another process, the kill switch — serializes here, so the
	// roles read below are the roles of the configuration this apply
	// installs over. Lock order is store → ledger (each Append takes the
	// ledger flock inside the writer lock); nothing takes them the other
	// way round. Released by defer after the success append (step 11).
	unlock, lockErr := ledger.LockFile(installedLock(req.ControlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "apply: %s\n", msgLockBusy)
			return a.done(applyBusy)
		}
		// The lock file cannot be created or opened (an unwritable
		// .agenthof/): the StageSnapshot-failure class — the ledger is known
		// writable, so it is recorded.
		_, _ = fmt.Fprintln(out, lockErr)
		return a.ioError(lockErr)
	}
	defer unlock()

	// 3. The installed configuration's roles, read under the lock.
	store := installedStore(req.ControlLog)
	installedRoles, currentHash, installed, instErr := config.InstalledRoles(store)
	if instErr != nil {
		// A pointer that is present but cannot be honored — malformed, or
		// naming a snapshot whose roles cannot be read: nobody can be
		// authorized. Fail closed, recorded, and name the one way out, which
		// is itself recorded as a bootstrap.
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprintf(out, "apply: cannot read the installed configuration under %s; refusing to apply (remove %s to re-bootstrap)\n",
			store, filepath.Join(store, config.InstalledPointer))
		return a.ioError(instErr)
	}
	a.res.CurrentHash, a.res.Installed = currentHash, installed

	// 4. Authorize BEFORE the proposal is read, against the roles of the
	// configuration already installed: a caller those roles grant no `apply`
	// learns one refusal — never the proposal's validation errors — and
	// cannot grant themselves anything in the change itself. Nothing
	// installed is the bootstrap: permitted when the caller allows it (the
	// CLI always does — in CLI mode the filesystem is the root of trust;
	// docs/control-plane-lifecycle.md says so) and a recorded refusal
	// otherwise. Authorization precedes the precondition so an unauthorized
	// caller learns nothing about the installed hash.
	if installed && !authz.ControlAllows(installedRoles, req.Invoker, "apply") {
		return a.refused(control.NotAuthorized("apply"))
	}
	if !installed && !req.AllowBootstrap {
		return a.refused(&control.Reason{Code: control.CodeNotAuthorized, Message: msgBootstrapDisabled})
	}

	// 5. The precondition — a stale-client check against the pointer read
	// under the lock. Not recorded: no governance decision was made and the
	// proposal was never looked at.
	if p := req.Precondition; p != nil {
		if (p.ExpectNone && installed) || (!p.ExpectNone && p.ExpectInstalled != currentHash) {
			_, _ = fmt.Fprintf(out, "apply: precondition failed: installed configuration is %s, not %s\n", orNothing(currentHash), expected(p))
			return a.done(applyPreconditionFailed)
		}
	}

	// 6. Snapshot-first: one read of the proposed bytes into the store, then
	// everything below — parse, validate, hash, install — is over the copy.
	// A copy that cannot be made is a genuine I/O denial, recorded hash-less.
	temp, stageErr := req.Source.Stage(store)
	if stageErr != nil {
		_, _ = fmt.Fprintln(out, stageErr)
		return a.ioError(stageErr)
	}
	committed := false
	defer func() {
		// A copy that was never installed is removed; after CommitSnapshot
		// the temp no longer exists (renamed, or discarded as a duplicate).
		if !committed {
			_ = os.RemoveAll(temp)
		}
	}()

	// 7. Load.
	cfg, loadErrs := config.LoadDir(temp)
	for _, e := range loadErrs {
		_, _ = fmt.Fprintln(out, e)
	}
	a.res.Errors = append(a.res.Errors, loadErrs...)
	if len(loadErrs) > 0 {
		// The copy succeeded, so the bytes are readable: a parse failure here
		// is a rejectable config, recorded with the copy's hash.
		return a.rejected(temp, loadErrs[0])
	}

	// 8. Build + the no-apply floor.
	_, valErrs := registry.Build(cfg)
	valErrs = append(valErrs, applyFloorErrors(cfg)...)
	for _, e := range valErrs {
		_, _ = fmt.Fprintln(out, e.Error())
		a.res.Errors = append(a.res.Errors, e)
	}
	if len(valErrs) > 0 {
		return a.rejected(temp, valErrs[0])
	}

	// 9. config_hash is required on a "success" event, and it names the
	// snapshot directory: routed through the hashConfigDir seam so a hash
	// failure is exercisable by a test — recorded as io_error, never a
	// hash-less success, and nothing installed.
	h, hashErr := hashConfigDir(temp)
	if hashErr != nil {
		return a.hashFailure(hashErr)
	}
	// 9a. A bundle must install exactly the bytes the client hashed: a 200
	// can never name a hash the client did not compute, whatever the
	// filesystem did to names or bytes in between (case folding, Unicode
	// normalization). A directory is read once by StageSnapshot and may
	// legitimately differ from a hash computed earlier, so it is exempt.
	if _, isBundle := req.Source.(bundleSource); isBundle {
		want, err := req.Source.Hash()
		if err != nil {
			return a.hashFailure(err)
		}
		if want != h {
			_, _ = fmt.Fprintln(out, msgStagedDiffers)
			return a.ioError(errors.New(msgStagedDiffers))
		}
	}

	// 10. Install. CommitSnapshot leaves `current` untouched on any error:
	// nothing is installed, so this is a plain recorded error.
	if err := config.CommitSnapshot(store, temp, h); err != nil {
		_, _ = fmt.Fprintln(out, err)
		return a.ioError(err)
	}
	committed = true
	a.res.Agents, a.res.Workflows, a.res.Roles = len(cfg.Agents), len(cfg.Workflows), len(cfg.Roles)
	_, _ = fmt.Fprintf(out, "registry ok: %d agents, %d workflows, %d roles\n", a.res.Agents, a.res.Workflows, a.res.Roles)

	// 11. Test-only crash hook (the apply twin of cmdRegistryFlip's): the
	// process dies after the snapshot is installed and the pointer flipped
	// but before the success append — the documented residual window,
	// exercisable by a test instead of an unreproducible race.
	if os.Getenv("AGENTHOF_TEST_CRASH_AT") == "after_install_before_append" {
		_, _ = fmt.Fprintln(out, msgInstalledNotRecorded)
		return a.done(applyInstalledNotRecorded)
	}
	return a.record(applyInstalled, "success", nil, h)
}

// done sets the terminal kind on an unrecorded outcome.
func (a *applyRun) done(kind applyKind) applyOutcome {
	a.res.Kind = kind
	return a.res
}

// record appends the terminal control event and prints the head line. An
// append that itself fails is printed and reported as applyAppendFailed —
// or, after the install landed, as applyInstalledNotRecorded with the
// msgInstalledNotRecorded line, since the pointer already moved.
func (a *applyRun) record(kind applyKind, outcome string, reason *control.Reason, hash string) applyOutcome {
	a.res.Kind, a.res.Reason, a.res.ConfigHash = kind, reason, hash
	head, appendErr := control.Append(a.req.ControlLog, control.Event{
		Action:     "apply",
		Outcome:    outcome,
		Reason:     reason,
		Invoker:    a.req.Invoker,
		AssertedAs: a.req.AssertedAs,
		Witness:    control.CaptureWitness(),
		ConfigHash: hash,
		Bootstrap:  kind == applyInstalled && !a.res.Installed,
		Origin:     a.req.Origin,
	})
	if appendErr != nil {
		_, _ = fmt.Fprintln(a.out, appendErr)
		a.res.Kind = applyAppendFailed
		if kind == applyInstalled {
			_, _ = fmt.Fprintln(a.out, msgInstalledNotRecorded)
			a.res.Kind = applyInstalledNotRecorded
		}
		return a.res
	}
	a.res.Head = head
	_, _ = fmt.Fprintf(a.out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	return a.res
}

// refused prints the refusal and records it with the proposal's hash — the
// forensic value of recording it. The same rule as success/rejected
// applies: no hash, no refused record (a hash failure is an io_error).
func (a *applyRun) refused(reason *control.Reason) applyOutcome {
	_, _ = fmt.Fprintf(a.out, "apply: %s\n", reason.Message)
	h, hashErr := a.req.Source.Hash()
	if hashErr != nil {
		return a.hashFailure(hashErr)
	}
	return a.record(applyRefused, "refused", reason, h)
}

// ioError records an already-printed I/O failure as error/io_error with no
// config_hash.
func (a *applyRun) ioError(err error) applyOutcome {
	return a.record(applyError, "error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(err)}, "")
}

// hashFailure records a hash that could not be computed after
// LoadDir/Build already judged the same bytes: config_hash is required on
// success and rejected, so this is itself a writable-ledger denial —
// error/io_error, never a hash-less success/rejected.
func (a *applyRun) hashFailure(hashErr error) applyOutcome {
	_, _ = fmt.Fprintln(a.out, hashErr)
	return a.ioError(hashErr)
}

// rejected records rejected/validation_failed with the staged copy's hash
// — required on that outcome — or the honest io_error when the copy cannot
// be hashed. cause is the first load or validation error; over the API the
// proposer is any authorized token-holder and the message carries names
// from the proposed YAML, so over the API (Origin present) it is cleaned
// (printable, 200 runes) before the byte cap; a CLI apply (no Origin) records
// it raw via truncateErr, byte-identical to what the local command recorded
// before the API path existed.
func (a *applyRun) rejected(temp string, cause error) applyOutcome {
	h, hashErr := hashConfigDir(temp)
	if hashErr != nil {
		return a.hashFailure(hashErr)
	}
	return a.record(applyRejected, "rejected", &control.Reason{Code: control.CodeValidationFailed, Message: a.cleanReason(cause)}, h)
}

// cleanReason bounds the recorded reason. On the API path (Origin present —
// the proposer is any authorized token-holder) it sanitizes through
// origin.Clean first, so attacker-shaped names from the proposed YAML cannot
// put control runes or an over-long line into the ledger. On the CLI path
// (no Origin) it is exactly truncateErr, byte-identical to what the local
// command recorded before the API path existed — so no existing control record
// changes (a multi-line yaml TypeError keeps its original form on the CLI; a
// blanket Clean would have collapsed it to one line).
func (a *applyRun) cleanReason(err error) string {
	if a.req.Origin == nil {
		return truncateErr(err)
	}
	return truncateErr(errors.New(origin.Clean(err.Error())))
}

func orNothing(hash string) string {
	if hash == "" {
		return "nothing"
	}
	return hash
}

func expected(p *applyPrecondition) string {
	if p.ExpectNone {
		return "none"
	}
	return p.ExpectInstalled
}

// ifInstalledRE is --if-installed's hash grammar: the pointer's own.
var ifInstalledRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// parseIfInstalled turns --if-installed into a precondition: "" is nil (no
// check — the default), "none" expects nothing installed, a sha256:<hex>
// expects that pointer; anything else is a usage error.
func parseIfInstalled(v string) (*applyPrecondition, bool) {
	switch {
	case v == "":
		return nil, true
	case v == "none":
		return &applyPrecondition{ExpectNone: true}, true
	case ifInstalledRE.MatchString(v):
		return &applyPrecondition{ExpectInstalled: v}, true
	}
	return nil, false
}
