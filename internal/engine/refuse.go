package engine

import (
	"errors"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
)

// ErrStepConfig marks a step failure as a configuration problem (e.g. no
// route for the agent's model) rather than a transient/executor failure.
// Executors that hit a configuration error should wrap it:
//
//	fmt.Errorf("no route for model %q: %w", model, engine.ErrStepConfig)
//
// Run treats an error wrapping ErrStepConfig as terminal: it fails the
// workflow immediately without bouncing back to a prior step, since retrying
// a misconfigured step cannot succeed.
var ErrStepConfig = errors.New("step configuration error")

// ErrLedgerWrite marks an error Run returns because the run's ledger could
// not be appended. A caller that must tell "refused, and recorded" from
// "refused, and the record itself failed" checks errors.Is(err, ErrLedgerWrite).
var ErrLedgerWrite = errors.New("ledger write failed")

// RecordRefused records a run refusal decided before Run — a caller that
// ran Admit (or its own pre-run gate) and never starts a workflow. It opens
// a fresh log under opts.LogDir (under opts.RunID when set, else a fresh
// id), writes exactly one run_refused event — the same event Run's own
// refusal writes: the binding, linked under opts.Parent when set, and
// opts.Origin sanitized — and closes the log. It returns the run id so the
// refusal can be looked up and audited like any other run. opts.LogDir
// defaults as Run's does.
func RecordRefused(opts Options, inv identity.Invoker, role, workflow, reason string) (string, error) {
	if opts.LogDir == "" {
		opts.LogDir = ".agenthof/runs"
	}
	runID := opts.RunID
	if runID == "" {
		runID = NewRunID()
	}
	log, err := OpenLog(opts.LogDir, runID)
	if err != nil {
		return runID, err
	}
	defer func() { _ = log.Close() }()
	bind := Binding{Invoker: inv, Role: role, Workflow: workflow, RunID: runID}.linkedTo(opts.Parent)
	e := Event{
		Time:    time.Now().UTC(),
		Type:    "run_refused",
		Reason:  reason,
		Origin:  opts.Origin.sanitized(),
		Binding: bind,
	}
	if err := log.Append(e); err != nil {
		return runID, err
	}
	return runID, nil
}

// Refuse is RecordRefused for a caller that has only a log directory and a
// parent: a root (nil parent) or a spawned child refused before the engine
// started, with no Origin. Kept for those callers; the bytes it writes are
// unchanged.
func Refuse(logDir, role, workflow string, inv identity.Invoker, reason string, parent *Binding) (string, error) {
	return RecordRefused(Options{LogDir: logDir, Parent: parent}, inv, role, workflow, reason)
}
