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

// Refuse records a run refusal that happens before (or independent of) a
// call to Run — for example a caller that pre-checks authorization and never
// starts a workflow at all. It opens a fresh log under logDir, writes exactly
// one run_refused event carrying the binding, and closes the log. It returns
// the new run's ID so the refusal can be looked up and audited like any
// other run.
func Refuse(logDir, role, workflow string, inv identity.Invoker, reason string) (string, error) {
	runID := NewRunID()
	log, err := OpenLog(logDir, runID)
	if err != nil {
		return runID, err
	}
	defer log.Close()
	bind := Binding{Invoker: inv, Role: role, Workflow: workflow, RunID: runID}
	e := Event{
		Time:    time.Now().UTC(),
		Type:    "run_refused",
		Reason:  reason,
		Binding: bind,
	}
	if err := log.Append(e); err != nil {
		return runID, err
	}
	return runID, nil
}
