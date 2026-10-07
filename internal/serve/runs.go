package serve

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
)

// runState is one hosted run as the table knows it. status is
// apiclient.StatusRunning until the goroutine finishes, then the engine's
// Result.Status.
type runState struct {
	id       string
	status   string
	reason   string
	started  time.Time
	finished time.Time
	result   engine.Result
	cancel   context.CancelFunc
}

func (st runState) wire() apiclient.RunStatus {
	out := apiclient.RunStatus{RunID: st.id, Status: st.status, Reason: st.reason, Started: st.started}
	if !st.finished.IsZero() {
		f := st.finished
		out.Finished = &f
	}
	if st.status == "succeeded" {
		out.OutputSHA, out.OutputPreview = st.result.OutputSHA, st.result.OutputPreview
	}
	return out
}

// runTable is the status source for runs this process hosts. It never
// evicts (a reserved limit for a long-lived server).
type runTable struct {
	mu sync.Mutex
	m  map[string]*runState
}

func newRunTable() *runTable { return &runTable{m: map[string]*runState{}} }

// mint picks a fresh run id and inserts it as running, all under the lock,
// so two concurrent POSTs can never share one. An id already in the table
// or already on disk under logDir is skipped; the on-disk check is a cheap
// pre-check — the exclusive create inside the engine is what closes the
// cross-process race, and a loss there surfaces as the run's outcome.
func (t *runTable) mint(logDir string, cancel context.CancelFunc, now time.Time) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for range 3 {
		id := engine.NewRunID()
		if !t.fresh(logDir, id) {
			continue
		}
		t.m[id] = &runState{id: id, status: apiclient.StatusRunning, started: now, cancel: cancel}
		return id, nil
	}
	return "", errors.New("could not mint a fresh run id")
}

// fresh reports whether id is unknown to the table AND has no log under
// logDir. Called with the lock held.
func (t *runTable) fresh(logDir, id string) bool {
	if _, dup := t.m[id]; dup {
		return false
	}
	_, err := os.Stat(filepath.Join(logDir, id+".jsonl"))
	return err != nil
}

func (t *runTable) get(id string) (runState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.m[id]
	if !ok {
		return runState{}, false
	}
	return *st, true
}

func (t *runTable) finish(id string, res engine.Result, reason string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if st, ok := t.m[id]; ok {
		st.status, st.reason, st.result, st.finished = res.Status, reason, res, now
	}
}

// cancelRun cancels a running run's context. It reports whether the run is
// hosted here and whether it was still running.
func (t *runTable) cancelRun(id string) (st runState, found, running bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok {
		return runState{}, false, false
	}
	if p.status != apiclient.StatusRunning {
		return *p, true, false
	}
	p.cancel()
	return *p, true, true
}

func (t *runTable) snapshot() []runState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]runState, 0, len(t.m))
	for _, id := range slices.Sorted(maps.Keys(t.m)) {
		out = append(out, *t.m[id])
	}
	return out
}

// readLedger is engine.ReadLog with the verdict classified: torn/broken
// still return the prefix (ok=true); a missing file is (ok=false, nil);
// any other open/IO failure is the error.
func readLedger(logDir, id string) (events []engine.Event, head ledger.Head, verr error, ok bool, err error) {
	events, head, verr = engine.ReadLog(logDir, id)
	if verr == nil {
		return events, head, nil, true, nil
	}
	var te *ledger.TornError
	var be *ledger.ChainBrokenError
	if errors.As(verr, &te) || errors.As(verr, &be) {
		return events, head, verr, true, nil
	}
	if errors.Is(verr, fs.ErrNotExist) {
		return nil, ledger.Head{}, nil, false, nil
	}
	return nil, ledger.Head{}, nil, false, verr
}

// summarizeOnDisk derives a run's status from its ledger alone — the only
// view of a run this process did not host, or hosted before a restart. No
// terminal event means StatusIncomplete. ok is false when there is no
// ledger for id at all.
func summarizeOnDisk(logDir, id string) (st apiclient.RunStatus, ok bool, err error) {
	events, _, _, ok, err := readLedger(logDir, id)
	if err != nil || !ok {
		return apiclient.RunStatus{}, ok, err
	}
	st = apiclient.RunStatus{RunID: id, Status: apiclient.StatusIncomplete}
	if len(events) == 0 {
		return st, true, nil
	}
	st.Started = events[0].Time
	var sha, preview string
	for _, e := range events {
		switch e.Type {
		case "step_succeeded":
			sha, preview = e.ArtifactSHA, e.Artifact
		case "workflow_finished":
			t := e.Time
			st.Status, st.Reason, st.Finished = e.Status, e.Reason, &t
		case "run_refused":
			t := e.Time
			st.Status, st.Reason, st.Finished = apiclient.StatusRefused, e.Reason, &t
		}
	}
	if st.Status == "succeeded" {
		st.OutputSHA, st.OutputPreview = sha, preview
	}
	return st, true, nil
}

// terminalReason reads back the reason a hosted run's ledger recorded on
// its last word — workflow_finished or run_refused — so the status view
// says why, not only what. Empty when the ledger cannot say.
func terminalReason(logDir, id string) string {
	st, ok, err := summarizeOnDisk(logDir, id)
	if err != nil || !ok {
		return ""
	}
	return st.Reason
}

func sortedKeys(m map[string]string) []string { return slices.Sorted(maps.Keys(m)) }
