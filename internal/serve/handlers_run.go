package serve

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/identity"
)

// getRun answers from the table for a hosted run, else from the ledger on
// disk; a run nowhere is 404.
func (s *Server) getRun(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	id, ok := runID(w, r)
	if !ok {
		return
	}
	if st, ok := s.runs.get(id); ok {
		writeJSON(w, http.StatusOK, st.wire())
		return
	}
	st, found, err := summarizeOnDisk(s.cfg.LogDir, id)
	if err != nil {
		s.logger.Error("run ledger read failed", "run", id, "err", err)
		http.Error(w, "run ledger unreadable", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// listRuns is the hosted table plus every run log under LogDir, skipping
// exactly what investigate.Timeline skips: the control ledger, its torn
// fragments, and anything that is not a run log.
func (s *Server) listRuns(w http.ResponseWriter, _ *http.Request, _ identity.Invoker, _ string) {
	status := map[string]string{}
	for _, st := range s.runs.snapshot() {
		status[st.id] = st.status
	}
	entries, err := os.ReadDir(s.cfg.LogDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.logger.Error("log dir unreadable", "err", err)
		http.Error(w, "log directory unreadable", http.StatusInternalServerError)
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || name == "control.jsonl" || strings.Contains(name, ".torn-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		id := strings.TrimSuffix(name, ".jsonl")
		if _, hosted := status[id]; hosted || !runIDPattern.MatchString(id) {
			continue
		}
		st, found, err := summarizeOnDisk(s.cfg.LogDir, id)
		if err != nil {
			s.logger.Warn("run ledger unreadable; omitted from the listing", "run", id, "err", err)
			continue
		}
		if found {
			status[id] = st.Status
		}
	}
	out := apiclient.RunList{Runs: make([]apiclient.RunSummary, 0, len(status))}
	for _, id := range sortedKeys(status) {
		out.Runs = append(out.Runs, apiclient.RunSummary{RunID: id, Status: status[id]})
	}
	writeJSON(w, http.StatusOK, out)
}

// cancelRun cancels a hosted, running run's context; the engine records
// cancelled at or after the current step. 404 for a run not hosted here
// (an on-disk run has nothing to cancel), 409 for one already over.
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	id, ok := runID(w, r)
	if !ok {
		return
	}
	st, found, running := s.runs.cancelRun(id)
	switch {
	case !found:
		http.Error(w, "run not hosted here", http.StatusNotFound)
	case !running:
		http.Error(w, "run is not running", http.StatusConflict)
	default:
		s.logger.Info("run cancel requested", "run", id)
		writeJSON(w, http.StatusAccepted, st.wire())
	}
}

// startRun is replaced by the next task: POST /v1/runs.
func (s *Server) startRun(w http.ResponseWriter, _ *http.Request, _ identity.Invoker, _ string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
