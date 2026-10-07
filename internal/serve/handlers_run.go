package serve

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/engine"
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
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request, inv identity.Invoker, _ string) {
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
		s.logger.Info("run cancel requested", "run", id, "invoker", inv.Subject)
		writeJSON(w, http.StatusAccepted, st.wire())
	}
}

// maxRunBody caps POST /v1/runs' body: role, workflow and an input.
const maxRunBody = 1 << 20

// maxNameLen caps a role/workflow name from an untrusted request.
const maxNameLen = 200

// validName reports whether a role/workflow name is safe to record and
// render: non-empty, at most maxNameLen runes, every rune printable.
func validName(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > maxNameLen {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// startRun is POST /v1/runs. Order is the point: the bearer was verified
// before this ran; a slot is reserved BEFORE the body is read or the
// config loaded, so an authenticated caller cannot hammer LoadDir outside
// the cap; then the config resolves, the host's gate and engine.Admit
// decide synchronously (a refusal is recorded and answered 403/422 here,
// not after a 202), and only then is a run id minted and the engine
// started — in a goroutine, under the SERVER's context, so the client
// hanging up never cancels the run.
func (s *Server) startRun(w http.ResponseWriter, r *http.Request, inv identity.Invoker, token string) {
	release, code := s.reserve()
	if code != 0 {
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many concurrent runs", code)
			return
		}
		http.Error(w, "server is shutting down", code)
		return
	}
	started := false
	defer func() {
		if !started {
			release()
		}
	}()

	var req apiclient.RunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRunBody)).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	// role and workflow are attacker-controlled strings that land in the
	// run's Binding and are printed verbatim by audit.Render; a crafted name
	// (terminal escapes, megabyte padding) must never reach the ledger or a
	// reader's terminal. Registry names are identifiers, so a non-empty,
	// printable, capped name is the whole contract — reject anything else
	// here, before Prepare, with no run recorded.
	if !validName(req.Role) || !validName(req.Workflow) {
		http.Error(w, "role and workflow must be non-empty printable names", http.StatusBadRequest)
		return
	}
	if req.Input == "" {
		http.Error(w, "input is required", http.StatusBadRequest)
		return
	}
	origin := originFrom(r, s.cfg.ServerHost)

	prep, err := s.cfg.Host.Prepare(inv, token)
	if err != nil {
		if errors.Is(err, ErrConfigInvalid) {
			s.refuse(w, inv, req, origin, err.Error(), "configuration invalid", http.StatusUnprocessableEntity)
			return
		}
		if errors.Is(err, ErrNoConfigInstalled) {
			// The configuration is the problem, not the caller: 422 like
			// "configuration invalid", after auth and the slot reservation.
			s.refuse(w, inv, req, origin, ErrNoConfigInstalled.Error(), ErrNoConfigInstalled.Error(), http.StatusUnprocessableEntity)
			return
		}
		s.logger.Error("run preparation failed", "err", err)
		http.Error(w, "run could not be prepared", http.StatusInternalServerError)
		return
	}
	if reason, ok := prep.Admit(req.Role, req.Workflow, inv); !ok {
		s.refuse(w, inv, req, origin, reason, reason, http.StatusForbidden)
		return
	}

	runCtx, cancel := context.WithCancel(s.base)
	id, err := s.runs.mint(s.cfg.LogDir, cancel, time.Now().UTC())
	if err != nil {
		cancel()
		s.logger.Error("run id mint failed", "err", err)
		http.Error(w, "could not mint a run id", http.StatusInternalServerError)
		return
	}
	started = true
	logger := s.logger.With("run", id, "role", req.Role, "workflow", req.Workflow)
	logger.Info("run accepted", "invoker", inv.Subject)
	go func() {
		defer release()
		defer cancel()
		// A panic in the run (adapter, gateway, supervisor) must not take
		// the server and every other in-flight run down with it: recover,
		// record the run failed, and let this goroutine unwind cleanly.
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("run panicked", "panic", rec)
				s.runs.finish(id, engine.Result{RunID: id, Status: "failed"}, "run error", time.Now().UTC())
			}
		}()
		res, err := prep.Run(runCtx, id, req.Role, req.Workflow, req.Input, inv, origin)
		s.runs.finish(id, res, finishReason(s.cfg.LogDir, id, res, err), time.Now().UTC())
		logger.Info("run finished", "status", res.Status)
	}()
	w.Header().Set("Location", "/v1/runs/"+id)
	writeJSON(w, http.StatusAccepted, apiclient.RunAccepted{RunID: id, Status: apiclient.StatusRunning})
}

// refuse records an authenticated invoker's policy refusal — the same
// run_refused event the CLI writes, plus origin — and answers with the
// reason the client prints. ledgerReason and bodyReason differ only for an
// invalid config: the ledger keeps the first error, the body the fixed
// "configuration invalid" the CLI prints.
func (s *Server) refuse(w http.ResponseWriter, inv identity.Invoker, req apiclient.RunRequest, origin *engine.Origin, ledgerReason, bodyReason string, code int) {
	id, err := engine.RecordRefused(engine.Options{LogDir: s.cfg.LogDir, Origin: origin}, inv, req.Role, req.Workflow, ledgerReason)
	if err != nil {
		s.logger.Error("refusal record failed", "err", err)
		http.Error(w, "refusal could not be recorded", http.StatusInternalServerError)
		return
	}
	s.logger.Warn("run refused", "run", id, "role", req.Role, "workflow", req.Workflow, "reason", ledgerReason)
	writeJSON(w, code, apiclient.RunAccepted{RunID: id, Status: apiclient.StatusRefused, Reason: bodyReason})
}

// originFrom is the request channel's account of itself. Every field is
// capped and stripped by the engine before it is written; forwarded_for is
// recorded verbatim and is unverified.
func originFrom(r *http.Request, serverHost string) *engine.Origin {
	return &engine.Origin{
		Via:          "api",
		RemoteAddr:   r.RemoteAddr,
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.UserAgent(),
		ServerHost:   serverHost,
	}
}

// finishReason is what the status view says about a finished run. A
// recorded refusal's reason is the engine's own; an engine error carries a
// path and is replaced by a fixed word; a lost exclusive create (another
// process wrote this id first) is named; everything else reads the reason
// back from the ledger the run wrote.
func finishReason(logDir, id string, res engine.Result, err error) string {
	switch {
	case err == nil:
		return terminalReason(logDir, id)
	case res.Status == apiclient.StatusRefused && !errors.Is(err, engine.ErrLedgerWrite):
		return err.Error()
	case errors.Is(err, engine.ErrRunExists):
		return "run id collision"
	default:
		return "run error"
	}
}
