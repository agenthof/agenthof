package serve

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
)

// integrityOf classifies a ledger verdict for the API. A torn tail on a
// run this process is still writing is in_flight — a record caught
// mid-write, which the next read will see whole — never damage; a torn
// tail anywhere else is torn, and a broken chain is broken wherever it is
// found, with its 1-based line.
func (s *Server) integrityOf(id string, verr error) (string, int) {
	if verr == nil {
		return apiclient.IntegrityVerified, 0
	}
	var te *ledger.TornError
	var be *ledger.ChainBrokenError
	switch {
	case errors.As(verr, &be):
		return apiclient.IntegrityBroken, be.Line
	case errors.As(verr, &te):
		if st, ok := s.runs.get(id); ok && st.status == apiclient.StatusRunning {
			return apiclient.IntegrityInFlight, 0
		}
		return apiclient.IntegrityTorn, 0
	}
	return apiclient.IntegrityBroken, 0
}

// getEvents is the run ledger as the API reads it: the verified prefix,
// its head, and the verdict.
func (s *Server) getEvents(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	id, ok := runID(w, r)
	if !ok {
		return
	}
	events, head, verr, found, err := readLedger(s.cfg.LogDir, id)
	if err != nil {
		s.logger.Error("run ledger read failed", "run", id, "err", err)
		http.Error(w, "run ledger unreadable", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if events == nil {
		events = []engine.Event{} // "events": [] — never null
	}
	integrity, line := s.integrityOf(id, verr)
	writeJSON(w, http.StatusOK, apiclient.RunEvents{Events: events, Head: apiclient.Head{Hash: head.Hash, Count: head.Count}, Integrity: integrity, BrokenLine: line})
}

// getAudit is `agenthof audit <run-id>` rendered here, where both ledgers
// are: the run's trail and the control-plane line naming the apply that
// put its config in place. The verdict rides in a header so a client can
// exit as the local command does.
func (s *Server) getAudit(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	id, ok := runID(w, r)
	if !ok {
		return
	}
	events, head, verr, found, err := readLedger(s.cfg.LogDir, id)
	if err != nil {
		s.logger.Error("run ledger read failed", "run", id, "err", err)
		http.Error(w, "run ledger unreadable", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	var sb strings.Builder
	sb.WriteString(audit.Render(events, head, verr))
	for _, e := range events {
		if e.Type == "workflow_started" && e.ConfigHash != "" {
			cev, verdict, _ := investigate.LoadControl(s.cfg.ControlLog)
			sb.WriteString(investigate.ConfigJoin(cev, verdict, e.ConfigHash, e.Time))
			sb.WriteString("\n")
			break
		}
	}
	integrity, _ := s.integrityOf(id, verr)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set(apiclient.IntegrityHeader, integrity)
	_, _ = w.Write([]byte(sb.String()))
}

// investigate is `agenthof investigate --json` over both ledgers. since
// and until are RFC3339 only; the client resolves durations.
func (s *Server) investigate(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	q := apiclient.InvestigateQueryFrom(r.URL.Query())
	f := investigate.Filter{Invoker: q.Invoker, Agent: q.Agent, Outcome: q.Outcome, Run: q.Run, ConfigHash: q.ConfigHash}
	if q.Since != "" {
		t, err := time.Parse(time.RFC3339, q.Since)
		if err != nil {
			http.Error(w, "since must be RFC3339", http.StatusBadRequest)
			return
		}
		t = t.UTC()
		f.Since = &t
	}
	if q.Until != "" {
		t, err := time.Parse(time.RFC3339, q.Until)
		if err != nil {
			http.Error(w, "until must be RFC3339", http.StatusBadRequest)
			return
		}
		t = t.UTC()
		f.Until = &t
	}
	res, err := investigate.Timeline(s.cfg.LogDir, s.cfg.ControlLog, f)
	if err != nil {
		s.logger.Error("investigate failed", "err", err)
		http.Error(w, "investigation failed", http.StatusInternalServerError)
		return
	}
	doc, err := investigate.RenderJSON(res, f)
	if err != nil {
		s.logger.Error("investigate render failed", "err", err)
		http.Error(w, "investigation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(doc))
}
