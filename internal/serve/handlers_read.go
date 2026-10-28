package serve

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/completeness"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/sidecar"
)

// completenessOf refines a run's own completeness verdict for the API: an
// unterminated ledger on a run this process is still running is in_flight.
func (s *Server) completenessOf(id string, rep completeness.Report) string {
	if rep.Verdict == completeness.Unterminated {
		if st, ok := s.runs.get(id); ok && st.status == apiclient.StatusRunning {
			return apiclient.CompletenessInFlight
		}
	}
	return rep.Verdict
}

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

// anchorOf is a run's anchor state as the read routes report it, and the
// first cause it is not verified. Offline under the server's own pin
// (the anchor.pub beside its ledger, resolved per request): a read route never
// asks the log and never submits. A run whose own chain failed has nothing a
// sidecar can be checked against and reports none (""). The unpinned or
// undecidable case is unverifiable, never tampering, and never as-served —
// that is a networked state of `audit verify`.
func (s *Server) anchorOf(id string, verr error) (state, detail string) {
	if verr != nil {
		return "", ""
	}
	v, _ := sidecar.VerifyRun(s.cfg.LogDir, id, s.cfg.Investigate.AnchorKey, s.cfg.Investigate.AnchorBackend, true, 0)
	return v.State(), anchorCause(v)
}

// anchorCause is the cause behind v's folded state: the first record in that
// state (so a mismatch names its own cause, not an earlier unverifiable
// one), or the sidecar's own fault. "" for verified and not anchored. Cleaned
// like every string that came from a sidecar, a ledger or a backend.
func anchorCause(v sidecar.Verdict) string {
	switch state := v.State(); state {
	case sidecar.StateVerified, sidecar.StateNotAnchored:
		return ""
	case sidecar.StateUnverifiable:
		if v.Err != nil {
			return origin.Clean(v.Err.Error())
		}
		if len(v.Results) == 0 {
			return "the sidecar holds no records"
		}
		fallthrough
	default:
		for _, r := range v.Results {
			if string(r.State) == state {
				return origin.Clean(r.Cause)
			}
		}
	}
	return ""
}

// treeAnchor is the worst anchor state across a run and its verified
// descendants — mismatch, then unverifiable, else the run's own word — the
// ranking `audit <run-id>` exits on.
func treeAnchor(t sidecar.TreeVerdicts) string {
	worst := t.Root.State()
	for _, c := range t.Children {
		switch c.State() {
		case sidecar.StateMismatch:
			return sidecar.StateMismatch
		case sidecar.StateUnverifiable:
			if worst != sidecar.StateMismatch {
				worst = sidecar.StateUnverifiable
			}
		}
	}
	return worst
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
	var comp completeness.Report
	if verr == nil {
		comp = completeness.Check(events)
	}
	anchorState, anchorDetail := s.anchorOf(id, verr)
	writeJSON(w, http.StatusOK, apiclient.RunEvents{
		Events:             events,
		Head:               apiclient.Head{Hash: head.Hash, Count: head.Count},
		Integrity:          integrity,
		BrokenLine:         line,
		Completeness:       s.completenessOf(id, comp),
		CompletenessDetail: comp.Detail,
		Anchor:             anchorState,
		AnchorDetail:       anchorDetail,
	})
}

// getAudit is `agenthof audit <run-id>` rendered here, where both ledgers
// are: the run's trail and the control-plane line naming the apply that
// put its config in place. Both verdicts ride in headers so a client can
// exit as the local command does; the integrity header reports a
// descendant's torn or broken chain too, the completeness header the
// tree's worst.
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
	tree := completeness.VerifyTree(s.cfg.LogDir, id, events, verr)
	var sb strings.Builder
	// The anchor is read exactly as `audit <run-id>` reads it: offline under
	// the server's own pin (the anchor.pub beside its ledger, resolved per
	// request) — the log is never asked — and by the same renderer, so the
	// text here is the text the local command prints.
	anchors := sidecar.VerifyTree(s.cfg.LogDir, id, tree, verr == nil, s.cfg.Investigate.AnchorKey, s.cfg.Investigate.AnchorBackend, true, 0)
	anchorLine := ""
	if verr == nil {
		anchorLine = sidecar.Lines(anchors.Root, sidecar.RenderOptions{Pinned: anchors.Pinned, Offline: true, OfflineOnly: true, RunID: id})
	}
	sb.WriteString(audit.Render(events, head, verr, tree.Root.Report, anchorLine))
	sb.WriteString(tree.SubtreeLinesWith(anchors.Suffix))
	for _, e := range events {
		if e.Type == "workflow_started" && e.ConfigHash != "" {
			cev, verdict, _ := investigate.LoadControl(s.cfg.ControlLog)
			sb.WriteString(investigate.ConfigJoin(cev, verdict, e.ConfigHash, e.Time))
			sb.WriteString("\n")
			break
		}
	}
	integrity, _ := s.integrityOf(id, verr)
	if word := tree.ChildIntegrityFailure(); word != "" && verr == nil {
		// A descendant's torn or broken chain: the local command exits 1 on
		// it, so the client must too. A child that cannot be read at all
		// says `error` in the subtree text; the header keeps its closed
		// enum and reads broken, as integrityOf does for the run's own
		// unreadable chain.
		integrity = word
		if word != apiclient.IntegrityTorn && word != apiclient.IntegrityBroken {
			integrity = apiclient.IntegrityBroken
		}
	}
	comp := s.completenessOf(id, tree.Root.Report)
	switch tree.ChildCompletenessWorst() {
	case completeness.Gap:
		comp = completeness.Gap
	case completeness.Unterminated:
		if comp != completeness.Gap {
			comp = completeness.Unterminated
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set(apiclient.IntegrityHeader, integrity)
	if comp != "" {
		w.Header().Set(apiclient.CompletenessHeader, comp)
	}
	if verr == nil {
		// The tree-worst, from the verdicts the text above was rendered from.
		w.Header().Set(apiclient.AnchorHeader, treeAnchor(anchors))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// investigate is `agenthof investigate --json` over both ledgers. since
// and until are RFC3339 only; the client resolves durations. Every success
// anchor record carries its offline verdict under the anchor.pub beside the
// server's ledger — the API carries no key parameter — the pin is the server's
// own anchor.pub, read on each request.
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
	res, err := investigate.Timeline(s.cfg.LogDir, s.cfg.ControlLog, f, s.cfg.Investigate)
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
