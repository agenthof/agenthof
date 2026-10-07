package serve

import (
	"net/http"

	"github.com/agenthof/agenthof/internal/identity"
)

// The ledger read-back routes are replaced wholesale by a later task. The
// id check runs first, so a traversal attempt is already a 400 and nothing
// reaches a filesystem join.
func (s *Server) getEvents(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	if _, ok := runID(w, r); !ok {
		return
	}
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request, _ identity.Invoker, _ string) {
	if _, ok := runID(w, r); !ok {
		return
	}
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) investigate(w http.ResponseWriter, _ *http.Request, _ identity.Invoker, _ string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
