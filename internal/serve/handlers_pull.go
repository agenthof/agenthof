package serve

import (
	"net/http"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/identity"
)

// getConfig is GET /v1/config: the installed configuration for
// distribution — hash, the control ledger's version and time of the
// install, and the files.
func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request, inv identity.Invoker, _ string) {
	s.answerPull(w, inv, true)
}

// getConfigHash is GET /v1/config/hash: the same answer without the files
// — the poll. It runs the same Pull (the same authorization, the same
// verify, the same ledger vouching), so it never names a hash the full
// pull would then refuse to serve.
func (s *Server) getConfigHash(w http.ResponseWriter, _ *http.Request, inv identity.Invoker, _ string) {
	s.answerPull(w, inv, false)
}

// answerPull is the read handler's discipline, not the writer's: the
// bearer was verified before this ran; the host's Pull is not bound to the
// request context (a client hanging up must not interrupt a ledger scan
// holding a lock); there is no drain gate — a pull is a read and is served
// while the server drains, like every read; and nothing is recorded on any
// outcome. Non-200 answers are fixed text bodies, never a path and never
// the OS text; one log line at most — the 500s log nothing here, since the
// host already logged the cause; the hash poll's 200 logs nothing at all;
// the full pull's 200 names the signing key when signed, never the
// signature.
func (s *Server) answerPull(w http.ResponseWriter, inv identity.Invoker, withFiles bool) {
	res := s.cfg.Config.Pull(inv)
	switch res.Status {
	case PullOK:
		snap := res.Snapshot
		if withFiles {
			attrs := []any{"invoker", inv.Subject, "hash", snap.Hash, "version", snap.Version}
			if snap.Signature != nil {
				attrs = append(attrs, "key_id", snap.Signature.KeyID)
			}
			s.logger.Info("config pulled", attrs...)
		} else {
			snap.Files = nil
		}
		w.Header().Set("ETag", `"`+snap.Hash+`"`)
		writeJSON(w, http.StatusOK, snap)
	case PullNothingInstalled:
		s.logger.Warn("config pull", "invoker", inv.Subject, "status", res.Status)
		http.Error(w, ErrNoConfigInstalled.Error(), http.StatusNotFound)
	case PullRefused:
		s.logger.Warn("config pull refused", "invoker", inv.Subject)
		http.Error(w, apiclient.PullBodyRefused, http.StatusForbidden)
	case PullNotBundleable:
		http.Error(w, apiclient.PullBodyNotBundleable, http.StatusInternalServerError)
	case PullLedgerDamaged:
		http.Error(w, apiclient.ReasonLedgerDamaged, http.StatusInternalServerError)
	case PullBusy:
		s.logger.Info("config pull", "invoker", inv.Subject, "status", res.Status)
		w.Header().Set("Retry-After", "1")
		http.Error(w, apiclient.PullBodyBusy, http.StatusServiceUnavailable)
	case PullNotRecorded:
		s.logger.Info("config pull", "invoker", inv.Subject, "status", res.Status)
		w.Header().Set("Retry-After", "1")
		http.Error(w, apiclient.PullBodyNotRecorded, http.StatusServiceUnavailable)
	case PullNotSigned:
		// Retryable like not-on-record, with its own body so an edge's error
		// names the right remedy (config sign, not re-apply). The host logs
		// the cause at the level it deserves; this line is the status only.
		s.logger.Info("config pull", "invoker", inv.Subject, "status", res.Status)
		w.Header().Set("Retry-After", "1")
		http.Error(w, apiclient.PullBodyNotSigned, http.StatusServiceUnavailable)
	default:
		// PullStoreUnusable, and any status this handler does not know:
		// fail closed with the fixed store body.
		http.Error(w, apiclient.ReasonStoreUnusable, http.StatusInternalServerError)
	}
}
