package serve

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/agenthof/agenthof/internal/identity"
)

// authedHandler is a handler that runs only for a verified invoker. token
// is the raw bearer, handed on for on-behalf-of exchange and nothing else
// — never logged, never ledgered.
type authedHandler func(w http.ResponseWriter, r *http.Request, inv identity.Invoker, token string)

// authed verifies the bearer FIRST: an unauthenticated request does no
// work and no write. The 401 body is fixed — the verifier's error can echo
// unverified claims — and nothing is ledgered: a run_refused is written
// only for an authenticated invoker's policy refusal. A provider outage is
// 503, the token was never judged.
func (s *Server) authed(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			s.logger.Warn("request rejected", "reason", "no bearer", "path", r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inv, err := s.cfg.Auth.Authenticate(r.Context(), raw)
		if err != nil {
			if errors.Is(err, identity.ErrProviderUnavailable) {
				s.logger.Error("identity provider unavailable", "path", r.URL.Path)
				http.Error(w, "identity provider unavailable", http.StatusServiceUnavailable)
				return
			}
			s.logger.Warn("request rejected", "reason", "token verification failed", "path", r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, inv, raw)
	}
}

// bearer extracts the token from an Authorization header.
func bearer(h string) (string, bool) {
	scheme, tok, ok := strings.Cut(h, " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}

// runIDPattern is what a run id looks like. The {id} wildcard is matched
// unescaped, so without this check "%2e%2e" would reach ReadLog's
// filesystem join; nothing touches the disk before it.
var runIDPattern = regexp.MustCompile(`^r-[0-9a-f]+$`)

func runID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !runIDPattern.MatchString(id) {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return "", false
	}
	return id, true
}
