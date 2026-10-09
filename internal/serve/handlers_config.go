package serve

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/origin"
)

// ifMatchPattern is the only If-Match value honored: the installed
// pointer's own grammar, lowercase hex. Uppercase is a 400 that says so.
var ifMatchPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// applyConfig is POST /v1/config/apply. Order is the point: the bearer was
// verified before this ran; the request is admitted (503 while draining)
// and the WaitGroup given back on EVERY exit, 400/413/409 included; the
// body is read whole under the cap, checked for valid UTF-8 before any
// decode (encoding/json would otherwise coerce bad bytes to U+FFFD and the
// server would stage bytes the client never sent), decoded, and the bundle
// and precondition validated — all without a control event, since a
// malformed request is not a governance decision; then one apply at a time
// (409 otherwise) runs the host's applyConfig, unbound from the request
// context (a client hanging up never interrupts an install), and the answer
// follows from the outcome's status.
func (s *Server) applyConfig(w http.ResponseWriter, r *http.Request, inv identity.Invoker, _ string) {
	release, ok := s.admit()
	if !ok {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}
	defer release()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, apiclient.MaxApplyBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	if !utf8.Valid(body) {
		http.Error(w, "request body is not valid UTF-8", http.StatusBadRequest)
		return
	}
	var req apiclient.ApplyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	files, problem := bundleFrom(req)
	if problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}
	pre, problem := preconditionFrom(r.Header)
	if problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}

	if !s.applyMu.TryLock() {
		answerBusy(w)
		return
	}
	defer s.applyMu.Unlock()

	via := originFrom(r, s.cfg.ServerHost)
	res := s.cfg.Config.Apply(inv, files, pre, via)
	s.answerApply(w, inv, res)
}

// bundleFrom validates the bundle: present and non-empty, at most
// MaxBundleFiles entries, every key a path config.ValidBundlePath accepts.
// The first problem is named; a key is attacker-controlled and echoed into
// an HTTP body, so it is cleaned the way every origin field is (printable,
// capped) — it never reaches a ledger or a log. Keys are checked in sorted
// order so the named problem is deterministic.
func bundleFrom(req apiclient.ApplyRequest) (map[string][]byte, string) {
	if len(req.Files) == 0 {
		return nil, "files is required"
	}
	if len(req.Files) > apiclient.MaxBundleFiles {
		return nil, "too many files"
	}
	keys := make([]string, 0, len(req.Files))
	for rel := range req.Files {
		keys = append(keys, rel)
	}
	sort.Strings(keys)
	files := make(map[string][]byte, len(keys))
	for _, rel := range keys {
		if !config.ValidBundlePath(rel) {
			return nil, "invalid config path: " + origin.Clean(rel)
		}
		files[rel] = []byte(req.Files[rel])
	}
	return files, ""
}

// preconditionFrom parses exactly one of If-Match: sha256:<hex> (optionally
// quoted, as an entity-tag) and If-None-Match: * (RFC 9110's create-only
// idiom). A weak validator, a list, "*" on If-Match, uppercase hex or any
// other shape is a 400 whose text says what was expected.
func preconditionFrom(h http.Header) (apiclient.Precondition, string) {
	im, inm := h.Values("If-Match"), h.Values("If-None-Match")
	switch {
	case len(im) == 0 && len(inm) == 0, len(im) > 0 && len(inm) > 0:
		return apiclient.Precondition{}, "exactly one of If-Match and If-None-Match is required"
	case len(inm) > 0:
		if len(inm) != 1 || strings.TrimSpace(inm[0]) != "*" {
			return apiclient.Precondition{}, "If-None-Match must be *"
		}
		return apiclient.Precondition{ExpectNone: true}, ""
	}
	v := strings.TrimSpace(im[0])
	if len(im) == 1 && len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if len(im) != 1 || !ifMatchPattern.MatchString(v) {
		return apiclient.Precondition{}, "If-Match must be a single sha256: followed by 64 lowercase hex digits"
	}
	return apiclient.Precondition{ExpectInstalled: v}, ""
}

// answerBusy is every 409: the same JSON body whether this handler's
// TryLock or the host's writer-lock timeout produced it, so the client
// decodes one shape.
func answerBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusConflict, apiclient.ApplyResult{Status: apiclient.ApplyBusy})
}

// answerApply maps an outcome to its status, headers and fixed 500 bodies,
// logs one line (never the token, never the body), and writes the JSON.
func (s *Server) answerApply(w http.ResponseWriter, inv identity.Invoker, res apiclient.ApplyResult) {
	code := http.StatusInternalServerError
	switch res.Status {
	case apiclient.ApplyInstalled:
		code = http.StatusOK
		w.Header().Set("ETag", `"`+res.ConfigHash+`"`)
	case apiclient.ApplyRefused:
		code = http.StatusForbidden
	case apiclient.ApplyPreconditionFailed:
		code = http.StatusPreconditionFailed
		if res.CurrentHash != "" {
			w.Header().Set("ETag", `"`+res.CurrentHash+`"`)
		}
	case apiclient.ApplyRejected:
		code = http.StatusUnprocessableEntity
	case apiclient.ApplyBusy:
		s.logger.Info("config apply", "invoker", inv.Subject, "status", res.Status)
		answerBusy(w)
		return
	case apiclient.ApplyError:
		// The recorded reason can name store paths; the operator who has
		// the host reads it in the ledger and the log, never a client.
		if res.Head == nil {
			res.Reason = apiclient.ReasonNotRecorded
		} else {
			res.Reason = apiclient.ReasonStoreUnusable
		}
	case apiclient.ApplyLedgerDamaged:
		res.Reason = apiclient.ReasonLedgerDamaged
	case apiclient.ApplyInstalledNotRecorded, apiclient.ApplyInstalledNotSigned:
		// the counts, hash and head are known: the install landed and was
		// recorded; only the server's own follow-up failed
	default:
		res = apiclient.ApplyResult{Status: apiclient.ApplyError, Reason: apiclient.ReasonStoreUnusable}
	}
	if code == http.StatusOK || code == http.StatusPreconditionFailed {
		s.logger.Info("config apply", "invoker", inv.Subject, "status", res.Status, "config_hash", res.ConfigHash)
	} else {
		s.logger.Warn("config apply", "invoker", inv.Subject, "status", res.Status, "config_hash", res.ConfigHash)
	}
	writeJSON(w, code, res)
}
