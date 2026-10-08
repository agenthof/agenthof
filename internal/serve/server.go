// Package serve hosts governed runs behind an authenticated HTTP API:
// every request except GET /healthz carries a bearer verified per call;
// a run executes in a goroutine under the server's own context (a client
// hanging up never cancels a run); and the two ledgers are read back over
// the same API. It is a control surface over the existing doors — no new
// door, no new containment claim.
package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
)

// Authenticator verifies one bearer per call. identity.CachedOIDC is the
// production implementation.
type Authenticator interface {
	Authenticate(ctx context.Context, rawToken string) (identity.Invoker, error)
}

// RunHost is what serve needs from the process hosting it. Prepare
// resolves the configuration for one run — the INSTALLED snapshot beside
// the control ledger, loaded in full and validated — exactly as `agenthof
// run` does, bound to the invoker's verified token for on-behalf-of
// exchange. It is read per run, so an apply or a kill-switch flip takes
// effect on the next run with no restart. A load or validation failure
// wraps ErrConfigInvalid; nothing installed is ErrNoConfigInstalled;
// anything else is the host's own failure.
type RunHost interface {
	Prepare(inv identity.Invoker, subjectToken string) (Prepared, error)
}

// Prepared is one run's resolved config and dependencies.
type Prepared interface {
	// Admit is the pre-run gate: the host's own checks (an on-behalf-of
	// workflow needs a verified token) and then engine.Admit. It returns
	// the reason to record and false on refusal.
	Admit(role, workflow string, inv identity.Invoker) (reason string, ok bool)
	// Run executes the run under runID with origin stamped, blocking until
	// it is over. ctx is the run's context: cancel it to cancel the run.
	Run(ctx context.Context, runID, role, workflow, input string, inv identity.Invoker, origin *engine.Origin) (engine.Result, error)
}

// ConfigHost is what serve needs to apply a configuration: the same apply
// the CLI runs, over the control root this process serves, serialized by
// the host against every other writer (its store-level writer lock). Apply
// returns an outcome, never an error: every failure is a recorded (or
// deliberately unrecorded) outcome with an HTTP status of its own. via is
// the request channel's account of itself (origin), which the host records
// on the control event.
type ConfigHost interface {
	Apply(inv identity.Invoker, files map[string][]byte, pre apiclient.Precondition, via *engine.Origin) apiclient.ApplyResult
}

// ErrConfigInvalid marks a Prepare failure that is the configuration's:
// the run is refused (recorded, 422) with "configuration invalid: <first
// error>", the same text the CLI ledgers.
var ErrConfigInvalid = errors.New("configuration invalid")

// ErrNoConfigInstalled marks a Prepare that found nothing installed under
// the control root: the run is refused (recorded, 422) with the fixed
// reason "no configuration installed", the same text the CLI ledgers.
var ErrNoConfigInstalled = errors.New("no configuration installed")

// Config is everything a Server needs. MaxConcurrentRuns is required —
// there is no unbounded default.
type Config struct {
	Auth Authenticator
	Host RunHost
	// Config applies configurations; required, like Host.
	Config     ConfigHost
	LogDir     string
	ControlLog string
	// MaxConcurrentRuns caps runs in flight; a POST beyond it answers 429.
	MaxConcurrentRuns int
	// ServerHost is the host:port the server answers on, recorded as
	// Origin.ServerHost on every run it starts.
	ServerHost string
	Logger     *slog.Logger
}

// Server is the API over one log directory and one control ledger.
type Server struct {
	cfg    Config
	logger *slog.Logger
	// base is the context every run derives from — never a request's.
	base   context.Context
	cancel context.CancelFunc
	runs   *runTable
	slots  chan struct{}
	mux    *http.ServeMux

	// lifecycle orders reserve() against Shutdown: a run either starts
	// before the drain (and is cancelled with the rest) or sees it.
	lifecycle sync.RWMutex
	draining  bool
	wg        sync.WaitGroup

	// applyMu admits one API apply at a time: a second is answered 409 at
	// once instead of parking a handler goroutine on the host's writer lock
	// for its timeout. It covers only this process; the host's lock covers
	// every writer.
	applyMu sync.Mutex
}

// New validates cfg and builds the server; call Handler to serve it.
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil || cfg.Host == nil || cfg.Config == nil {
		return nil, errors.New("serve: Auth, Host and Config are required")
	}
	if cfg.LogDir == "" {
		return nil, errors.New("serve: LogDir is required")
	}
	if cfg.MaxConcurrentRuns <= 0 {
		return nil, errors.New("serve: MaxConcurrentRuns must be positive; there is no unbounded default")
	}
	base, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg: cfg, logger: obs.OrDiscard(cfg.Logger), base: base, cancel: cancel,
		runs: newRunTable(), slots: make(chan struct{}, cfg.MaxConcurrentRuns), mux: http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("POST /v1/runs", s.authed(s.startRun))
	s.mux.HandleFunc("GET /v1/runs", s.authed(s.listRuns))
	s.mux.HandleFunc("GET /v1/runs/{id}", s.authed(s.getRun))
	s.mux.HandleFunc("GET /v1/runs/{id}/events", s.authed(s.getEvents))
	s.mux.HandleFunc("GET /v1/runs/{id}/audit", s.authed(s.getAudit))
	s.mux.HandleFunc("POST /v1/runs/{id}/cancel", s.authed(s.cancelRun))
	s.mux.HandleFunc("GET /v1/investigate", s.authed(s.investigate))
	s.mux.HandleFunc("POST /v1/config/apply", s.authed(s.applyConfig))
}

// Handler is the server's HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// healthz is the one unauthenticated route: liveness, and nothing else —
// no version, no counts, no paths.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

// admit registers one unit of work with the WaitGroup, or says the server
// is draining. The returned release is safe to call once from any path.
// Shutdown waits for every admitted unit — a run, or an apply, whose
// install-then-record window the drain deadline must not cut.
func (s *Server) admit() (release func(), ok bool) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.draining {
		return nil, false
	}
	s.wg.Add(1)
	var once sync.Once
	return func() { once.Do(s.wg.Done) }, true
}

// reserve is admit plus a run slot: 503 while draining, 429 when every slot
// is held. The returned release gives both back; it is safe to call once
// from whichever path ends the run — a failed POST or the finished
// goroutine.
func (s *Server) reserve() (release func(), code int) {
	done, ok := s.admit()
	if !ok {
		return nil, http.StatusServiceUnavailable
	}
	select {
	case s.slots <- struct{}{}:
	default:
		done()
		return nil, http.StatusTooManyRequests
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-s.slots
			done()
		})
	}, 0
}

// Shutdown stops accepting new work (POST /v1/runs and POST /v1/config/apply
// answer 503), keeps serving reads, cancels every in-flight run, and waits
// for every admitted unit of work — runs and applies — until ctx ends.
// A deadline shorter than the step timeout can return while a step is
// still finishing; the caller decides what that is worth.
func (s *Server) Shutdown(ctx context.Context) error {
	s.lifecycle.Lock()
	s.draining = true
	s.lifecycle.Unlock()
	s.cancel()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("serve: shutdown deadline passed with work still in flight: %w", ctx.Err())
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
