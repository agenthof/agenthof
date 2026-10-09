package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/refspawn"
	"github.com/agenthof/agenthof/internal/serve"
)

// cmdServe runs the control-plane API: governed runs over HTTP, every
// call authenticated with the invoker's OIDC token, both ledgers readable
// back, and the installed configuration pullable by the execution points
// it governs. ctx ending (SIGINT/SIGTERM from dispatch) starts a graceful
// shutdown: new runs and applies are refused, in-flight runs are cancelled
// and waited for — applies are waited for — up to --shutdown-timeout, then
// the listener closes.
func cmdServe(ctx context.Context, args []string, out, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address; a non-loopback address needs --allow-non-loopback")
	allowNonLoopback := fs.Bool("allow-non-loopback", false, "serve a non-loopback address (put TLS in front; see docs/reference/serve.md)")
	allowAPIBootstrap := fs.Bool("allow-api-bootstrap", false, "permit POST /v1/config/apply while nothing is installed (the first authenticated caller then owns the configuration); off, such an apply is a recorded refusal — bootstrap locally instead")
	addrFile := fs.String("addr-file", "", "after binding, write the actual host:port to this file (for a :0 port)")
	fs.String("config", "./config", "accepted for compatibility; runs execute the installed configuration beside --control-log")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	artifactDir := fs.String("artifact-dir", ".agenthof/artifacts", "artifact store directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it, per run, and the ledger itself for audit's config-join and investigate")
	maxRuns := fs.Int("max-concurrent-runs", 8, "runs in flight at once; further POST /v1/runs answer 429")
	shutdownTimeout := fs.Duration("shutdown-timeout", 0, "how long a graceful shutdown waits for in-flight runs (default: the config's step timeout)")
	logLevel := fs.String("log-level", "", "operational log level: debug|info|warn|error (default info; env "+envLogLevel+")")
	logFormat := fs.String("log-format", "", "operational log format: text|json (default text; env "+envLogFormat+")")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	level, format, err := resolveLogConfig(*logLevel, *logFormat, os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintf(out, "serve: %v\n", err)
		return 2
	}
	logger := obs.New(stderr, level, format)

	issuer := os.Getenv("AGENTHOF_OIDC_ISSUER")
	if issuer == "" {
		_, _ = fmt.Fprintln(out, "serve: AGENTHOF_OIDC_ISSUER must be set — serve authenticates every call with OIDC")
		return 2
	}
	if !*allowNonLoopback && !loopbackAddr(*addr) {
		_, _ = fmt.Fprintf(out, "serve: --addr %q is not loopback; pass --allow-non-loopback to serve it (and put TLS in front)\n", *addr)
		return 2
	}
	if *maxRuns <= 0 {
		_, _ = fmt.Fprintln(out, "serve: --max-concurrent-runs must be positive")
		return 2
	}
	if *shutdownTimeout == 0 {
		// The installed configuration is resolved per run; it is read once
		// here only for the step timeout the shutdown deadline should cover.
		// With nothing usable installed the zero GatewayConfig's default
		// applies, and serve says so once — it starts either way, because
		// apply is a separate command and every run is refused until one
		// lands. The timeout is read once: a later apply with a longer
		// step_timeout does not move this deadline (--shutdown-timeout does).
		cfg, _, _, installed, errs := resolveRunConfig(*controlLog)
		switch {
		case len(errs) > 0:
			logger.Warn("installed configuration unusable; every run will be refused until apply", "store", installedStore(*controlLog), "err", errs[0].Error())
			cfg = config.Config{}
		case !installed:
			logger.Warn("no configuration installed; every run will be refused until apply", "store", installedStore(*controlLog))
		}
		*shutdownTimeout = cfg.Gateway.EffectiveStepTimeout()
	}
	clientID := os.Getenv("AGENTHOF_OIDC_CLIENT_ID")
	if clientID == "" {
		clientID = "agenthof"
	}
	// The provider cache outlives every request and the shutdown itself:
	// reads keep being served while runs drain. An explicit client with a
	// timeout is required: nil falls back to http.DefaultClient, which has
	// none, so a black-holed issuer would park discovery — and every call
	// waiting on it — forever, and the base context deliberately does not
	// end with the shutdown.
	auth := identity.NewCachedOIDC(context.Background(), identity.OIDC{IssuerURL: issuer, ClientID: clientID,
		Audience: os.Getenv("AGENTHOF_OIDC_AUDIENCE"), HTTP: &http.Client{Timeout: 30 * time.Second}})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		_, _ = fmt.Fprintf(out, "serve: %v\n", err)
		return 1
	}
	host := &runHost{controlLog: *controlLog, logDir: *logDir, artifactDir: *artifactDir, logger: logger, broker: newBroker(subjectTokenTypeFromEnv(os.Getenv))}
	cfgHost := &configHost{controlLog: *controlLog, allowBootstrap: *allowAPIBootstrap, logger: logger}
	srv, err := serve.New(serve.Config{
		Auth: auth, Host: host, Config: cfgHost, LogDir: *logDir, ControlLog: *controlLog,
		MaxConcurrentRuns: *maxRuns, ServerHost: ln.Addr().String(), Logger: logger,
	})
	if err != nil {
		_ = ln.Close()
		_, _ = fmt.Fprintf(out, "serve: %v\n", err)
		return 1
	}
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()+"\n"), 0o600); err != nil {
			_ = ln.Close()
			_, _ = fmt.Fprintf(out, "serve: %v\n", err)
			return 1
		}
	}
	_, _ = fmt.Fprintf(out, "serving on %s\n", ln.Addr())
	logger.Info("serve started", "addr", ln.Addr().String(), "max_concurrent_runs", *maxRuns, "shutdown_timeout", shutdownTimeout.String())

	// ReadTimeout bounds the whole request read, not just headers: a slot is
	// reserved before the body is read, so without it an authenticated caller
	// could hold every slot by trickling (or never sending) a body — with no
	// ledger trace. The body is <= 1 MiB, so 30s is generous. IdleTimeout
	// reaps idle keep-alive connections.
	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	served := make(chan error, 1)
	go func() { served <- hs.Serve(ln) }()
	select {
	case <-ctx.Done():
		// The first signal cancelled ctx and begins the drain (up to
		// --shutdown-timeout). Restore the default disposition so a second
		// Ctrl-C / SIGTERM terminates immediately instead of being swallowed.
		signal.Reset(os.Interrupt, syscall.SIGTERM)
	case err := <-served:
		_, _ = fmt.Fprintf(out, "serve: %v\n", err)
		return 1
	}
	logger.Info("shutting down", "timeout", shutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		// A run cut off mid-step may have left its ledger without a final
		// event; the status view reports it as incomplete — honestly.
		logger.Warn("in-flight runs or applies did not finish before the deadline", "err", err)
	}
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		logger.Warn("listener shutdown", "err", err)
	}
	return 0
}

// loopbackAddr reports whether addr names a loopback host. The default
// bind is loopback; anything else is an explicit choice, because serve
// speaks plain HTTP and the operator owns TLS.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return loopbackHost(host)
}

// runHost is serve.RunHost over this process: the control root (whose
// installed snapshot every run executes), the ledger and artifact
// locations, one broker for the process, and the supervisor the config
// names. Prepare is `cmdRun`'s config sequence — resolveRunConfig, then the
// supervisor — bound to one invoker's token, resolved per run so an apply
// or a kill-switch flip takes effect on the next run with no restart.
type runHost struct {
	controlLog, logDir, artifactDir string
	logger                          *slog.Logger
	broker                          broker.Broker
}

func (h *runHost) Prepare(_ identity.Invoker, subjectToken string) (serve.Prepared, error) {
	cfg, reg, hash, installed, errs := resolveRunConfig(h.controlLog)
	if len(errs) > 0 {
		// Before the installed flag, as in cmdRun: a damaged install is
		// "configuration invalid", never "nothing installed".
		return nil, fmt.Errorf("%w: %s", serve.ErrConfigInvalid, errs[0].Error())
	}
	if !installed {
		return nil, serve.ErrNoConfigInstalled
	}
	var sup refspawn.Provisioner
	if ep := cfg.Gateway.SpawnSupervisor; ep != "" {
		client, err := refspawn.New(ep, h.logger)
		if err != nil {
			return nil, err
		}
		sup = client
	}
	return preparedRun{deps: newRunDeps(cfg, reg, h.broker, h.logger, h.logDir, h.artifactDir, hash, subjectToken, sup)}, nil
}

// preparedRun is one run's deps. Admit is cmdRun's gate in cmdRun's order:
// the on-behalf-of check, then the engine's registry gate.
type preparedRun struct{ deps *runDeps }

func (p preparedRun) Admit(role, workflow string, inv identity.Invoker) (string, bool) {
	if reason, refused := preRunRefusal(p.deps.cfg, p.deps.reg, workflow, inv); refused {
		return reason, false
	}
	return engine.Admit(p.deps.reg, role, workflow, inv)
}

func (p preparedRun) Run(ctx context.Context, runID, role, workflow, input string, inv identity.Invoker, origin *engine.Origin) (engine.Result, error) {
	// deps is this run's alone (one Prepare per POST), so setting the
	// origin here reaches every child the run spawns through options().
	p.deps.origin = origin
	opts := p.deps.options(nil)
	opts.RunID = runID
	return engine.Run(ctx, p.deps.reg, role, workflow, input, inv, p.deps.executor(), opts)
}
