// Command refexec is the reference first-hand exec runtime: an operator-side
// supervisor that runs one allowlisted command per request in its own
// confined compartment — a rootless podman container on Linux, a Seatbelt
// profile on macOS, chosen by the config's confiner key — and attests to
// Agenthof what it ran. It serves a tiny HTTP contract (POST /run) on a Unix
// socket only Agenthof dials, on the operator's HOST: it drives the confiner
// backend, so it is a host process like agenthof, not a container. Agenthof itself still runs
// nothing; the command runs here, in the operator's runtime. It is
// credential-less: no bearer is injected and none is materialized.
//
// Usage:
//
//	refexec -config refexec.yaml          serve
//	refexec -config refexec.yaml -check   validate and print the launcher lines
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

// reapPrefix is the name prefix of every compartment refexec mints (newSession),
// so a startup Reap touches nothing another runtime owns.
const reapPrefix = "refexec-"

func main() {
	cfgPath := flag.String("config", "", "path to refexec's YAML config (required)")
	check := flag.Bool("check", false, "validate the config, print the launcher lines for the selected confiner, and exit")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "refexec: -config is required")
		os.Exit(2)
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := selectConfiner(cfg, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "refexec:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Print(checkLines(cfg, c))
		return
	}

	r, ln, err := startup(cfg, logger, c)
	if err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}
	logger.Info("refexec listening", "socket", cfg.Socket, "confiner", c.Tier(), "opts", c.Opts(),
		"store", cfg.Store, "timeout", cfg.Timeout, "max_compartments", cfg.MaxCompartments, "env_allow", cfg.EnvAllow)
	if err := refrunner.Serve(ln, r.handler(), logger, r.close); err != nil {
		logger.Error("serve failed", "error", err)
		os.Exit(1)
	}
}

// selectConfiner builds the backend the config names (or the OS default). A key
// the backend does not consume, or an image the backend will not run, is
// refused here, before anything starts.
func selectConfiner(cfg execConfig, logger *slog.Logger) (confiner.Confiner, error) {
	return confiner.Select(confiner.Options{Tier: cfg.Confiner, Keys: cfg.Keys, Environ: os.Environ, Logger: logger})
}

// startup fails closed: the backend must Probe as available, leftovers from an
// earlier refexec are reaped, and only then does the socket open. Any failure
// returns before a listener exists.
func startup(cfg execConfig, logger *slog.Logger, c confiner.Confiner) (*runner, net.Listener, error) {
	ctx := context.Background()
	if err := c.Probe(ctx); err != nil {
		return nil, nil, fmt.Errorf("confiner %s is not available: %w", c.Tier(), err)
	}
	if err := c.Reap(ctx, reapPrefix); err != nil {
		return nil, nil, fmt.Errorf("reap leftover compartments: %w", err)
	}
	ln, err := refrunner.Listen(cfg.Socket)
	if err != nil {
		return nil, nil, fmt.Errorf("listen: %w", err)
	}
	return newRunner(cfg, logger, c), ln, nil
}
