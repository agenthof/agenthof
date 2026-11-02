// Command refspawn is the reference compartment supervisor for Agenthof's
// spawn door: an operator-side runtime that provisions each spawned child
// run its own isolated set — one workspace store, one confined refbox
// compartment per agent in the child's workflow (all sharing that store and
// reaching Agenthof only over a socket directory; for the podman tier, a
// volume mounted at /work and a bind-mounted directory), and one refexec host
// process bound to the same store — and
// tears the set down, in order, when the child is over or anything in it
// dies. It serves one held request per child (POST /provision) on a Unix
// socket only Agenthof dials, on the operator's HOST: it drives the confiner
// backend (for the podman tier, that runs podman), so it is a host process
// like agenthof, not a container. Agenthof itself still runs nothing. It is
// credential-less.
//
// Usage:
//
//	refspawn -config refspawn.yaml          serve
//	refspawn -config refspawn.yaml -check   validate and print the socket and spawn_root lines
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

func main() {
	cfgPath := flag.String("config", "", "path to refspawn's YAML config (required)")
	check := flag.Bool("check", false, "validate the config, print socket=<path> and spawn_root=<dir>, and exit")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "refspawn: -config is required")
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *check {
		fmt.Print(cfg.checkLines())
		return
	}
	os.Exit(startup(cfg, logger, c))
}

// selectConfiner builds the backend the config names (the OS default when it
// names none). The factory refuses a key the backend does not consume.
func selectConfiner(cfg spawnConfig, logger *slog.Logger) (confiner.Confiner, error) {
	c, err := confiner.Select(confiner.Options{Tier: cfg.Confiner, Keys: cfg.Keys, SpawnRoot: cfg.SpawnRoot, Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("refspawn config: %w", err)
	}
	return c, nil
}

// startup refuses to serve unless the backend is usable (Probe) and can run
// every configured program (ValidateProgram), then serves. Nothing is
// prepared or listened on before both pass. Agent names are checked in sorted
// order so the first refusal is deterministic.
func startup(cfg spawnConfig, logger *slog.Logger, c confiner.Confiner) int {
	if err := c.Probe(context.Background()); err != nil {
		logger.Error("confiner is not usable; refusing to serve", "confiner", c.Tier(), "error", err)
		return 1
	}
	agents := make([]string, 0, len(cfg.Images))
	for agent := range cfg.Images {
		agents = append(agents, agent)
	}
	sort.Strings(agents)
	for _, agent := range agents {
		if err := c.ValidateProgram(cfg.Images[agent]); err != nil {
			logger.Error("images entry refused by the confiner; refusing to serve", "agent", agent, "confiner", c.Tier(), "error", err)
			return 1
		}
	}
	return serve(cfg, logger, c)
}

// prepareSpawnRoot creates spawn_root owner-only and refuses a directory on a
// non-native (bridged or remote) filesystem, where the per-child socket
// directories the compartments bind-mount would not behave as the kernel's own.
func prepareSpawnRoot(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := refrunner.CheckNativeFS(dir); err != nil {
		return fmt.Errorf("refspawn: spawn_root: %w", err)
	}
	return nil
}

// serve prepares spawn_root, reaps leftovers, listens and serves until a
// signal. The leftovers are reaped before the socket exists: a supervisor
// that cannot account for an earlier one's compartments refuses to serve
// rather than count slots it does not know it holds. The stub mode (test
// tree) reaches it through startup with an in-process fake confiner.
func serve(cfg spawnConfig, logger *slog.Logger, c confiner.Confiner) int {
	if err := prepareSpawnRoot(cfg.SpawnRoot); err != nil {
		logger.Error("spawn_root", "error", err)
		return 1
	}
	s := newSupervisor(cfg, logger, c)
	if err := s.reap(); err != nil {
		logger.Error("could not account for leftover compartments; refusing to serve", "error", err)
		return 1
	}
	ln, err := refrunner.Listen(cfg.Socket)
	if err != nil {
		logger.Error("listen failed", "error", err)
		return 1
	}
	logger.Info("refspawn listening", "socket", cfg.Socket, "spawn_root", cfg.SpawnRoot,
		"agents", len(cfg.Images), "max_compartments", cfg.MaxCompartments, "timeout", cfg.Timeout)
	if err := refrunner.Serve(ln, s.handler(), logger, s.close); err != nil {
		logger.Error("serve failed", "error", err)
		return 1
	}
	return 0
}
