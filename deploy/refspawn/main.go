// Command refspawn is the reference compartment supervisor for Agenthof's
// spawn door: an operator-side runtime that provisions each spawned child
// run its own isolated set — one workspace volume, one rootless-podman
// refbox compartment per agent in the child's workflow (all mounting that
// volume at /work and reaching Agenthof only over a bind-mounted socket
// directory), and one refexec host process bound to the same volume — and
// tears the set down, in order, when the child is over or anything in it
// dies. It serves one held request per child (POST /provision) on a Unix
// socket only Agenthof dials, on the operator's HOST: it invokes podman, so
// it is a host process like agenthof, not a container. Agenthof itself still
// runs nothing. It is credential-less.
//
// Usage:
//
//	refspawn -config refspawn.yaml          serve
//	refspawn -config refspawn.yaml -check   validate and print the socket and spawn_root lines
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

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
	if *check {
		fmt.Print(cfg.checkLines())
		return
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	os.Exit(serve(cfg, logger, []string{"podman"}))
}

// serve prepares spawn_root, listens, reaps leftovers and serves until a
// signal. The stub mode (test tree) calls it with a fake podman.
func serve(cfg spawnConfig, logger *slog.Logger, podman []string) int {
	if err := os.MkdirAll(cfg.SpawnRoot, 0o700); err != nil {
		logger.Error("spawn_root", "error", err)
		return 1
	}
	if err := os.Chmod(cfg.SpawnRoot, 0o700); err != nil {
		logger.Error("spawn_root", "error", err)
		return 1
	}
	ln, err := refrunner.Listen(cfg.Socket)
	if err != nil {
		logger.Error("listen failed", "error", err)
		return 1
	}
	s := newSupervisor(cfg, logger, podman)
	s.reap()
	logger.Info("refspawn listening", "socket", cfg.Socket, "spawn_root", cfg.SpawnRoot,
		"agents", len(cfg.Images), "max_compartments", cfg.MaxCompartments, "timeout", cfg.Timeout)
	if err := refrunner.Serve(ln, s.handler(), logger, s.close); err != nil {
		logger.Error("serve failed", "error", err)
		return 1
	}
	return 0
}
