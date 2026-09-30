// Command refexec is the reference first-hand exec runtime: an operator-side
// supervisor that runs one allowlisted command per request in its own
// rootless-podman compartment — no network, a read-only root, the shared
// workspace volume and nothing else mounted — and attests to Agenthof what
// it ran. It serves a tiny HTTP contract (POST /run) on a Unix socket only
// Agenthof dials, on the operator's HOST: it invokes podman, so it is a host
// process like agenthof, not a container. Agenthof itself still runs
// nothing; the command runs here, in the operator's runtime. It is
// credential-less: no bearer is injected and none is materialized.
//
// Usage:
//
//	refexec -config refexec.yaml          serve
//	refexec -config refexec.yaml -check   validate and print the socket and workspace lines
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

func main() {
	cfgPath := flag.String("config", "", "path to refexec's YAML config (required)")
	check := flag.Bool("check", false, "validate the config, print socket=<path> and workspace=<volume>:<path>, and exit")
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
	if *check {
		fmt.Print(cfg.checkLines())
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ln, err := refrunner.Listen(cfg.Socket)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	r := newRunner(cfg, logger, []string{"podman"})
	logger.Info("refexec listening", "socket", cfg.Socket, "image", cfg.Image,
		"workspace", cfg.WorkspaceVolume+":"+cfg.WorkspacePath, "timeout", cfg.Timeout,
		"max_compartments", cfg.MaxCompartments, "env_allow", cfg.EnvAllow)
	if err := refrunner.Serve(ln, r.handler(), logger, r.close); err != nil {
		logger.Error("serve failed", "error", err)
		os.Exit(1)
	}
}
