// Command refbridge is the reference stdio→HTTP MCP bridge: an operator-side
// supervisor that fronts a stdio-only MCP server so Agenthof's tool door can
// govern it. It serves a Streamable HTTP MCP endpoint on a Unix socket only
// Agenthof dials, spawns one stdio subprocess per MCP session with a clean
// environment plus the credential Agenthof injected on the call, and tears
// the subprocess down when the session ends. Agenthof itself still runs
// nothing: the subprocess lives here, in the operator's runtime.
//
// Usage:
//
//	refbridge -config refbridge.yaml          serve
//	refbridge -config refbridge.yaml -check   validate and print the egress line
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/agenthof/agenthof/deploy/internal/refrunner"
)

func main() {
	cfgPath := flag.String("config", "", "path to the bridge's YAML config (required)")
	check := flag.Bool("check", false, "validate the config, print its egress line (egress=none or egress=host,...) and exit")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "refbridge: -config is required")
		os.Exit(2)
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *check {
		fmt.Println(cfg.egressLine())
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ln, err := refrunner.Listen(cfg.Socket)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	b := newBridge(cfg, logger)
	logger.Info("refbridge listening", "socket", cfg.Socket, "command", cfg.Command[0],
		"materialization", cfg.Materialization, "egress", cfg.egressLine(),
		"max_sessions", cfg.MaxSessions, "idle_timeout", cfg.IdleTimeout, "max_lifetime", cfg.MaxLifetime)
	if err := refrunner.Serve(ln, b.handler(), logger, b.close); err != nil {
		logger.Error("serve failed", "error", err)
		os.Exit(1)
	}
}
