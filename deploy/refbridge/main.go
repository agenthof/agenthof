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
//	refbridge -project gateway.yaml -resource ID -credential-env NAME -out slice.yaml
//	                                          host-side: write the side-file for one governed resource, then exit
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
	project := flag.String("project", "", "host-side: path to the installed gateway.yaml to project one resource's launch spec from (writes -out and exits)")
	resource := flag.String("resource", "", "with -project: the tool resource id")
	out := flag.String("out", "", "with -project: where to write the side-file")
	credEnv := flag.String("credential-env", "", "with -project: the variable refbridge sets on the MCP child (required; not the resource's token_env)")
	maxSessions := flag.Int("max-sessions", 4, "with -project: concurrent sessions")
	idle := flag.String("idle-timeout", "10m", "with -project: idle session timeout")
	life := flag.String("max-lifetime", "30m", "with -project: session lifetime cap")
	mat := flag.String("materialization", matEnvAtSpawn, "with -project: credential materialization")
	flag.Parse()
	if *project != "" {
		if *cfgPath != "" || *check {
			fmt.Fprintln(os.Stderr, "refbridge: -project is its own mode; it takes neither -config nor -check")
			os.Exit(2)
		}
		if *out == "" {
			fmt.Fprintln(os.Stderr, "refbridge: -project requires -out")
			os.Exit(2)
		}
		ops := projectOps{CredentialEnv: *credEnv, MaxSessions: *maxSessions, IdleTimeout: *idle, MaxLifetime: *life, Materialization: *mat}
		if err := runProject(*project, *resource, *out, ops); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return
	}
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
