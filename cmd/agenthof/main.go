package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

const usage = `agenthof — the agents' court

Usage:
  agenthof apply    --config <dir>
  agenthof registry list|enable|disable [<agent>] --config <dir>
  agenthof run <role> <workflow> --input <text> [--as <user>] [--config <dir>] [--log-dir <dir>]
  agenthof audit <run-id> [--log-dir <dir>]
  agenthof runs prune --older-than <duration> [--log-dir <dir>]
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "apply":
		code = cmdApply(os.Args[2:], os.Stdout)
	case "registry":
		code = cmdRegistry(os.Args[2:], os.Stdout)
	case "run":
		code = cmdRun(os.Args[2:], os.Stdout)
	case "audit":
		code = cmdAudit(os.Args[2:], os.Stdout)
	case "runs":
		code = cmdRuns(os.Args[2:], os.Stdout)
	default:
		fmt.Fprint(os.Stderr, usage)
		code = 2
	}
	os.Exit(code)
}

func buildRegistry(configRoot string, out io.Writer) *registry.Registry {
	cfg, loadErrs := config.LoadDir(configRoot)
	for _, e := range loadErrs {
		fmt.Fprintln(out, e)
	}
	reg, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		fmt.Fprintln(out, e.Error())
	}
	if len(loadErrs) > 0 || len(valErrs) > 0 {
		return nil
	}
	return reg
}

func cmdApply(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	cfgDir := fs.String("config", "./config", "config directory")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, loadErrs := config.LoadDir(*cfgDir)
	for _, e := range loadErrs {
		fmt.Fprintln(out, e)
	}
	_, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		fmt.Fprintln(out, e.Error())
	}
	if len(loadErrs) > 0 || len(valErrs) > 0 {
		return 1
	}
	fmt.Fprintf(out, "registry ok: %d agents, %d workflows, %d roles\n",
		len(cfg.Agents), len(cfg.Workflows), len(cfg.Roles))
	return 0
}

func cmdRegistry(args []string, out io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(out, "registry needs a subcommand: list, enable, disable")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	var target string
	if sub == "enable" || sub == "disable" {
		if len(rest) < 1 {
			fmt.Fprintf(out, "registry %s needs an agent name\n", sub)
			return 2
		}
		target, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("registry", flag.ContinueOnError)
	cfgDir := fs.String("config", "./config", "config directory")
	fs.SetOutput(out)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	switch sub {
	case "list":
		reg := buildRegistry(*cfgDir, out)
		if reg == nil {
			return 1
		}
		for _, line := range reg.List() {
			fmt.Fprintln(out, line)
		}
		return 0
	case "enable", "disable":
		enabled := sub == "enable"
		if err := registry.SetEnabled(*cfgDir, target, enabled); err != nil {
			fmt.Fprintln(out, err)
			return 1
		}
		state := "disabled"
		if enabled {
			state = "enabled"
		}
		fmt.Fprintf(out, "agent %s %s\n", target, state)
		return 0
	default:
		fmt.Fprintf(out, "unknown registry subcommand %q\n", sub)
		return 2
	}
}

func cmdRun(args []string, out io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(out, "run needs: <role> <workflow>")
		return 2
	}
	role, workflow := args[0], args[1]
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	input := fs.String("input", "", "task input for the workflow")
	as := fs.String("as", "", "invoker identity (defaults to the OS user)")
	cfgDir := fs.String("config", "./config", "config directory")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	fs.SetOutput(out)
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	if *input == "" {
		fmt.Fprintln(out, "run needs --input")
		return 2
	}
	reg := buildRegistry(*cfgDir, out)
	if reg == nil {
		return 1
	}
	inv := identity.Static(*as)
	runID, status, err := engine.Run(context.Background(), reg, role, workflow, *input,
		inv, engine.EchoExecutor{}, engine.Options{LogDir: *logDir})
	if err != nil && status == "refused" {
		fmt.Fprintf(out, "run %s refused: %v\n", runID, err)
		return 1
	}
	if err != nil {
		fmt.Fprintf(out, "run %s error: %v\n", runID, err)
		return 1
	}
	fmt.Fprintf(out, "run %s finished: %s\n", runID, status)
	if status != "succeeded" {
		return 1
	}
	return 0
}

func cmdAudit(args []string, out io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(out, "audit needs a run id")
		return 2
	}
	runID := args[0]
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	events, err := engine.ReadLog(*logDir, runID)
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	fmt.Fprint(out, audit.Render(events))
	return 0
}

func cmdRuns(args []string, out io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(out, "runs needs a subcommand: prune")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "prune":
		return cmdRunsPrune(rest, out)
	default:
		fmt.Fprintf(out, "unknown runs subcommand %q\n", sub)
		return 2
	}
}

func cmdRunsPrune(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("runs prune", flag.ContinueOnError)
	olderThan := fs.String("older-than", "", "prune runs older than this duration (e.g. 720h or 180d)")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := parseRetentionDuration(*olderThan)
	if err != nil {
		fmt.Fprintf(out, "invalid --older-than %q: %v\n", *olderThan, err)
		return 2
	}
	cutoff := time.Now().Add(-dur)
	entries, err := os.ReadDir(*logDir)
	if err != nil {
		fmt.Fprintf(out, "pruned 0 run(s) older than %s\n", *olderThan)
		return 0
	}
	pruned := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(*logDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err == nil {
				pruned++
			}
		}
	}
	fmt.Fprintf(out, "pruned %d run(s) older than %s\n", pruned, *olderThan)
	return 0
}

// parseRetentionDuration parses a Go duration string, plus a "d" suffix
// meaning days (e.g. "180d" = 180*24h).
func parseRetentionDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("not a valid day count: %s", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
