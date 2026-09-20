package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/agentrt"
	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/gateway"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/registry"
)

const usage = `agenthof — the agents' court

Usage:
  agenthof apply    --config <dir>
  agenthof registry list|enable|disable [<agent>] --config <dir>
  agenthof run <role> <workflow> --input <text> [--as <user>] [--groups <a,b>] [--token <jwt>] [--config <dir>] [--log-dir <dir>] [--executor echo|adk] [--workspace <dir>] [--artifact-dir <dir>]
  agenthof audit <run-id> [--log-dir <dir>]
  agenthof audit verify <run-id> [--expect-head <hex>] [--log-dir <dir>]
  agenthof runs prune --older-than <duration> [--log-dir <dir>] [--artifact-dir <dir>]
  agenthof gateway provision --config <dir> [--admin-base <url>]
`

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// dispatch routes argv to a subcommand and returns the process exit code.
// It exists (rather than logic living in main) so the testscript harness can
// run the real CLI in-process.
func dispatch(argv []string, stdout, stderr io.Writer) int {
	if len(argv) < 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch argv[0] {
	case "apply":
		return cmdApply(argv[1:], stdout)
	case "registry":
		return cmdRegistry(argv[1:], stdout)
	case "run":
		return cmdRun(argv[1:], stdout)
	case "audit":
		return cmdAudit(argv[1:], stdout)
	case "runs":
		return cmdRuns(argv[1:], stdout)
	case "gateway":
		return cmdGateway(argv[1:], stdout)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
}

// loadRegistry loads and validates the config at configRoot, printing any
// load or validation errors to out. reg is nil when either step failed;
// cfg is still returned so callers that need config fields (e.g. the
// gateway section) don't have to reload it themselves.
func loadRegistry(configRoot string, out io.Writer) (config.Config, *registry.Registry) {
	cfg, loadErrs := config.LoadDir(configRoot)
	for _, e := range loadErrs {
		_, _ = fmt.Fprintln(out, e)
	}
	reg, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(loadErrs) > 0 || len(valErrs) > 0 {
		return cfg, nil
	}
	return cfg, reg
}

func buildRegistry(configRoot string, out io.Writer) *registry.Registry {
	_, reg := loadRegistry(configRoot, out)
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
		_, _ = fmt.Fprintln(out, e)
	}
	_, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(loadErrs) > 0 || len(valErrs) > 0 {
		return 1
	}
	_, _ = fmt.Fprintf(out, "registry ok: %d agents, %d workflows, %d roles\n",
		len(cfg.Agents), len(cfg.Workflows), len(cfg.Roles))
	return 0
}

func cmdRegistry(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "registry needs a subcommand: list, enable, disable")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	var target string
	if sub == "enable" || sub == "disable" {
		if len(rest) < 1 {
			_, _ = fmt.Fprintf(out, "registry %s needs an agent name\n", sub)
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
			_, _ = fmt.Fprintln(out, line)
		}
		return 0
	case "enable", "disable":
		enabled := sub == "enable"
		if err := registry.SetEnabled(*cfgDir, target, enabled); err != nil {
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
		state := "disabled"
		if enabled {
			state = "enabled"
		}
		_, _ = fmt.Fprintf(out, "agent %s %s\n", target, state)
		return 0
	default:
		_, _ = fmt.Fprintf(out, "unknown registry subcommand %q\n", sub)
		return 2
	}
}

func cmdRun(args []string, out io.Writer) int {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(out, "run needs: <role> <workflow>")
		return 2
	}
	role, workflow := args[0], args[1]
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	input := fs.String("input", "", "task input for the workflow")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC ID token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	cfgDir := fs.String("config", "./config", "config directory")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	executorName := fs.String("executor", "echo", `step executor: "echo" or "adk"`)
	workspace := fs.String("workspace", "", "workspace directory (default: .agenthof/workspaces/<unix-nano>)")
	artifactDir := fs.String("artifact-dir", ".agenthof/artifacts", "artifact store directory")
	fs.SetOutput(out)
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	if *input == "" {
		_, _ = fmt.Fprintln(out, "run needs --input")
		return 2
	}
	if *executorName != "echo" && *executorName != "adk" {
		_, _ = fmt.Fprintf(out, "run: invalid --executor %q, want \"echo\" or \"adk\"\n", *executorName)
		return 2
	}

	rawToken := *token
	if rawToken == "" {
		rawToken = os.Getenv("AGENTHOF_TOKEN")
	}
	var inv identity.Invoker
	if rawToken != "" {
		issuerURL := os.Getenv("AGENTHOF_OIDC_ISSUER")
		if issuerURL == "" {
			_, _ = fmt.Fprintln(out, "run: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
			return 2
		}
		clientID := os.Getenv("AGENTHOF_OIDC_CLIENT_ID")
		if clientID == "" {
			clientID = "agenthof"
		}
		authInv, err := (identity.OIDC{IssuerURL: issuerURL, ClientID: clientID}).Authenticate(context.Background(), rawToken)
		if err != nil {
			// Never echo the raw token: it's a bearer credential. Nor do we
			// echo the go-oidc error text into the ledger below — it can
			// echo claim values from the (unverified) token.
			_, _ = fmt.Fprintf(out, "run: token authentication failed: %v\n", err)
			refusedInv := identity.Invoker{Subject: "(unverified)", Issuer: issuerURL, Method: "oidc-rejected"}
			runID, refErr := engine.Refuse(*logDir, role, workflow, refusedInv, "token verification failed")
			if refErr != nil {
				_, _ = fmt.Fprintln(out, refErr)
				return 1
			}
			_, _ = fmt.Fprintf(out, "run %s refused: token verification failed\n", runID)
			return 1
		}
		inv = authInv
	} else {
		var g []string
		for _, raw := range strings.Split(*groups, ",") {
			trimmed := strings.TrimSpace(raw)
			if trimmed != "" {
				g = append(g, trimmed)
			}
		}
		// identity.Static only takes --as; it's set here rather than adding a
		// groups parameter, since ~15 existing call sites across the engine,
		// audit, and identity test suites call Static with a single arg.
		// Invoker.Groups is a plain exported field, so mutating the returned
		// value is equivalent to threading it through the constructor.
		inv = identity.Static(*as)
		inv.Groups = g
	}

	ws := *workspace
	if ws == "" {
		ws = filepath.Join(".agenthof", "workspaces", strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	cfg, loadErrs := config.LoadDir(*cfgDir)
	for _, e := range loadErrs {
		_, _ = fmt.Fprintln(out, e)
	}
	reg, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(loadErrs) > 0 || len(valErrs) > 0 {
		var firstErr string
		if len(loadErrs) > 0 {
			firstErr = loadErrs[0].Error()
		} else {
			firstErr = valErrs[0].Error()
		}
		reason := "configuration invalid: " + firstErr
		runID, refErr := engine.Refuse(*logDir, role, workflow, inv, reason)
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "run %s refused: configuration invalid\n", runID)
		return 1
	}
	_, _ = fmt.Fprintf(out, "workspace: %s\n", ws)
	if err := os.MkdirAll(ws, 0o755); err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 1
	}
	var contained engine.StepExecutor
	switch *executorName {
	case "adk":
		key := gateway.LoadRoleKey(".", role)
		contained = agentrt.ADKExecutor{Gateway: cfg.Gateway, RoleKey: key, WorkspaceDir: ws}
	default:
		contained = engine.EchoExecutor{}
	}
	exec := agentrt.MuxExecutor{Contained: contained, Fronted: agentrt.AdapterExecutor{}}
	runID, status, err := engine.Run(context.Background(), reg, role, workflow, *input,
		inv, exec, engine.Options{LogDir: *logDir, ArtifactDir: *artifactDir, WorkspaceDir: ws})
	if err != nil && status == "refused" {
		_, _ = fmt.Fprintf(out, "run %s refused: %v\n", runID, err)
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "run %s error: %v\n", runID, err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "run %s finished: %s\n", runID, status)
	if status != "succeeded" {
		return 1
	}
	return 0
}

func cmdGateway(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "gateway needs a subcommand: provision")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "provision":
		return cmdGatewayProvision(rest, out)
	default:
		_, _ = fmt.Fprintf(out, "unknown gateway subcommand %q\n", sub)
		return 2
	}
}

func cmdGatewayProvision(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("gateway provision", flag.ContinueOnError)
	cfgDir := fs.String("config", "./config", "config directory")
	adminBase := fs.String("admin-base", "http://localhost:4000", "LiteLLM admin API base URL")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	masterKey := os.Getenv("LITELLM_MASTER_KEY")
	if masterKey == "" {
		_, _ = fmt.Fprintln(out, "gateway provision needs LITELLM_MASTER_KEY set in the environment")
		return 2
	}
	// Provisioning needs the raw role list (registry.Registry only exposes
	// lookups), so load and validate the config directly rather than going
	// through buildRegistry.
	cfg, loadErrs := config.LoadDir(*cfgDir)
	for _, e := range loadErrs {
		_, _ = fmt.Fprintln(out, e)
	}
	_, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(loadErrs) > 0 || len(valErrs) > 0 {
		return 1
	}
	p := gateway.Provisioner{AdminBase: *adminBase, MasterKey: masterKey, HTTP: http.DefaultClient}
	for _, role := range cfg.Roles {
		created, err := p.EnsureRoleKey(".", role)
		if err != nil {
			_, _ = fmt.Fprintf(out, "role %s: %v\n", role.Name, err)
			return 1
		}
		if created {
			_, _ = fmt.Fprintf(out, "provisioned key for role %s (budget $%g)\n", role.Name, role.BudgetUSDMonth)
		} else {
			_, _ = fmt.Fprintf(out, "role %s: key ok\n", role.Name)
		}
	}
	return 0
}

func cmdAudit(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "audit needs a run id")
		return 2
	}
	// "verify" is disambiguated from a run id up front: run ids are always
	// of the form "r-<hex>" (see engine.NewRunID), which "verify" can never
	// match, so there's no ambiguity to parse around.
	if args[0] == "verify" {
		return cmdAuditVerify(args[1:], out)
	}
	runID := args[0]
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	events, head, err := engine.ReadLog(*logDir, runID)
	if err != nil {
		var te *ledger.TornError
		var be *ledger.ChainBrokenError
		if !errors.As(err, &te) && !errors.As(err, &be) {
			// Open/IO failure: no ledger at all to render.
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
	}
	_, _ = fmt.Fprint(out, audit.Render(events, head, err))
	if err != nil {
		// A torn/broken chain, whether or not a valid prefix was
		// recovered — the rendered output already names the failure,
		// but the exit code must not lie about a corrupted ledger.
		return 1
	}
	return 0
}

// cmdAuditVerify implements `audit verify <run-id> [--expect-head <hex>]`:
// it reports the verified chain's head hash and event count, and, given
// --expect-head, compares it against a previously recorded hash. Exit
// codes: 0 clean (and, when given, --expect-head matches); 1 torn/broken
// ledger or an open/IO failure; 4 --expect-head mismatch (hash only —
// count is informational and not compared); 2 usage errors. 3 is
// reserved for the E2 control-ledger taint verdict and is never returned
// here.
func cmdAuditVerify(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "audit verify needs a run id")
		return 2
	}
	runID := args[0]
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	expectHead := fs.String("expect-head", "", "expected ledger head hash (hex) to verify against")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	_, head, err := engine.ReadLog(*logDir, runID)
	if err != nil {
		var te *ledger.TornError
		var be *ledger.ChainBrokenError
		if !errors.As(err, &te) && !errors.As(err, &be) {
			// Open/IO failure: no ledger at all to report a head for.
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
	}
	_, _ = fmt.Fprintf(out, "head: %s (%d events)\n", head.Hash, head.Count)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 1
	}
	if *expectHead != "" && *expectHead != head.Hash {
		_, _ = fmt.Fprintf(out, "expect-head mismatch: want %s, got %s\n", *expectHead, head.Hash)
		return 4
	}
	return 0
}

func cmdRuns(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "runs needs a subcommand: prune")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "prune":
		return cmdRunsPrune(rest, out)
	default:
		_, _ = fmt.Fprintf(out, "unknown runs subcommand %q\n", sub)
		return 2
	}
}

func cmdRunsPrune(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("runs prune", flag.ContinueOnError)
	olderThan := fs.String("older-than", "", "prune runs older than this duration (e.g. 720h or 180d)")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	artifactDir := fs.String("artifact-dir", ".agenthof/artifacts", "artifact store directory")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := parseRetentionDuration(*olderThan)
	if err != nil {
		_, _ = fmt.Fprintf(out, "invalid --older-than %q: %v\n", *olderThan, err)
		return 2
	}
	if dur <= 0 {
		_, _ = fmt.Fprintln(out, "--older-than must be a positive duration")
		return 2
	}

	runsPruned, err := pruneRuns(*logDir, dur)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 1
	}

	// Constitution Art. III keeps artifact bodies out of the append-only
	// ledger precisely so they can be pruned independently; do that here
	// too, rather than leaving retention half-enforced. A missing
	// artifact-dir is not an error (nothing provisioned it yet, e.g. an
	// echo-executor-only deployment) — mirror the missing-log-dir case
	// instead of having artifact.NewStore create it just to prune nothing.
	artifactsPruned := 0
	if _, statErr := os.Stat(*artifactDir); statErr == nil {
		store, err := artifact.NewStore(*artifactDir)
		if err != nil {
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
		artifactsPruned, err = store.Prune(dur)
		if err != nil {
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
	} else if !os.IsNotExist(statErr) {
		_, _ = fmt.Fprintln(out, statErr)
		return 1
	}

	_, _ = fmt.Fprintf(out, "pruned %d run(s) and %d artifact(s) older than %s\n", runsPruned, artifactsPruned, *olderThan)
	return 0
}

// pruneRuns removes run log files under logDir whose modification time is
// older than dur. A missing logDir is not an error — nothing has run yet —
// and prunes 0.
func pruneRuns(logDir string, dur time.Duration) (int, error) {
	cutoff := time.Now().Add(-dur)
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	pruned := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(logDir, entry.Name())
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
	return pruned, nil
}

// parseRetentionDuration parses a Go duration string, plus a "d" suffix
// meaning days (e.g. "180d" = 180*24h).
func parseRetentionDuration(s string) (time.Duration, error) {
	if before, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(before)
		if err != nil {
			return 0, fmt.Errorf("not a valid day count: %s", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
