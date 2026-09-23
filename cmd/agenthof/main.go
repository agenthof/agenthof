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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/agentrt"
	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/gateway"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/toolproxy"
)

const usage = `agenthof — the agents' court

Usage:
  agenthof apply    --config <dir> [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]
  agenthof registry list --config <dir>
  agenthof registry enable|disable <agent> --config <dir> [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]
  agenthof run <role> <workflow> --input <text> [--as <user>] [--groups <a,b>] [--token <jwt>] [--config <dir>] [--log-dir <dir>] [--executor echo|adk] [--workspace <dir>] [--artifact-dir <dir>] [--tool-proxy-addr <addr>]
  agenthof audit <run-id> [--log-dir <dir>]
  agenthof audit verify <run-id> [--expect-head <hex>] [--log-dir <dir>]
  agenthof audit verify control [--control-log <path>] [--expect-head <hex>]
  agenthof audit control [--control-log <path>]
  agenthof audit repair control [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]
  agenthof runs prune --older-than <duration> [--log-dir <dir>] [--artifact-dir <dir>]
  agenthof gateway provision --config <dir> [--admin-base <url>]
  agenthof investigate [--since <dur|RFC3339>] [--until <dur|RFC3339>] [--invoker <id>] [--agent <name>] [--outcome <name>] [--run <run-id>] [--config-hash <hex>] [--json] [--log-dir <dir>] [--control-log <path>]
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
	case "investigate":
		return cmdInvestigate(argv[1:], stdout)
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

// hashConfigDir computes the config directory's join-key hash for
// cmdApply and cmdRegistryFlip. It is a var (rather than a direct
// config.HashDir call) so tests can force a hash failure independently of
// LoadDir/Build's own read of the same files — the two read the same
// bytes via the same enumeration, so there is no way to make one fail
// without the other through the filesystem alone.
var hashConfigDir = config.HashDir

// cmdApply implements the audited path for `apply` (spec §3.4/§3.5/§3.7):
// resolve invoker; pre-verify the control chain is writable before any
// append; then LoadDir+Build as before, but a load failure now records
// outcome "rejected"/validation_failed with a config_hash over the
// rejected-but-readable bytes when hashConfigDir can still hash them, or
// outcome "error"/io_error with no config_hash when it can't (the bytes
// are genuinely unreadable); a validation failure likewise records outcome
// "rejected"/validation_failed with a config_hash over the rejected
// bytes. Apply never mutates files, so unlike cmdRegistryFlip there is no
// "state changed; event NOT recorded" case — a failed success/rejected
// Append is just reported and the process exits nonzero.
func cmdApply(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	cfgDir := fs.String("config", "./config", "config directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC ID token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "apply: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}

	// Verify the control chain FIRST, before any append (including a
	// refused-token append below): a torn or broken control ledger means
	// the ledger itself is unwritable, so the "audit repair control" hint
	// must always be what a damaged ledger prints, regardless of which
	// branch would otherwise have run next.
	c, err := ledger.Open(*controlLog, ledger.Locked)
	if err != nil {
		_, _ = fmt.Fprintf(out, "control ledger damaged; run: agenthof audit repair control --control-log %s\n", *controlLog)
		return 1
	}
	_ = c.Close()

	if refused {
		// Never echo the raw token, nor the go-oidc error text, into the
		// ledger: it can echo claim values from the (unverified) token
		// (see resolveInvoker's doc comment) — the recorded reason is a
		// fixed string; only the printed line below shows verifyErr.
		_, _ = fmt.Fprintf(out, "apply: token authentication failed: %v\n", verifyErr)
		head, appendErr := control.Append(*controlLog, control.Event{
			Action:     "apply",
			Outcome:    "refused",
			Reason:     &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}

	cfg, loadErrs := config.LoadDir(*cfgDir)
	for _, e := range loadErrs {
		_, _ = fmt.Fprintln(out, e)
	}
	if len(loadErrs) > 0 {
		// A LoadDir failure is ambiguous by itself: it fires both when the
		// config bytes are genuinely unreadable (I/O denial) and when they
		// are readable but fail to parse (a rejectable config, per §3.5).
		// hashConfigDir reads the same files as LoadDir but only cares
		// about raw bytes, so it succeeds on readable-but-unparseable YAML
		// and fails only on the genuine I/O case — used here to tell the
		// two apart so a bad-but-readable config is hashed and recorded as
		// "rejected", not hash-less "error".
		h, hashErr := hashConfigDir(*cfgDir)
		event := control.Event{
			Action:     "apply",
			Outcome:    "rejected",
			Reason:     &control.Reason{Code: control.CodeValidationFailed, Message: truncateErr(loadErrs[0])},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
			ConfigHash: h,
		}
		if hashErr != nil {
			// The config bytes themselves are unreadable — a genuine I/O
			// denial, not a rejectable-but-hashable config; no config_hash
			// can be computed, so this stays "error" / io_error.
			event.Outcome = "error"
			event.Reason = &control.Reason{Code: control.CodeIOError, Message: truncateErr(loadErrs[0])}
			event.ConfigHash = ""
		}
		head, appendErr := control.Append(*controlLog, event)
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}

	_, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(valErrs) > 0 {
		// config_hash is a required field on a "rejected" event (spec
		// §3.2). HashDir hashes raw file contents, so it normally
		// succeeds even though registry.Build just failed on the same
		// bytes — but if it can't be computed at all, the honest record
		// is an io_error, never a hash-less "rejected".
		h, hashErr := hashConfigDir(*cfgDir)
		if hashErr != nil {
			return appendApplyHashFailure(*controlLog, inv, assertedAs, hashErr, out)
		}
		head, appendErr := control.Append(*controlLog, control.Event{
			Action:     "apply",
			Outcome:    "rejected",
			Reason:     &control.Reason{Code: control.CodeValidationFailed, Message: truncateErr(valErrs[0])},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
			ConfigHash: h,
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}

	_, _ = fmt.Fprintf(out, "registry ok: %d agents, %d workflows, %d roles\n",
		len(cfg.Agents), len(cfg.Workflows), len(cfg.Roles))
	// config_hash is likewise required on a "success" event; the same
	// rule applies here as above.
	h, hashErr := hashConfigDir(*cfgDir)
	if hashErr != nil {
		return appendApplyHashFailure(*controlLog, inv, assertedAs, hashErr, out)
	}
	head, appendErr := control.Append(*controlLog, control.Event{
		Action:     "apply",
		Outcome:    "success",
		Invoker:    inv,
		AssertedAs: assertedAs,
		Witness:    control.CaptureWitness(),
		ConfigHash: h,
	})
	if appendErr != nil {
		_, _ = fmt.Fprintln(out, appendErr)
		return 1
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	return 0
}

// appendApplyHashFailure records apply's success/rejected outcome as an
// "error"/io_error control event instead, when config.HashDir itself
// failed after LoadDir/Build already succeeded/rejected the same bytes:
// config_hash is required on both of those outcomes (spec §3.2), so a
// hash that cannot be computed is itself a writable-ledger denial (spec
// §3.7's "a denial is itself an event" rule) — the same shape as the
// LoadDir-error branch above, never a hash-less success/rejected.
func appendApplyHashFailure(controlLog string, inv identity.Invoker, assertedAs string, hashErr error, out io.Writer) int {
	_, _ = fmt.Fprintln(out, hashErr)
	head, appendErr := control.Append(controlLog, control.Event{
		Action:     "apply",
		Outcome:    "error",
		Reason:     &control.Reason{Code: control.CodeIOError, Message: truncateErr(hashErr)},
		Invoker:    inv,
		AssertedAs: assertedAs,
		Witness:    control.CaptureWitness(),
	})
	if appendErr != nil {
		_, _ = fmt.Fprintln(out, appendErr)
		return 1
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	return 1
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
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path (enable/disable only)")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC ID token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
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
		return cmdRegistryFlip(sub, target, *cfgDir, *controlLog, *as, *groups, *token, out)
	default:
		_, _ = fmt.Fprintf(out, "unknown registry subcommand %q\n", sub)
		return 2
	}
}

// maxRecordedErrLen bounds how much of an underlying config/IO error's
// text is copied into a control event's reason message: config and IO
// errors carry no secrets or invoker identity, so including the text is
// safe, but it must still be bounded before it goes into an append-only
// ledger.
const maxRecordedErrLen = 200

// truncateErr renders err's message, cut to at most maxRecordedErrLen
// bytes.
func truncateErr(err error) string {
	s := err.Error()
	if len(s) > maxRecordedErrLen {
		s = s[:maxRecordedErrLen]
	}
	return s
}

// cmdRegistryFlip implements the audited write path for `registry
// enable|disable` (spec §3.4). Every branch that can write a control
// event does so before returning, once the control chain itself is
// known writable; the only unrecorded exit is a control ledger that
// itself cannot be opened (step 2 below) or a final append that fails
// AFTER the agent's enabled bit already changed (the documented
// residual risk).
func cmdRegistryFlip(action, target, cfgDir, controlLog, as, groups, token string, out io.Writer) int {
	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(as, groups, token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "registry: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}

	// Verify the control chain FIRST, before any state mutation OR any
	// append (including a refused-token append below): a torn or broken
	// control ledger means the ledger itself is unwritable, so nothing
	// past this point may flip state or record anything — the "audit
	// repair control" hint must always be what a damaged ledger prints,
	// regardless of which branch would otherwise have run next.
	c, err := ledger.Open(controlLog, ledger.Locked)
	if err != nil {
		_, _ = fmt.Fprintf(out, "control ledger damaged; run: agenthof audit repair control --control-log %s\n", controlLog)
		return 1
	}
	_ = c.Close()

	if refused {
		// Never echo the raw token, nor the go-oidc error text, into the
		// ledger: it can echo claim values from the (unverified) token
		// (see resolveInvoker's doc comment) — the recorded reason is a
		// fixed string; only the printed line below shows verifyErr.
		_, _ = fmt.Fprintf(out, "registry %s: token authentication failed: %v\n", action, verifyErr)
		head, err := control.Append(controlLog, control.Event{
			Action:     action,
			Agent:      target,
			Outcome:    "refused",
			Reason:     &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
		})
		if err != nil {
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}

	// Unknown-agent detection is done here, independently, against the
	// loaded config, rather than by parsing SetEnabled's own error text:
	// that keeps the refusal's reason code stable regardless of how
	// SetEnabled happens to word its error. The control chain is
	// already known writable at this point (step 2 above), so a config
	// that fails to load at all is now itself a recordable denial —
	// outcome "error", reason io_error — rather than a silent, unlogged
	// exit; it is still never conflated with "agent not found", which is
	// reserved for a config that loaded cleanly and genuinely lacks the
	// name.
	cfg, loadErrs := config.LoadDir(cfgDir)
	if len(loadErrs) > 0 {
		for _, e := range loadErrs {
			_, _ = fmt.Fprintln(out, e)
		}
		head, appendErr := control.Append(controlLog, control.Event{
			Action:     action,
			Agent:      target,
			Outcome:    "error",
			Reason:     &control.Reason{Code: control.CodeIOError, Message: truncateErr(loadErrs[0])},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}
	known := false
	for _, a := range cfg.Agents {
		if a.Name == target {
			known = true
			break
		}
	}
	if !known {
		head, appendErr := control.Append(controlLog, control.Event{
			Action:     action,
			Agent:      target,
			Outcome:    "refused",
			Reason:     &control.Reason{Code: control.CodeAgentNotFound, Message: fmt.Sprintf("agent %s not found", target)},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}

	enabled := action == "enable"
	if setErr := registry.SetEnabled(cfgDir, target, enabled); setErr != nil {
		_, _ = fmt.Fprintln(out, setErr)
		head, appendErr := control.Append(controlLog, control.Event{
			Action:     action,
			Agent:      target,
			Outcome:    "error",
			Reason:     &control.Reason{Code: control.CodeIOError, Message: truncateErr(setErr)},
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return 1
	}
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	_, _ = fmt.Fprintf(out, "agent %s %s\n", target, state)

	// Test-only crash hook (spec §3.8): simulates the process dying after
	// SetEnabled has already changed on-disk state but before the success
	// control.Append below, so that documented residual-risk window is
	// exercisable by a test instead of only by an unreproducible race.
	if os.Getenv("AGENTHOF_TEST_CRASH_AT") == "after_state_before_append" {
		_, _ = fmt.Fprintln(out, "state changed; event NOT recorded")
		return 1
	}

	// Recompute config_hash by re-reading: SetEnabled just rewrote the
	// agent's YAML file, so the pre-flip hash is already stale. A
	// failure past this point means the state already changed but the
	// event could not be built/appended — the documented residual risk.
	// Routed through the hashConfigDir seam (the same one cmdApply uses)
	// rather than calling config.HashDir directly, so this branch is
	// exercisable by a test too.
	h, hashErr := hashConfigDir(cfgDir)
	if hashErr != nil {
		_, _ = fmt.Fprintln(out, "state changed; event NOT recorded")
		return 1
	}
	head, err := control.Append(controlLog, control.Event{
		Action:     action,
		Agent:      target,
		Outcome:    "success",
		Invoker:    inv,
		AssertedAs: assertedAs,
		Witness:    control.CaptureWitness(),
		ConfigHash: h,
	})
	if err != nil {
		_, _ = fmt.Fprintln(out, "state changed; event NOT recorded")
		return 1
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	return 0
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
	// Accepted for forward-compat: the tool proxy always binds 127.0.0.1:0
	// regardless of this flag's value today.
	fs.String("tool-proxy-addr", "127.0.0.1:0", "tool-proxy bind address (currently always binds 127.0.0.1:0; reserved for future use)")
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

	inv, _, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "run: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	if refused {
		// Never echo the raw token: it's a bearer credential. Nor do we
		// echo the go-oidc error text into the ledger below — it can
		// echo claim values from the (unverified) token.
		_, _ = fmt.Fprintf(out, "run: token authentication failed: %v\n", verifyErr)
		runID, refErr := engine.Refuse(*logDir, role, workflow, inv, "token verification failed")
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "run %s refused: token verification failed\n", runID)
		return 1
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
	// A hash failure here yields an empty join key, not a run failure: the
	// run's config already validated above, so the run proceeds regardless.
	h, _ := config.HashDir(*cfgDir)
	// Only wire a real tool proxy when the config actually declares gateway
	// tool resources; otherwise leave Options.ToolProxy nil (a *toolproxy.Proxy
	// assigned into the interface even when unused would make it a non-nil
	// interface holding a nil pointer, which the engine's own opts.ToolProxy
	// != nil bracketing check would then wrongly treat as present).
	var toolProxy engine.ToolProxy
	if len(cfg.Gateway.Tools) > 0 {
		toolProxy = toolproxy.New(cfg.Gateway.Tools, broker.StaticEnv{})
	}
	runID, status, err := engine.Run(context.Background(), reg, role, workflow, *input,
		inv, exec, engine.Options{LogDir: *logDir, ArtifactDir: *artifactDir, WorkspaceDir: ws, ConfigHash: h, ToolProxy: toolProxy})
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
	// "control" is likewise disambiguated up front: it, like "verify", can
	// never collide with a run id's "r-<hex>" form.
	if args[0] == "control" {
		return cmdAuditControl(args[1:], out)
	}
	// "repair" is disambiguated the same way: a run id is always
	// "r-<hex>" (engine.NewRunID), which "repair" can never match. Only
	// "repair control" exists today (there is no run-log repair), so the
	// "control" sub-dispatch lives inside cmdAuditRepairControl itself
	// rather than a separate cmdAuditRepair layer.
	if args[0] == "repair" {
		return cmdAuditRepairControl(args[1:], out)
	}
	runID := args[0]
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
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
	for _, e := range events {
		if e.Type == "workflow_started" && e.ConfigHash != "" {
			cev, verdict, _ := investigate.LoadControl(*controlLog)
			_, _ = fmt.Fprintln(out, investigate.ConfigJoin(cev, verdict, e.ConfigHash, e.Time))
			break
		}
	}
	if err != nil {
		// A torn/broken chain, whether or not a valid prefix was
		// recovered — the rendered output already names the failure,
		// but the exit code must not lie about a corrupted ledger.
		return 1
	}
	return 0
}

// cmdAuditVerify implements `audit verify <run-id> [--expect-head <hex>]`,
// dispatching to cmdAuditVerifyControl when the next arg is "control": it
// reports the verified chain's head hash and event count, and, given
// --expect-head, compares it against a previously recorded hash. For a
// run (this function's own path, unchanged from before the control
// dispatch was added): exit codes are 0 clean (and, when given,
// --expect-head matches); 1 torn/broken ledger or an open/IO failure; 4
// --expect-head mismatch (hash only — count is informational and not
// compared); 2 usage errors. 3 (the taint verdict) is returned only via
// the "control" dispatch — see cmdAuditVerifyControl.
func cmdAuditVerify(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "audit verify needs a run id")
		return 2
	}
	// "control" is disambiguated up front, same as cmdAudit does for its
	// own "verify"/"control" subcommands: a run id is always "r-<hex>"
	// (engine.NewRunID), which "control" can never match.
	if args[0] == "control" {
		return cmdAuditVerifyControl(args[1:], out)
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

// cmdAuditControl implements `audit control`: it renders the control
// ledger (spec §3.6) as a human-readable audit trail via control.Render.
// A missing control log (nothing has ever been recorded there) is
// reported plainly rather than as a generic open error; a torn/broken
// chain still renders whatever valid prefix ReadVerify recovered,
// followed by the integrity line naming the failure, and exits nonzero.
func cmdAuditControl(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("audit control", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	records, head, err := ledger.ReadVerify(*controlLog, ledger.Locked)
	if err != nil {
		var te *ledger.TornError
		var be *ledger.ChainBrokenError
		if !errors.As(err, &te) && !errors.As(err, &be) {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(out, "no control ledger at %s — nothing recorded yet\n", *controlLog)
				return 1
			}
			// Some other open/IO failure: no ledger to render.
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
	}
	_, _ = fmt.Fprint(out, control.Render(records, head, err))
	if err != nil {
		// A torn/broken chain, whether or not a valid prefix was
		// recovered — the rendered output already names the failure, but
		// the exit code must not lie about a corrupted ledger.
		return 1
	}
	return 0
}

// cmdAuditVerifyControl implements `audit verify control [--control-log
// <path>] [--expect-head <hex>]`: the control-ledger counterpart to
// cmdAuditVerify, reporting the control chain's head and, given
// --expect-head, comparing it against a previously recorded hash. Exit
// codes, checked in this order (spec §3.6): 1 for a missing control log
// or any other open/IO failure; 1 for a torn/broken chain; 3 when the
// chain is tainted (control.IsTainted — a "repair" record was ever
// appended), which takes precedence over an --expect-head mismatch; 4
// for an --expect-head mismatch (hash only — count is informational); 0
// otherwise.
func cmdAuditVerifyControl(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("audit verify control", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
	expectHead := fs.String("expect-head", "", "expected control ledger head hash (hex) to verify against")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	records, head, err := ledger.ReadVerify(*controlLog, ledger.Locked)
	if err != nil {
		var te *ledger.TornError
		var be *ledger.ChainBrokenError
		if !errors.As(err, &te) && !errors.As(err, &be) {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(out, "no control ledger at %s — nothing recorded yet\n", *controlLog)
				return 1
			}
			// Some other open/IO failure: no ledger to report a head for.
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 1
	}
	if tainted, seq := control.IsTainted(records); tainted {
		_, _ = fmt.Fprintf(out, "control ledger TAINTED: repaired at seq %d\n", seq)
		return 3
	}
	if *expectHead != "" && *expectHead != head.Hash {
		_, _ = fmt.Fprintf(out, "expect-head mismatch: want %s, got %s\n", *expectHead, head.Hash)
		return 4
	}
	return 0
}

// cmdAuditRepairControl implements `audit repair control [--control-log
// <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]` (spec §3.6): it
// resolves the repairing operator's identity exactly as apply/registry
// do, then hands off to control.Repair to move the torn fragment aside,
// truncate the live file, and append the chained "repair" event that
// taints the ledger forever (control.IsTainted; reported by a later
// `audit verify control` as exit 3).
//
// A missing control log is reported plainly rather than as a generic
// open error, matching cmdAuditControl/cmdAuditVerifyControl. An
// authentication refusal exits nonzero WITHOUT writing any control
// event: the ledger here may be exactly the torn/unwritable file being
// repaired, so there is no safe place to record the refusal, unlike
// apply/registry's refusal path against an already-known-writable
// chain.
func cmdAuditRepairControl(args []string, out io.Writer) int {
	if len(args) < 1 || args[0] != "control" {
		_, _ = fmt.Fprintln(out, "audit repair needs a subcommand: control")
		return 2
	}
	fs := flag.NewFlagSet("audit repair control", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC ID token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "audit repair control: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	if refused {
		// An unauthenticated operator must not repair anything, and — since
		// the ledger being repaired may itself be the torn/unwritable file
		// in question — there is no known-writable chain to safely record
		// this refusal against, unlike apply/registry's refusal path. Print
		// and exit; do not attempt a control.Append here.
		_, _ = fmt.Fprintf(out, "audit repair control: token authentication failed: %v\n", verifyErr)
		return 1
	}

	if _, statErr := os.Stat(*controlLog); statErr != nil {
		if os.IsNotExist(statErr) {
			_, _ = fmt.Fprintf(out, "no control ledger at %s — nothing recorded yet\n", *controlLog)
			return 1
		}
		_, _ = fmt.Fprintln(out, statErr)
		return 1
	}

	fragLen, fragSHA, err := control.Repair(*controlLog, inv, assertedAs, control.CaptureWitness())
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "repaired: moved %d bytes (sha256=%s) to %s; control ledger tainted\n",
		fragLen, fragSHA, latestTornFragmentPath(*controlLog))
	records, head, verr := ledger.ReadVerify(*controlLog, ledger.Locked)
	if verr != nil {
		_, _ = fmt.Fprintln(out, verr)
		return 1
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	if tainted, seq := control.IsTainted(records); tainted {
		_, _ = fmt.Fprintf(out, "control ledger TAINTED: repaired at seq %d\n", seq)
	}
	return 0
}

// latestTornFragmentPath finds the most recently created
// "<controlLog>.torn-<unix-seconds>" sibling file, for the human-readable
// message printed after a successful control.Repair. control.Repair
// itself only returns the fragment's length and sha256 (spec §3.6's
// interface), not the path it chose, so this glob-and-pick-newest
// reconstructs it; timestamps are decimal Unix seconds of equal length
// today, so the lexicographically greatest match is also the newest. A
// failure here never fails the repair itself — it already succeeded —
// so this just falls back to a glob pattern if, somehow, nothing matches.
func latestTornFragmentPath(controlLog string) string {
	pattern := controlLog + ".torn-*"
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return pattern
	}
	sort.Strings(matches)
	return matches[len(matches)-1]
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
		// The control ledger and its "<control-log>.torn-*" repair
		// fragments (internal/control/log.go's writeTornFragment) must
		// never be deleted here, even if --log-dir is misconfigured to
		// point at the ledger's own directory instead of the default
		// .agenthof/runs (spec §3.1).
		if entry.Name() == "control.jsonl" || strings.Contains(entry.Name(), ".torn-") {
			continue
		}
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

// cmdInvestigate implements `agenthof investigate`: it builds an
// investigate.Filter from the flags, asks investigate.Timeline to merge and
// normalize every run log under --log-dir plus --control-log into one
// timeline, then renders it as text or (with --json) the investigate/1 JSON
// contract. The exit code always comes from investigate.ExitCode — --json
// changes only the rendering, never the exit code.
func cmdInvestigate(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("investigate", flag.ContinueOnError)
	since := fs.String("since", "", "only events at/after this time: a duration (e.g. 1h, 30d) meaning \"ago\", or an RFC3339 timestamp")
	until := fs.String("until", "", "only events before this time: a duration (e.g. 1h, 30d) meaning \"ago\", or an RFC3339 timestamp")
	invoker := fs.String("invoker", "", "filter: exact invoker subject")
	agent := fs.String("agent", "", "filter: exact agent name")
	outcome := fs.String("outcome", "", "filter: exact outcome")
	run := fs.String("run", "", "filter: exact run id")
	configHash := fs.String("config-hash", "", "filter: exact config hash")
	jsonOut := fs.Bool("json", false, "render as the investigate/1 JSON contract instead of text")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	f := investigate.Filter{
		Invoker:    *invoker,
		Agent:      *agent,
		Outcome:    *outcome,
		Run:        *run,
		ConfigHash: *configHash,
	}
	if *since != "" {
		t, err := parseTimeBound(*since)
		if err != nil {
			_, _ = fmt.Fprintf(out, "investigate: invalid --since %q: %v\n", *since, err)
			return 2
		}
		f.Since = &t
	}
	if *until != "" {
		t, err := parseTimeBound(*until)
		if err != nil {
			_, _ = fmt.Fprintf(out, "investigate: invalid --until %q: %v\n", *until, err)
			return 2
		}
		f.Until = &t
	}

	res, err := investigate.Timeline(*logDir, *controlLog, f)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 1
	}

	var s string
	if *jsonOut {
		s, err = investigate.RenderJSON(res, f)
		if err != nil {
			_, _ = fmt.Fprintln(out, err)
			return 1
		}
	} else {
		s = investigate.RenderText(res)
	}
	_, _ = fmt.Fprint(out, s)
	return investigate.ExitCode(res)
}

// parseTimeBound parses a --since/--until value the same way runs prune
// interprets --older-than: try a Go duration (plus the "d" suffix) first, and
// when that succeeds treat it as "this long ago" — mirroring runs prune's
// cutoff := time.Now().Add(-dur) at pruneRuns above. On failure, fall back to
// an absolute RFC3339 timestamp. Both results are normalized to UTC.
func parseTimeBound(s string) (time.Time, error) {
	if dur, err := parseRetentionDuration(s); err == nil {
		return time.Now().Add(-dur).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("not a valid duration or RFC3339 timestamp: %q", s)
	}
	return t.UTC(), nil
}
