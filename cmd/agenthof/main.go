package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/gateway"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/refspawn"
	"github.com/agenthof/agenthof/internal/registry"
)

const usage = `agenthof — the agents' court

Usage:
  agenthof apply    --config <dir> [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>] [--if-installed <sha256:hex|none>]
  agenthof registry list --config <dir>
  agenthof registry enable|disable <agent> --config <dir> [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]
  agenthof run <role> <workflow> --input <text> [--as <user>] [--groups <a,b>] [--token <jwt>] [--config <dir>] [--log-dir <dir>] [--artifact-dir <dir>] [--tool-proxy-addr <addr>] [--log-level debug|info|warn|error] [--log-format text|json] [--server <url>]
  agenthof serve [--addr 127.0.0.1:8080] [--allow-non-loopback] [--addr-file <path>] [--config <dir>] [--log-dir <dir>] [--artifact-dir <dir>] [--control-log <path>] [--max-concurrent-runs <n>] [--shutdown-timeout <dur>] [--log-level ...] [--log-format ...]  (AGENTHOF_OIDC_ISSUER required)
  agenthof audit <run-id> [--log-dir <dir>] [--server <url>] [--token <jwt>]
  agenthof audit verify <run-id> [--expect-head <hex>] [--log-dir <dir>]
  agenthof audit verify control [--control-log <path>] [--expect-head <hex>]
  agenthof audit control [--control-log <path>]
  agenthof audit repair control [--control-log <path>] [--config <dir>] [--as <user>] [--groups <a,b>] [--token <jwt>]
  agenthof runs prune --older-than <duration> [--log-dir <dir>] [--artifact-dir <dir>]
  agenthof gateway provision --config <dir> [--admin-base <url>]  (provisions a per-role model key for the reserved model gateway; no run consumes it)
  agenthof investigate [--since <dur|RFC3339>] [--until <dur|RFC3339>] [--invoker <id>] [--agent <name>] [--outcome <name>] [--run <run-id>] [--config-hash <hex>] [--json] [--log-dir <dir>] [--control-log <path>] [--server <url>] [--token <jwt>]
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
		return cmdRun(argv[1:], stdout, stderr)
	case "audit":
		return cmdAudit(argv[1:], stdout)
	case "runs":
		return cmdRuns(argv[1:], stdout)
	case "gateway":
		return cmdGateway(argv[1:], stdout)
	case "investigate":
		return cmdInvestigate(argv[1:], stdout)
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return cmdServe(ctx, argv[1:], stdout, stderr)
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

// resolveRunConfig resolves the configuration a run executes under: the
// INSTALLED snapshot beside controlLog (never the --config directory),
// loaded in full and validated by registry.Build — ONE function, shared by
// `run` and `serve`. installed=false means nothing is installed and the
// caller must refuse; errs holds every load error followed by every
// validation error, in order (cfg is returned even then so callers can
// report them). Callers test errs BEFORE installed: a malformed pointer
// reads back as not-installed-with-an-error and must never invite a
// bootstrap over a damaged store. hash is the installed pointer's value,
// verbatim — the hash the installer (apply, or a kill-switch flip) recorded
// for this snapshot, and the key the audit readers join on; the bytes under
// it are read unverified (docs/control-plane-lifecycle.md, honest limits).
// It is never empty when installed and errs is nil. applyFloorErrors is
// not run here: it is a property of what may be installed, and the snapshot
// passed it at apply.
func resolveRunConfig(controlLog string) (cfg config.Config, reg *registry.Registry, hash string, installed bool, errs []error) {
	cfg, hash, installed, loadErrs := config.LoadInstalled(installedStore(controlLog))
	errs = append(errs, loadErrs...)
	if !installed {
		return cfg, nil, "", false, errs
	}
	reg, valErrs := registry.Build(cfg)
	for _, e := range valErrs {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		return cfg, nil, hash, true, errs
	}
	return cfg, reg, hash, true, nil
}

// cmdApply is `apply`: flags, the invoker, the ledger-writable check and
// the refused-token branch (which records a fixed reason and never reaches
// the installed configuration), then applyConfig — the one apply the
// server runs too. Exit 0 only when a snapshot was installed AND recorded;
// 1 for every recorded denial, a busy lock, a failed precondition, the
// install-then-record gap, and a damaged ledger (which prints the repair
// hint and records nothing); 2 for usage.
func cmdApply(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	cfgDir := fs.String("config", "./config", "config directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token (ID token, or an access token minted for AGENTHOF_OIDC_AUDIENCE) to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	ifInstalled := fs.String("if-installed", "", "proceed only if the installed configuration is this sha256:<hex>, or `none` (nothing installed); a mismatch exits 1 and records nothing")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pre, ok := parseIfInstalled(*ifInstalled)
	if !ok {
		_, _ = fmt.Fprintln(out, "apply: --if-installed must be sha256:<64 lowercase hex digits> or none")
		return 2
	}

	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "apply: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}

	// Verify the control chain FIRST, before any append (including the
	// refused-token append below): a torn or broken control ledger means
	// the ledger itself is unwritable, so the "audit repair control" hint
	// must always be what a damaged ledger prints, regardless of which
	// branch would otherwise have run next. applyConfig repeats this check
	// (it must never append to a ledger it has not verified); the second
	// open costs one verify of a small file.
	c, err := ledger.Open(*controlLog, ledger.Locked)
	if err != nil {
		if errors.Is(err, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "apply: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control ledger damaged; run: agenthof audit repair control --control-log %s --config %s\n", *controlLog, *cfgDir)
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

	res := applyConfig(applyRequest{
		ControlLog: *controlLog, Invoker: inv, AssertedAs: assertedAs,
		Source: dirSource(*cfgDir), Precondition: pre, AllowBootstrap: true,
	}, out)
	switch res.Kind {
	case applyInstalled:
		return 0
	case applyLedgerDamaged:
		_, _ = fmt.Fprintf(out, "control ledger damaged; run: agenthof audit repair control --control-log %s --config %s\n", *controlLog, *cfgDir)
		return 1
	default:
		return 1
	}
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
	cfgDir := fs.String("config", "./config", "configuration directory; list builds and lists it; enable|disable use it to look up and flip the agent only while nothing is installed (afterwards the installed snapshot is flipped and re-installed)")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path (enable/disable only)")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token (ID token, or an access token minted for AGENTHOF_OIDC_AUDIENCE) to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
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
// enable|disable`. Every branch that can write a control event does so
// before returning, once the control chain itself is known writable; the
// only unrecorded exits are a control ledger that cannot be opened and a
// final append that fails AFTER the state already changed (the documented
// residual window). With something installed the flip is a re-snapshot of
// the installed configuration (flipInstalled); with nothing installed it is
// the bootstrap-era path below — the directory is the only configuration
// there is, so the bit is flipped there and the first apply installs the
// directory as flipped — marked Bootstrap on its record.
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
		_, _ = fmt.Fprintf(out, "control ledger damaged; run: agenthof audit repair control --control-log %s --config %s\n", controlLog, cfgDir)
		return 1
	}
	_ = c.Close()

	// recordExit appends a terminal control event — a refusal or an error,
	// never the success path (which carries a config hash and is built inline
	// below) — and returns the process exit code. The control chain is already
	// known writable, so the only reason the recorded outcome and the returned
	// code can disagree is an append that itself fails here.
	recordExit := func(outcome string, reason *control.Reason) int {
		head, appendErr := control.Append(controlLog, control.Event{
			Action:     action,
			Agent:      target,
			Outcome:    outcome,
			Reason:     reason,
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

	if refused {
		// Never echo the raw token, nor the go-oidc error text, into the
		// ledger: it can echo claim values from the (unverified) token
		// (see resolveInvoker's doc comment) — the recorded reason is a
		// fixed string; only the printed line below shows verifyErr.
		_, _ = fmt.Fprintf(out, "registry %s: token authentication failed: %v\n", action, verifyErr)
		return recordExit("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"})
	}

	// Authorize before loading --config whenever a snapshot is installed: the
	// invoker is checked against the INSTALLED configuration's roles — what a
	// previous apply approved — so an unauthorized caller learns one refusal
	// and never makes this command read --config at all (mirroring the apply
	// path, which records one refusal and never the config's own parse errors).
	// Only the bootstrap-era fallback — nothing installed yet — needs
	// --config's roles to authorize, so that case loads first, below. A
	// pointer present but unusable means nobody can be authorized: fail closed,
	// recorded, nothing flipped.
	installedRoles, installedHash, installed, instErr := config.InstalledRoles(installedStore(controlLog))
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(instErr)})
	}
	if installed && !authz.ControlAllows(installedRoles, inv, action) {
		reason := control.NotAuthorized(action)
		_, _ = fmt.Fprintf(out, "registry %s: %s\n", action, reason.Message)
		return recordExit("refused", reason)
	}
	if installed {
		return flipInstalled(action, target, installedStore(controlLog), installedHash, controlLog, inv, assertedAs, recordExit, out)
	}

	// Nothing installed: load --config. It supplies the fallback roles the
	// invoker is authorized against, the unknown-agent check and SetEnabled
	// below. Never registry.Build: with the target agent disabled, Build
	// rejects the config (disabled-agent-ref), which would make a disabled
	// agent un-re-enableable. The control chain is already known writable,
	// so a config that fails to load at all is a recordable denial —
	// outcome "error", reason io_error — never a silent exit and never
	// conflated with "agent not found", which is reserved for a config that
	// loaded cleanly and genuinely lacks the name. The directory is what
	// this path mutates: the first apply will install it as flipped.
	cfg, loadErrs := config.LoadDir(cfgDir)
	if len(loadErrs) > 0 {
		for _, e := range loadErrs {
			_, _ = fmt.Fprintln(out, e)
		}
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(loadErrs[0])})
	}
	if !authz.ControlAllows(cfg.Roles, inv, action) {
		reason := control.NotAuthorized(action)
		_, _ = fmt.Fprintf(out, "registry %s: %s\n", action, reason.Message)
		return recordExit("refused", reason)
	}

	known := false
	for _, a := range cfg.Agents {
		if a.Name == target {
			known = true
			break
		}
	}
	if !known {
		return recordExit("refused", &control.Reason{Code: control.CodeAgentNotFound, Message: fmt.Sprintf("agent %s not found", target)})
	}

	enabled := action == "enable"
	if setErr := registry.SetEnabled(cfgDir, target, enabled); setErr != nil {
		_, _ = fmt.Fprintln(out, setErr)
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(setErr)})
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
		// This path runs only while nothing is installed: the record is
		// marked so the audit readers never mistake the directory's hash for
		// an install (control.Installing).
		Bootstrap: true,
	})
	if err != nil {
		_, _ = fmt.Fprintln(out, "state changed; event NOT recorded")
		return 1
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	return 0
}

// flipInstalled is the kill switch against an installed snapshot (every
// flip once something is installed): stage a copy of the installed snapshot
// under the store, flip the one bit on the copy, hash the copy, and install
// it through the same store functions apply uses. The configuration
// directory is not touched — after a flip, --config and the installed
// snapshot disagree until the next apply re-asserts the directory (the
// declared-state model, docs/control-plane-lifecycle.md). Every failure
// before the commit changes nothing and is recorded; the hash precedes the
// state change, so a hash failure is a plain recorded error. After the
// commit the pointer has moved and only the success append remains: a
// failure there prints "state changed; event NOT recorded", and audit
// control / audit verify control flag the pointer-vs-ledger mismatch.
// Disabling an already-disabled agent whose snapshot a flip wrote yields the
// same bytes → the same hash → CommitSnapshot's identical-snapshot branch
// re-points; the first flip on apply-written bytes always yields a new hash
// (SetEnabled re-marshals the file).
func flipInstalled(action, target, store, hash, controlLog string, inv identity.Invoker, assertedAs string,
	recordExit func(outcome string, reason *control.Reason) int, out io.Writer) int {
	temp, stageErr := config.StageSnapshot(store, config.SnapshotDir(store, hash))
	if stageErr != nil {
		_, _ = fmt.Fprintln(out, stageErr)
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(stageErr)})
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temp)
		}
	}()

	// Lenient load, never registry.Build (see cmdRegistryFlip). A snapshot
	// that loaded at apply and no longer does is damage: recorded io_error.
	cfg, loadErrs := config.LoadDir(temp)
	if len(loadErrs) > 0 {
		for _, e := range loadErrs {
			_, _ = fmt.Fprintln(out, e)
		}
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(loadErrs[0])})
	}
	// The lookup is in the INSTALLED snapshot: an agent whose file exists in
	// the directory but was never applied is not installed, so there is
	// nothing to flip.
	known := false
	for _, a := range cfg.Agents {
		if a.Name == target {
			known = true
			break
		}
	}
	if !known {
		return recordExit("refused", &control.Reason{Code: control.CodeAgentNotFound, Message: fmt.Sprintf("agent %s not found", target)})
	}

	enabled := action == "enable"
	if setErr := registry.SetEnabled(temp, target, enabled); setErr != nil {
		_, _ = fmt.Fprintln(out, setErr)
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(setErr)})
	}
	// Through the hashConfigDir seam, so a hash failure is exercisable by a
	// test; it precedes the commit, so it leaves the pointer untouched.
	h, hashErr := hashConfigDir(temp)
	if hashErr != nil {
		_, _ = fmt.Fprintln(out, hashErr)
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(hashErr)})
	}
	if err := config.CommitSnapshot(store, temp, h); err != nil {
		// CommitSnapshot leaves the pointer exactly as it was on any error.
		_, _ = fmt.Fprintln(out, err)
		return recordExit("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(err)})
	}
	committed = true
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	_, _ = fmt.Fprintf(out, "agent %s %s\n", target, state)

	// Test-only crash hook: the process dies after the pointer moved but
	// before the success append — the residual window, exercisable by a
	// test instead of an unreproducible race (the bootstrap path has the
	// same hook after its SetEnabled).
	if os.Getenv("AGENTHOF_TEST_CRASH_AT") == "after_state_before_append" {
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

// newBroker builds the process credential broker. Dispatch routes each
// resource's grant to the right sub-broker: a direct-bearer (static_env)
// grant to StaticEnv, a client_credentials grant to ClientCredentials, and a
// token_exchange grant to TokenExchange, which exchanges the invoker's
// verified token (subjectTokenType names its kind) for a per-user upstream
// token. Extracted so the routing is unit-testable without a live run.
//
// A broker's error text can reach the ledger: a failure while the tool
// proxy starts is recorded under the fixed reason "tool proxy start failed",
// but a failure mid-step is recorded as the tool_call's reason verbatim
// (capped at 200 runes) — which is why TokenExchange speaks only a fixed
// vocabulary and never echoes the authorization server.
func newBroker(subjectTokenType string) broker.Broker {
	// A hung upstream token endpoint must not block the outbound call
	// forever: an explicit client with a timeout is required here,
	// mirroring the proxy's own connectTimeout, rather than nil (which
	// falls back to http.DefaultClient, which has no timeout).
	// token_exchange is the first grant to put a secret (the invoker's subject
	// token) in the POST body. Go re-sends a body across a 307/308 redirect
	// while stripping only the Authorization header, so a redirecting token
	// endpoint could carry the human's token to another host. Refuse to follow
	// redirects: a 3xx then lands in the broker's fixed-vocabulary failure path.
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return broker.Dispatch{
		StaticEnv:         broker.StaticEnv{},
		ClientCredentials: broker.NewClientCredentials(httpClient),
		TokenExchange:     broker.NewTokenExchange(httpClient, subjectTokenType),
	}
}

// cmdRun runs one workflow. out receives command results (and usage errors,
// like every subcommand); stderr receives operational diagnostics built by
// obs.New — the third channel, separate from stdout and from the run ledger.
func cmdRun(args []string, out, stderr io.Writer) int {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(out, "run needs: <role> <workflow>")
		return 2
	}
	role, workflow := args[0], args[1]
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	input := fs.String("input", "", "task input for the workflow")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token (ID token, or an access token minted for AGENTHOF_OIDC_AUDIENCE) to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	server := fs.String("server", "", "run over an agenthof serve API at this base URL (env AGENTHOF_SERVER); needs --token/AGENTHOF_TOKEN")
	cfgDir := fs.String("config", "./config", "configuration directory you apply from; run executes the INSTALLED configuration (see --control-log), not this directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	artifactDir := fs.String("artifact-dir", ".agenthof/artifacts", "artifact store directory")
	// Accepted for forward-compat: the tool proxy always binds 127.0.0.1:0
	// regardless of this flag's value today.
	fs.String("tool-proxy-addr", "127.0.0.1:0", "tool-proxy bind address (currently always binds 127.0.0.1:0; reserved for future use)")
	// Empty defaults are sentinels: an unset flag falls through to the env
	// variable, then to info / text (resolveLogConfig).
	logLevel := fs.String("log-level", "", "operational log level: debug|info|warn|error (default info; env "+envLogLevel+")")
	logFormat := fs.String("log-format", "", "operational log format: text|json (default text; env "+envLogFormat+")")
	fs.SetOutput(out)
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	if *input == "" {
		_, _ = fmt.Fprintln(out, "run needs --input")
		return 2
	}
	level, format, err := resolveLogConfig(*logLevel, *logFormat, os.Getenv)
	if err != nil {
		// A usage error, printed where every other usage error goes: stdout.
		_, _ = fmt.Fprintf(out, "run: %v\n", err)
		return 2
	}
	// Diagnostics go to the stderr writer threaded from dispatch — never to
	// out and never into the ledger. Run lifecycle is Debug: the result line
	// on stdout below is the Info-level signal already.
	logger := obs.New(stderr, level, format)
	logger.Debug("run invoked", "role", role, "workflow", workflow)

	if base := serverBase(*server); base != "" {
		tok := serverToken(*token)
		if tok == "" {
			_, _ = fmt.Fprintln(out, "run: --server needs --token or AGENTHOF_TOKEN")
			return 2
		}
		if *as != "" || *groups != "" {
			_, _ = fmt.Fprintln(stderr, "run: --as/--groups are ignored with --server; the server authenticates your --token")
		}
		return runViaServer(base, tok, role, workflow, *input, out)
	}

	r := resolveInvokerForRun(*as, *groups, *token)
	inv, refused, usageErr, verifyErr := r.inv, r.refused, r.usageErr, r.verifyErr
	if usageErr {
		_, _ = fmt.Fprintln(out, "run: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	if refused {
		// Never echo the raw token: it's a bearer credential. Nor do we
		// echo the go-oidc error text into the ledger below — it can
		// echo claim values from the (unverified) token.
		_, _ = fmt.Fprintf(out, "run: token authentication failed: %v\n", verifyErr)
		runID, refErr := engine.Refuse(*logDir, role, workflow, inv, "token verification failed", nil)
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "run %s refused: token verification failed\n", runID)
		return 1
	}

	cfg, reg, h, installed, cfgErrs := resolveRunConfig(*controlLog)
	for _, e := range cfgErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(cfgErrs) > 0 {
		// Checked BEFORE installed: a malformed pointer or a snapshot that
		// is gone or no longer loads is a damaged install, never "run apply
		// first". No fallback to --config, no re-bootstrap hint: a run has
		// no business touching the store; the control-plane remedies are in
		// docs/control-plane-lifecycle.md.
		reason := "configuration invalid: " + cfgErrs[0].Error()
		runID, refErr := engine.Refuse(*logDir, role, workflow, inv, reason, nil)
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "run %s refused: configuration invalid\n", runID)
		return 1
	}
	if !installed {
		// Fail closed, recorded: a fallback to --config would make the
		// directory the executed configuration exactly when the control
		// plane has said nothing. The remedy is named with the exact flags.
		_, _ = fmt.Fprintf(out, "run: %s under %s; run: agenthof apply --config %s --control-log %s\n",
			msgNoConfigInstalled, installedStore(*controlLog), *cfgDir, *controlLog)
		runID, refErr := engine.Refuse(*logDir, role, workflow, inv, msgNoConfigInstalled, nil)
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "run %s refused: %s\n", runID, msgNoConfigInstalled)
		return 1
	}
	// The pre-run gate — shared with spawned children, so a child fronting an
	// on-behalf-of resource under a dev identity is refused the same way.
	if reason, refused := preRunRefusal(cfg, reg, workflow, inv); refused {
		runID, refErr := engine.Refuse(*logDir, role, workflow, inv, reason, nil)
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "run %s refused: %s\n", runID, reason)
		return 1
	}
	// One broker for the process; one runDeps for this run and every child
	// it spawns. The verified subject token goes to the gateways and nowhere
	// else — never to the engine, Binding, or the ledger. The compartment
	// supervisor is the spawn door's only way to run a child: unset (valid
	// only when no agent may spawn), every spawn is refused.
	b := newBroker(subjectTokenTypeFromEnv(os.Getenv))
	var sup refspawn.Provisioner
	if ep := cfg.Gateway.SpawnSupervisor; ep != "" {
		client, err := refspawn.New(ep, logger)
		if err != nil {
			_, _ = fmt.Fprintf(out, "run: %v\n", err)
			return 2
		}
		sup = client
	}
	deps := newRunDeps(cfg, reg, b, logger, *logDir, *artifactDir, h, r.subjectToken, sup)
	res, err := engine.Run(context.Background(), reg, role, workflow, *input, inv, deps.executor(), deps.options(nil))
	if err != nil && res.Status == "refused" {
		_, _ = fmt.Fprintf(out, "run %s refused: %v\n", res.RunID, err)
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "run %s error: %v\n", res.RunID, err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "run %s finished: %s\n", res.RunID, res.Status)
	if res.Status != "succeeded" {
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
		// A control-only role runs nothing, so it needs no provider key: a
		// key with budget $0 would be a credential nothing consumes.
		if len(role.Workflows) == 0 {
			_, _ = fmt.Fprintf(out, "role %s: owns no workflows; no key provisioned\n", role.Name)
			continue
		}
		created, err := p.EnsureRoleKey(".", role)
		if err != nil {
			_, _ = fmt.Fprintf(out, "role %s: %v\n", role.Name, err)
			return 1
		}
		if created {
			_, _ = fmt.Fprintf(out, "provisioned key for role %s (budget $%g); reserved model gateway, not consumed by a run\n", role.Name, role.BudgetUSDMonth)
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
	server := fs.String("server", "", "read the audit from an agenthof serve API at this base URL (env AGENTHOF_SERVER)")
	token := fs.String("token", "", "bearer for --server (env AGENTHOF_TOKEN)")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if base := serverBase(*server); base != "" {
		return auditViaServer(base, serverToken(*token), runID, out)
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
// After the integrity line it reports the installed pointer's standing:
// whether <dir of --control-log>/installed/current names the last recorded
// install — the last successful apply or kill-switch flip on record
// (nothing is printed when nothing was ever installed). That is
// informational here; audit verify control turns a mismatch into an exit
// code.
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
	line, _ := installedPointerLine(*controlLog, records)
	_, _ = fmt.Fprint(out, line)
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
// for an --expect-head mismatch (hash only — count is informational);
// 5 when the installed pointer (<dir of --control-log>/installed/current)
// does not name the last recorded install (the last successful apply or
// kill-switch flip — control.Installing) — an install whose event was never
// appended, or whose record was lost — checked last; 0 otherwise.
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
	line, mismatch := installedPointerLine(*controlLog, records)
	_, _ = fmt.Fprint(out, line)
	if tainted, seq := control.IsTainted(records); tainted {
		_, _ = fmt.Fprintf(out, "control ledger TAINTED: repaired at seq %d\n", seq)
		return 3
	}
	if *expectHead != "" && *expectHead != head.Hash {
		_, _ = fmt.Fprintf(out, "expect-head mismatch: want %s, got %s\n", *expectHead, head.Hash)
		return 4
	}
	if mismatch {
		return exitInstalledMismatch
	}
	return 0
}

// cmdAuditRepairControl implements `audit repair control [--control-log
// <path>] [--config <dir>] [--as <user>] [--groups <a,b>] [--token <jwt>]`
// (spec §3.6): it resolves the repairing operator's identity exactly as
// apply/registry do and authorizes that invoker against the installed
// configuration's roles — or, when nothing is installed yet, the --config
// dir's — (authz.ControlAllows, "repair"); a refusal — like an
// authentication refusal and like roles that cannot be read — is printed
// and exits nonzero WITHOUT writing any control event, because the ledger
// here may be exactly the torn file being repaired. Only an authorized
// invoker reaches control.Repair, which moves the torn fragment aside,
// truncates the live file, and appends the chained "repair" event that
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
	cfgDir := fs.String("config", "./config", "config directory; its roles decide who may repair only until a configuration is installed")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token (ID token, or an access token minted for AGENTHOF_OIDC_AUDIENCE) to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
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

	// Authorize against the installed configuration's roles when one is
	// installed under this control root; else fall back to --config's roles,
	// read without validation (the ledger may be the torn one, so the config
	// is the only other input). Nothing in this stretch appends: a refusal —
	// or roles that cannot be read, installed or not — is printed and exits
	// nonzero, fail-closed, because the one ledger to record it in is the
	// damaged one. The check runs before the ledger is even looked at, so a
	// refused caller learns nothing about it.
	store := installedStore(*controlLog)
	roles, _, installed, instErr := config.InstalledRoles(store)
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprintf(out, "audit repair control: cannot read the installed configuration under %s; refusing to repair (remove %s to re-bootstrap)\n",
			store, filepath.Join(store, config.InstalledPointer))
		return 1
	}
	if !installed {
		cfg, loadErrs := config.LoadDir(*cfgDir)
		if len(loadErrs) > 0 {
			for _, e := range loadErrs {
				_, _ = fmt.Fprintln(out, e)
			}
			_, _ = fmt.Fprintf(out, "audit repair control: cannot read the configuration at %s; refusing to repair\n", *cfgDir)
			return 1
		}
		roles = cfg.Roles
	}
	if !authz.ControlAllows(roles, inv, "repair") {
		_, _ = fmt.Fprintf(out, "audit repair control: %s\n", control.NotAuthorized("repair").Message)
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
	// artifact-dir is not an error (no run has written one yet) — mirror the
	// missing-log-dir case
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
	server := fs.String("server", "", "investigate against an agenthof serve API at this base URL (env AGENTHOF_SERVER)")
	token := fs.String("token", "", "bearer for --server (env AGENTHOF_TOKEN)")
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

	if base := serverBase(*server); base != "" {
		q := apiclient.InvestigateQuery{Invoker: f.Invoker, Agent: f.Agent, Outcome: f.Outcome, Run: f.Run, ConfigHash: f.ConfigHash}
		if f.Since != nil {
			q.Since = f.Since.Format(time.RFC3339)
		}
		if f.Until != nil {
			q.Until = f.Until.Format(time.RFC3339)
		}
		return investigateViaServer(base, serverToken(*token), q, *jsonOut, out)
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
