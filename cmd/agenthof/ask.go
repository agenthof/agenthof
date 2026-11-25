package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/completeness"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/refspawn"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

const (
	// orchestratorAgent names the installed agent whose may_spawn list is the
	// orchestrator's authority: everything ask may start, and nothing else.
	orchestratorAgent = "orchestrator"
	// orchestratorRole and askWorkflow label the orchestrator's own run in
	// its ledger; ask drives spawns directly and runs no workflow steps.
	orchestratorRole = "orchestrator"
	askWorkflow      = "ask"
	// routerRole and routerWorkflow are the installed classifier the
	// orchestrator spawns first. It must be on the orchestrator's may_spawn
	// like any other child, and is never offered as a menu choice.
	routerRole     = "router-chat"
	routerWorkflow = "router-chat"
	// orchestrateStep labels the single step window the orchestrator's own
	// ledger wraps its spawns in, so the ledger accounts for itself like any
	// governed run's: every door (spawn) event sits inside the window and the
	// step terminal carries the door-call count the gate admitted.
	orchestrateStep = "orchestrate"
	// reasonOffMenu is the fixed terminal reason recorded when the classifier
	// names a target that is not on the offered menu — a misbehaviour signal,
	// never the classifier's own (untrusted) text.
	reasonOffMenu = "classifier named a target that is not on the menu"
)

// Convention: the installed configuration names the trusted orchestrator
// agent exactly orchestratorAgent and the classifier exactly routerRole/
// routerWorkflow; ask drives these by name, not by discovery. The orchestrator
// AgentDef's endpoint is never dialled by ask (ask spawns its children
// directly rather than running the orchestrator as a step), so it may be any
// placeholder; but `run orchestrator ask` WOULD front that endpoint and hand
// whatever listens there the orchestrator's may_spawn authority, so the
// orchestrator agent is meant to be run only through this command.

// menuEntry is one choice offered to the classifier. Its JSON shape is the
// classifier's input contract; the key names are fixed by its signed card.
type menuEntry struct {
	Role        string `json:"role"`
	Workflow    string `json:"workflow"`
	Description string `json:"description"`
}

// classifierInput is the classifier's whole input: the menu and the user's
// prompt, under the keys its card fixes.
type classifierInput struct {
	Menu      []menuEntry `json:"menu"`
	Utterance string      `json:"utterance"`
}

// classifierPick is the classifier's answer when it chose an entry; the
// other answer is the literal null.
type classifierPick struct {
	Role     string `json:"role"`
	Workflow string `json:"workflow"`
}

// projectMenu turns the orchestrator's may_spawn list into the menu offered
// to the classifier, in list order, each entry described by its workflow.
// The classifier's own target is not a choice.
func projectMenu(orch config.AgentDef, reg *registry.Registry) []menuEntry {
	menu := []menuEntry{}
	for _, t := range orch.MaySpawn {
		if t.Role == routerRole && t.Workflow == routerWorkflow {
			continue
		}
		wf, ok := reg.Workflow(t.Workflow)
		if !ok {
			continue // validation rejects this; never offer what cannot run
		}
		desc := wf.Description
		if desc == "" && len(wf.Steps) > 0 {
			if a, ok := reg.Agent(wf.Steps[0].Agent); ok {
				desc = a.Description
			}
		}
		menu = append(menu, menuEntry{Role: t.Role, Workflow: t.Workflow, Description: desc})
	}
	return menu
}

// spawnFunc is the orchestrator's one way to start a child: it counts the
// gate entry, drives the shared spawn gate (the may_spawn re-check, caps and
// parent spawn event), and fails closed on a parent-ledger write error so a
// child's output is never used once the record of it could not be written.
type spawnFunc func(ctx context.Context, role, workflow, input string) (rungateway.SpawnResult, error)

// classify asks the installed classifier which menu entry fits the prompt.
// The spawn goes through the gateway's spawn gate, so the classifier is
// subject to the same may_spawn check, caps and parent-ledger record as any
// child. Its answer is read from the artifact store by the recorded digest.
// A spawn that did not succeed, or an answer that is neither a complete pick
// nor null, is an error — never a guessed pick.
func classify(ctx context.Context, spawn spawnFunc, menu []menuEntry, prompt string, store *artifact.Store) (role, workflow string, matched bool, err error) {
	in, err := json.Marshal(classifierInput{Menu: menu, Utterance: prompt})
	if err != nil {
		return "", "", false, err
	}
	res, err := spawn(ctx, routerRole, routerWorkflow, string(in))
	if err != nil {
		return "", "", false, fmt.Errorf("classifier spawn did not complete: %w", err)
	}
	if res.Status != "succeeded" {
		reason := res.Reason
		if reason == "" {
			reason = res.Status
		}
		return "", "", false, fmt.Errorf("classifier %s: %s", res.Status, reason)
	}
	if res.OutputSHA == "" {
		return "", "", false, errors.New("classifier produced no answer")
	}
	body, err := store.Get(res.OutputSHA)
	if err != nil {
		return "", "", false, errors.New("classifier answer not found in the artifact store")
	}
	body = strings.TrimSpace(body)
	if body == "null" {
		return "", "", false, nil
	}
	var pick classifierPick
	if err := json.Unmarshal([]byte(body), &pick); err != nil || pick.Role == "" || pick.Workflow == "" {
		return "", "", false, errors.New("classifier answer is neither a pick nor null")
	}
	return pick.Role, pick.Workflow, true, nil
}

// cmdAsk is `ask [flags] "<prompt>"`: a trusted command, not a contained
// agent. It establishes its own run from the installed configuration, offers
// the orchestrator agent's may_spawn list to the classifier, and reports the
// pick. Flags must precede the prompt, which is the single trailing
// positional argument; a prompt that begins with "-" must be preceded by "--".
// Only the answer is written to out; every usage error, refusal and status
// line goes to stderr, so a piped stdout carries the answer alone.
func cmdAsk(args []string, out, stderr io.Writer) int {
	fs := flag.NewFlagSet("ask", flag.ContinueOnError)
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	cfgDir := fs.String("config", "./config", "configuration directory you apply from; ask runs the INSTALLED configuration (see --control-log), not this directory")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it")
	verifyKey := fs.String("verify-key", "", "path of the pinned operator public key; default verify.pub beside --control-log")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory")
	artifactDir := fs.String("artifact-dir", ".agenthof/artifacts", "artifact store directory")
	yes := fs.Bool("yes", false, "run the chosen agent without asking for confirmation")
	logLevel := fs.String("log-level", "", "operational log level: debug|info|warn|error (default info; env "+envLogLevel+")")
	logFormat := fs.String("log-format", "", "operational log format: text|json (default text; env "+envLogFormat+")")
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Exactly one positional prompt. Flag parsing stops at the first
	// non-flag, so a flag written AFTER the prompt lands here as a leftover
	// positional: it is refused, never folded into the prompt (a --token or
	// --as after the prompt would otherwise be sent to the model or silently
	// dropped). A prompt that begins with "-" is parsed as a flag unless the
	// caller separates it with "--".
	rest := fs.Args()
	if len(rest) == 0 || strings.TrimSpace(rest[0]) == "" {
		_, _ = fmt.Fprintln(stderr, `ask needs a prompt: ask [flags] "<prompt>" (flags precede the prompt; use -- before a prompt that begins with -)`)
		return 2
	}
	if len(rest) > 1 {
		_, _ = fmt.Fprintf(stderr, "ask takes exactly one prompt; %d extra argument(s) followed it. Flags must precede the prompt.\n", len(rest)-1)
		return 2
	}
	prompt := rest[0]
	level, format, err := resolveLogConfig(*logLevel, *logFormat, os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ask: %v\n", err)
		return 2
	}
	logger := obs.New(stderr, level, format)

	r := resolveInvokerForRun(*as, *groups, *token)
	inv := r.inv
	if r.usageErr {
		_, _ = fmt.Fprintln(stderr, "ask: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	refuse := func(reason string) int {
		runID, refErr := engine.Refuse(*logDir, orchestratorRole, askWorkflow, inv, reason, nil)
		if refErr != nil {
			_, _ = fmt.Fprintln(stderr, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "ask %s refused: %s\n", runID, reason)
		return 1
	}
	if r.refused {
		_, _ = fmt.Fprintf(stderr, "ask: token authentication failed: %v\n", r.verifyErr)
		return refuse("token verification failed")
	}

	// The installed snapshot, vouched exactly as run vouches it — never the
	// raw configuration directory.
	cfg, reg, h, installed, cfgErrs, unverified := resolveRunConfig(*controlLog, *verifyKey, verifyAndAdvance)
	for _, e := range cfgErrs {
		_, _ = fmt.Fprintln(stderr, e.Error())
	}
	if len(cfgErrs) > 0 {
		return refuse("configuration invalid: " + cfgErrs[0].Error())
	}
	if unverified != nil {
		if unverified.Transient() {
			_, _ = fmt.Fprintf(stderr, "ask: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "ask: %s\n", unverified.Error())
		return refuse(unverified.Error())
	}
	if !installed {
		_, _ = fmt.Fprintf(stderr, "ask: %s under %s; run: agenthof apply --config %s --control-log %s\n",
			msgNoConfigInstalled, installedStore(*controlLog), *cfgDir, *controlLog)
		return refuse(msgNoConfigInstalled)
	}
	orch, ok := reg.Agent(orchestratorAgent)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "ask: the installed configuration has no %q agent\n", orchestratorAgent)
		return 1
	}
	// The orchestrator run passes the registry gate every run does: the role
	// exists, owns the ask workflow, and admits this invoker. Without this the
	// orchestrator role's allowed_groups would be decorative — a stamped role
	// never checked against the caller — so it runs before any spawn.
	if reason, admitted := engine.Admit(reg, orchestratorRole, askWorkflow, inv); !admitted {
		return refuse(reason)
	}
	if reason, refused := preRunRefusal(cfg, reg, askWorkflow, inv); refused {
		return refuse(reason)
	}

	var sup refspawn.Provisioner
	if ep := cfg.Gateway.SpawnSupervisor; ep != "" {
		client, err := refspawn.New(ep, logger)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "ask: %v\n", err)
			return 2
		}
		sup = client
	}
	deps := newRunDeps(cfg, reg, newBroker(subjectTokenTypeFromEnv(os.Getenv)), logger, *logDir, *artifactDir, h, r.subjectToken, sup)
	store, err := artifact.NewStore(*artifactDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ask: %v\n", err)
		return 1
	}

	// The projected menu is offered to the classifier (the may_spawn re-check
	// at the gate is the authority over any pick, so a thin or forged menu is
	// harmless); the invoker-admitted subset is what "here is what I can do"
	// lists. With the orchestrator unable to start anything but the classifier,
	// there is nothing to route to — say so without spending a spawn.
	menu := projectMenu(orch, reg)
	if len(menu) == 0 {
		_, _ = fmt.Fprintf(stderr, "ask: the %q agent's may_spawn lists no workflow to route to; add targets to it\n", orchestratorAgent)
		return 1
	}
	admitted := admittedMenu(reg, menu, inv)

	// The orchestrator's own run: a ledger of its own, so every spawn it
	// makes is recorded on a parent the way a spawning agent's are.
	runID := engine.NewRunID()
	bind := engine.Binding{Invoker: inv, Role: orchestratorRole, Workflow: askWorkflow, RunID: runID}
	log, err := engine.OpenLog(*logDir, runID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ask: %v\n", err)
		return 1
	}
	defer func() { _ = log.Close() }()

	// One cancellable command context for every spawn: an interrupt or a
	// termination signal cancels a child that is still running.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	gw := rungateway.New(cfg.Gateway, ".", deps.broker, logger, r.subjectToken).WithSpawner(deps)

	fi, statErr := os.Stdin.Stat()
	var served servedLeaf
	code := runOrchestration(ctx, orchestration{
		gw: gw, bind: bind, orch: orch, reg: reg, menu: menu, admitted: admitted, prompt: prompt,
		store: store, configHash: h, log: log, logger: logger,
		yes:         *yes,
		interactive: statErr == nil && fi.Mode()&os.ModeCharDevice != 0,
		outTerminal: isCharDevice(out),
		in:          os.Stdin, out: out, msg: stderr, served: &served,
	})
	// The receipt follows the answer or the failure message, after the run's
	// own terminal event is on its ledger, so the verdicts it reports cover the
	// whole run. The answer was control-char-stripped on a terminal so it
	// cannot drive the cursor to overwrite the receipt.
	receiptAfter(stderr, *logDir, runID, served, cfg.Gateway.Tools)
	return code
}

// receiptAfter prints the receipt, after a separating blank line, once a leaf
// run was started — whether it answered or failed: a leaf that failed may
// already have written to the user's store, and its ledger says whether it
// did. A run that started no leaf (a refusal, a no-match, a declined
// confirmation, a failed classification) ended with its own message and has
// no receipt.
func receiptAfter(w io.Writer, logDir, runID string, served servedLeaf, tools map[string]config.ToolResource) {
	if !served.answered && served.runID == "" {
		return
	}
	_, _ = fmt.Fprintln(w)
	renderReceipt(w, logDir, runID, served, tools)
}

// orchestration is the ask run's own-ledger orchestration: the gateway and
// binding it spawns through, the offered and admitted menus, the artifact
// store, the open run log, and the streams. It is the testable core of cmdAsk
// — everything from the first ledger event through the run's terminal — so the
// ledger shape and its completeness are exercised without disk configuration.
type orchestration struct {
	gw          *rungateway.Gateway
	bind        engine.Binding
	orch        config.AgentDef
	reg         *registry.Registry
	menu        []menuEntry
	admitted    []menuEntry
	prompt      string
	store       *artifact.Store
	configHash  string
	log         *engine.Log
	logger      *slog.Logger
	yes         bool
	interactive bool // stdin is a terminal a person can answer on
	outTerminal bool // stdout is a terminal, so the answer is control-char-stripped
	in          io.Reader
	out, msg    io.Writer
	served      *servedLeaf
}

// runOrchestration writes the ask run's ledger and drives the classify →
// dispatch flow. The ledger accounts for itself like any governed run's: a
// workflow_started that promises door accounting, ONE step window the spawns
// sit inside, and a step terminal carrying the door-call count the gate
// admitted — so `audit` reports completeness, not a false gap. finish is the
// one exit after workflow_started and every path reaches it, so the step and
// the workflow always carry agreeing terminals. The orchestrator fails closed
// on any parent-ledger write error: a child's output is never used once the
// record of it could not be written.
func runOrchestration(ctx context.Context, o orchestration) int {
	var logErr error
	appendEvent := func(e engine.Event) {
		if logErr != nil {
			return
		}
		e.Time = time.Now().UTC()
		e.Binding = o.bind
		logErr = o.log.Append(e)
	}
	// doorCalls counts gate entries — the door calls the gate admits — so the
	// step terminal records the count independently of whether each spawn
	// event's append succeeded. A lost append then shows up as a completeness
	// gap (recorded < admitted).
	doorCalls := 0
	spawn := func(ctx context.Context, role, workflow, input string) (rungateway.SpawnResult, error) {
		doorCalls++
		res, err := o.gw.AuthorizeAndSpawn(ctx, o.bind, o.orch, role, workflow, input, appendEvent, o.logger)
		if err != nil {
			return res, err
		}
		if logErr != nil {
			return res, fmt.Errorf("run ledger write failed: %w", logErr)
		}
		return res, nil
	}

	appendEvent(engine.Event{Type: "workflow_started", ConfigHash: o.configHash, DoorAccounting: engine.DoorAccountingAdmission})
	appendEvent(engine.Event{Type: "step_started", Step: orchestrateStep, Agent: o.orch.Name})
	finish := func(status, reason string, code int) int {
		dc := doorCalls
		stepTerm := "step_failed"
		if status == "succeeded" {
			stepTerm = "step_succeeded"
		}
		appendEvent(engine.Event{Type: stepTerm, Step: orchestrateStep, DoorCalls: &dc})
		appendEvent(engine.Event{Type: "workflow_finished", Status: status, Reason: reason})
		if logErr != nil {
			_, _ = fmt.Fprintf(o.msg, "ask %s: run ledger write failed\n", o.bind.RunID)
			return 1
		}
		return code
	}
	if logErr != nil {
		return finish("failed", "run ledger write failed", 1)
	}

	role, workflow, matched, err := classify(ctx, spawn, o.menu, o.prompt, o.store)
	if err != nil {
		_, _ = fmt.Fprintf(o.msg, "ask %s: %v\n", o.bind.RunID, err)
		return finish("failed", "classification failed", 1)
	}
	status, reason, code := dispatchPick(ctx, pickRun{
		spawn: spawn, reg: o.reg, menu: o.menu, admitted: o.admitted, prompt: o.prompt, store: o.store,
		yes: o.yes, interactive: o.interactive, outIsTerminal: o.outTerminal,
		in: o.in, out: o.out, msg: o.msg, runID: o.bind.RunID, logger: o.logger,
		served: o.served,
	}, role, workflow, matched)
	return finish(status, reason, code)
}

// isCharDevice reports whether w is a terminal (a character device): an
// *os.File whose mode says so. A pipe, a file or an in-memory buffer is not,
// so the answer stays byte-exact when it is not going to a screen.
func isCharDevice(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// admittedMenu is the subset of menu the invoker may actually run: each
// entry's role must admit the invoker to that workflow, judged by the same
// registry gate a run passes. It is what "here is what I can do" lists.
func admittedMenu(reg *registry.Registry, menu []menuEntry, inv identity.Invoker) []menuEntry {
	out := make([]menuEntry, 0, len(menu))
	for _, m := range menu {
		if _, ok := engine.Admit(reg, m.Role, m.Workflow, inv); ok {
			out = append(out, m)
		}
	}
	return out
}

// printMenu lists what ask can do for this invoker: the admitted subset of
// the projected menu, never the classifier's own may_spawn entry.
func printMenu(out io.Writer, runID string, menu []menuEntry) {
	_, _ = fmt.Fprintf(out, "ask %s: nothing fits that request. Here is what I can do:\n", runID)
	for _, m := range menu {
		_, _ = fmt.Fprintf(out, "  %s/%s: %s\n", m.Role, m.Workflow, m.Description)
	}
}

// sanitizeForTerminal drops control characters other than newline and tab
// from an untrusted string bound for a terminal, so a contained leaf's answer
// cannot drive the cursor, recolour, or clear the screen to forge the trust
// signals around it. It is origin.Clean's rule relaxed to keep the line
// structure of a real answer (newlines and tabs) and with no length cap. It
// keeps every graphic rune — IsGraphic, not IsPrint, so non-ASCII spaces like
// NBSP and the ideographic space survive and French/CJK text is not mangled. A
// plain-text look-alike is not prevented by this — only escape sequences are.
func sanitizeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if r == '\n' || r == '\t' || unicode.IsGraphic(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// confirm asks a yes/no question on w and reads the answer from r. yes skips
// the question. The read gives way to ctx, so an interrupt ends the prompt
// instead of leaving it blocked; a cancelled prompt is a decline, with the
// context's error. With nothing to read (a closed or empty input) and no yes
// it refuses with a message instead of assuming consent; why is the reason the
// question was asked, named in that message.
func confirm(ctx context.Context, w io.Writer, r io.Reader, yes bool, prompt, why string) (bool, error) {
	if yes {
		return true, nil
	}
	_, _ = fmt.Fprintf(w, "%s [y/N] ", prompt)
	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		line, err := bufio.NewReader(r).ReadString('\n')
		ch <- readResult{line, err}
	}()
	var res readResult
	select {
	case <-ctx.Done():
		_, _ = fmt.Fprintln(w)
		return false, ctx.Err()
	case res = <-ch:
	}
	if res.err != nil && !errors.Is(res.err, io.EOF) {
		return false, res.err
	}
	if strings.TrimSpace(res.line) == "" && errors.Is(res.err, io.EOF) {
		_, _ = fmt.Fprintf(w, "\nno confirmation available: %s, so it needs --yes or an interactive confirmation\n", why)
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(res.line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// writesInWorkflow reports whether any step agent of the workflow holds a
// read-write tool grant, i.e. running it can write to the user's store.
func writesInWorkflow(reg *registry.Registry, workflow string) bool {
	wf, ok := reg.Workflow(workflow)
	if !ok {
		return false
	}
	for _, st := range wf.Steps {
		if a, ok := reg.Agent(st.Agent); ok && a.HoldsReadWriteToolGrant() {
			return true
		}
	}
	return false
}

// needsConfirm reports whether the workflow must be confirmed before it runs:
// one of its step agents is not declared grounded, or holds a read-write tool
// grant (running it can write to the user's store). An agent it cannot find
// counts as needing confirmation.
func needsConfirm(reg *registry.Registry, workflow string) bool {
	wf, ok := reg.Workflow(workflow)
	if !ok || len(wf.Steps) == 0 {
		return true
	}
	for _, st := range wf.Steps {
		a, ok := reg.Agent(st.Agent)
		if !ok || a.NeedsConfirm() {
			return true
		}
	}
	return false
}

// pickRun is everything dispatchPick needs: the spawn path, the offered and
// admitted menus, the store the answer is read from, and the streams. The
// answer goes to out alone; every other message goes to msg, so piping the
// command yields only the answer.
type pickRun struct {
	spawn         spawnFunc
	reg           *registry.Registry
	menu          []menuEntry // offered to the classifier; a pick must be one of these
	admitted      []menuEntry // the invoker-admitted subset, listed on a no-match
	prompt        string
	store         *artifact.Store
	yes           bool
	interactive   bool // stdin is a terminal a person can answer on
	outIsTerminal bool // stdout is a terminal, so the answer is control-char-stripped
	in            io.Reader
	out, msg      io.Writer
	runID         string
	logger        *slog.Logger
	served        *servedLeaf // when set, filled once a leaf run has been started
}

// servedLeaf records what the receipt needs to know about the picked leaf:
// its child run and the agents its workflow ran, set once the spawn gate
// reported a child run, and whether that run's answer was printed.
type servedLeaf struct {
	answered bool
	runID    string
	agents   []config.AgentDef
}

// dispatchPick acts on the classifier's pick: it must be one of the offered
// menu entries, a pick that is ungrounded or holds a read-write tool grant is
// confirmed, the leaf is spawned through the spawn gate, and its answer is
// read from the store by digest and printed. A leaf run that was started is
// recorded for the receipt whether or not it answered. It returns the run's
// final status, reason and exit code.
func dispatchPick(ctx context.Context, p pickRun, role, workflow string, matched bool) (status, reason string, code int) {
	inMenu := false
	if matched {
		for _, m := range p.menu {
			if m.Role == role && m.Workflow == workflow {
				inMenu = true
				break
			}
		}
	}
	if !inMenu {
		printMenu(p.msg, p.runID, p.admitted)
		// A pick that named an off-menu target (as opposed to the literal
		// null) is classifier misbehaviour: recorded with a fixed reason, never
		// the classifier's own text, so the terminal event tells the two apart.
		if matched {
			return "succeeded", reasonOffMenu, 0
		}
		return "succeeded", "", 0
	}
	_, _ = fmt.Fprintf(p.msg, "ask %s: picked %s/%s\n", p.runID, role, workflow)
	if !p.yes && needsConfirm(p.reg, workflow) {
		writes := writesInWorkflow(p.reg, workflow)
		if !p.interactive {
			why := "is not grounded"
			if writes {
				why = "will write to your store (this cannot be undone)"
			}
			_, _ = fmt.Fprintf(p.msg, "ask %s: %s/%s %s and there is no terminal to confirm on; re-run with --yes\n", p.runID, role, workflow, why)
			return "failed", "not confirmed", 1
		}
		question := fmt.Sprintf("Run %s/%s? Its answer is not grounded.", role, workflow)
		noInput := "this answer is not grounded"
		if writes {
			question = fmt.Sprintf("Run %s/%s? It will write to your store; this cannot be undone.", role, workflow)
			noInput = "this run will write to your store, which cannot be undone"
		}
		ok, err := confirm(ctx, p.msg, p.in, false, question, noInput)
		if err != nil {
			_, _ = fmt.Fprintf(p.msg, "ask %s: confirmation ended: %v\n", p.runID, err)
			return "failed", "confirmation ended", 1
		}
		if !ok {
			_, _ = fmt.Fprintf(p.msg, "ask %s: not run\n", p.runID)
			return "failed", "not confirmed", 1
		}
	}
	res, err := p.spawn(ctx, role, workflow, p.prompt)
	// A child run that was started is reported on however it ended: a leaf
	// that fails after writing has still written.
	if p.served != nil && res.ChildRunID != "" {
		p.served.runID = res.ChildRunID
		p.served.agents = workflowAgents(p.reg, workflow)
	}
	if err != nil {
		_, _ = fmt.Fprintf(p.msg, "ask %s: %s/%s did not complete: %v\n", p.runID, role, workflow, err)
		return "failed", "leaf spawn failed", 1
	}
	if res.Status != "succeeded" {
		why := res.Reason
		if why == "" {
			why = res.Status
		}
		_, _ = fmt.Fprintf(p.msg, "ask %s: %s/%s %s: %s\n", p.runID, role, workflow, res.Status, why)
		return "failed", "leaf " + res.Status, 1
	}
	if res.OutputSHA == "" {
		_, _ = fmt.Fprintf(p.msg, "ask %s: %s/%s produced no answer\n", p.runID, role, workflow)
		return "failed", "no answer", 1
	}
	body, err := p.store.Get(res.OutputSHA)
	if err != nil {
		p.logger.Warn("ask answer read failed", "sha", res.OutputSHA, "err", err)
		_, _ = fmt.Fprintf(p.msg, "ask %s: %s/%s answer is missing from the artifact store: %v\n", p.runID, role, workflow, err)
		return "failed", "answer missing", 1
	}
	if strings.TrimSpace(body) == "" {
		_, _ = fmt.Fprintf(p.msg, "ask %s: %s/%s produced an empty answer\n", p.runID, role, workflow)
		return "failed", "answer empty", 1
	}
	// Byte-exact when piped; on a terminal, control characters are stripped so
	// the contained leaf's answer cannot drive the cursor or forge the receipt
	// that follows it on stderr.
	if p.outIsTerminal {
		body = sanitizeForTerminal(body)
	}
	_, _ = fmt.Fprintln(p.out, body)
	if p.served != nil {
		p.served.answered = true
		p.served.agents = workflowAgents(p.reg, workflow)
	}
	return "succeeded", "", 0
}

// workflowAgents returns the registered agents the workflow's steps run, in
// step order.
func workflowAgents(reg *registry.Registry, workflow string) []config.AgentDef {
	wf, ok := reg.Workflow(workflow)
	if !ok {
		return nil
	}
	var out []config.AgentDef
	for _, st := range wf.Steps {
		if a, ok := reg.Agent(st.Agent); ok {
			out = append(out, a)
		}
	}
	return out
}

// doorKinds are the run-ledger event kinds that record a door call.
var doorKinds = map[string]bool{"model_call": true, "tool_call": true, "exec": true, "spawn": true}

// callCounts is what one run's ledger recorded for the model or tool calls
// under one label (a model call kind, or a tool resource), by status. A
// streamed model call is recorded once as started and never as succeeded, so
// it is counted apart from both.
type callCounts struct {
	attempted, succeeded, streaming, refused int
}

// agentEvidence is what a run's ledger recorded about one agent's calls that
// bears on where an answer came from: whether it generated at all, and how
// many read-only tool calls of its own succeeded.
type agentEvidence struct {
	generated bool // a chat model call that succeeded or was streamed
	reads     int  // succeeded tool calls classified read-only
}

// runFacts is the per-run door evidence the receipt reports, all of it read
// from that run's ledger records.
type runFacts struct {
	doors        map[string]int         // door kind -> count
	modelKinds   map[string]int         // model_call call kind -> count ("" when the record carries none)
	calls        map[string]*callCounts // "model <kind>" | "tool resource <id>" -> counts
	writes       map[string]int         // "<tool> on <resource>" -> succeeded write-classified calls
	unclassified int                    // succeeded tool calls on a resource the configuration does not define
	agents       map[string]*agentEvidence
}

func newRunFacts() *runFacts {
	return &runFacts{doors: map[string]int{}, modelKinds: map[string]int{}, calls: map[string]*callCounts{},
		writes: map[string]int{}, agents: map[string]*agentEvidence{}}
}

// Tool-call classes. A call is a read only when every resource it touched is
// defined in the configuration and lists the tool in read_only_tools; a tool a
// defined resource does not list is a write (an unlisted tool is mutating);
// with no resource recorded, or one the configuration does not define, the
// call cannot be classified.
const (
	toolRead = iota
	toolWrite
	toolUnclassified
)

// classifyTool labels a tool call the ledger recorded as a read or a write,
// from the operator's read_only_tools — the same list a read-only grant is
// validated against. It only labels a call; whether the call happened, and
// how it ended, is the ledger's to say.
func classifyTool(tools map[string]config.ToolResource, tool string, resources []string) int {
	if len(resources) == 0 {
		return toolUnclassified
	}
	class := toolRead
	for _, id := range resources {
		res, ok := tools[id]
		if !ok {
			return toolUnclassified
		}
		listed := false
		for _, name := range res.ReadOnlyTools {
			if name == tool {
				listed = true
				break
			}
		}
		if !listed {
			class = toolWrite
		}
	}
	return class
}

// add folds one run-ledger door record into the facts.
func (f *runFacts) add(r investigate.Record, tools map[string]config.ToolResource) {
	f.doors[r.Kind]++
	var label string
	switch r.Kind {
	case "model_call":
		f.modelKinds[r.CallKind]++
		label = "model " + kindLabel(r.CallKind)
	case "tool_call":
		label = "tool (no resource recorded)"
		if len(r.ResourcesTouched) > 0 {
			label = "tool resource " + strings.Join(r.ResourcesTouched, "+")
		}
	default:
		// The ledger records a status on exec and spawn events too, but the
		// investigate record carries a call status for model and tool calls
		// only, so these are counted as doors and their outcomes are not.
		return
	}
	c := f.calls[label]
	if c == nil {
		c = &callCounts{}
		f.calls[label] = c
	}
	c.attempted++
	switch r.Status {
	case "succeeded":
		c.succeeded++
	case "refused":
		c.refused++
	case "started":
		if r.Kind == "model_call" {
			c.streaming++
		}
	}
	ev := f.agents[r.Agent]
	if ev == nil {
		ev = &agentEvidence{}
		f.agents[r.Agent] = ev
	}
	if r.Kind == "model_call" {
		// A streamed answer is recorded as started and never reaches
		// succeeded, so both statuses evidence a generation.
		if r.CallKind == "chat" && (r.Status == "succeeded" || r.Status == "started") {
			ev.generated = true
		}
		return
	}
	if r.Status != "succeeded" {
		return
	}
	switch classifyTool(tools, r.Tool, r.ResourcesTouched) {
	case toolRead:
		ev.reads++
	case toolWrite:
		f.writes[r.Tool+" on "+strings.Join(r.ResourcesTouched, "+")]++
	default:
		f.unclassified++
	}
}

// kindLabel names a model call kind, saying so when the record carries none.
func kindLabel(kind string) string {
	if kind == "" {
		return "(kind not recorded)"
	}
	return kind
}

// countList renders counts as a stable, sorted "name ×N" list.
func countList(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s ×%d", n, counts[n])
	}
	return strings.Join(parts, ", ")
}

// render prints the run's door facts under its receipt line: the door-call
// summary, the attempted and succeeded counts per model call kind and tool
// resource, the succeeded writes, and the refused calls. The counts are only
// as good as the ledger they were read from, so integrity (that ledger's
// chain verdict) and comp (its completeness verdict) qualify them: every
// count from a ledger whose chain did not verify says so on its own line, and
// a verified ledger that does not account for all its door calls is noted.
func (f *runFacts) render(w io.Writer, integrity, comp string) {
	q := ""
	switch {
	case integrity != "verified":
		q = " (ledger integrity not verified)"
		_, _ = fmt.Fprintf(w, "    this run's ledger chain did not verify (%s): the counts below are from the records that could be read and may be partial\n", integrity)
	case comp == completeness.Gap:
		_, _ = fmt.Fprintln(w, "    ledger completeness gap: this ledger does not account for every door call the run made, so the counts below may be short")
	case comp == completeness.Unterminated:
		_, _ = fmt.Fprintln(w, "    ledger completeness unterminated: this ledger has no final record, so calls made after its last record are not counted below")
	}
	_, _ = fmt.Fprintf(w, "    door calls: %s%s\n", doorSummary(f.doors, f.modelKinds), q)
	labels := make([]string, 0, len(f.calls))
	for l := range f.calls {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	refused, refusedBy := 0, map[string]int{}
	for _, l := range labels {
		c := f.calls[l]
		_, _ = fmt.Fprintf(w, "    %s: attempted ×%d (succeeded ×%d)", l, c.attempted, c.succeeded)
		if c.streaming > 0 {
			_, _ = fmt.Fprintf(w, ", streaming ×%d (started; the ledger does not record how a streamed call ended)", c.streaming)
		}
		_, _ = fmt.Fprintln(w, q)
		if c.refused > 0 {
			refused += c.refused
			refusedBy[l] = c.refused
		}
	}
	writes := 0
	for _, n := range f.writes {
		writes += n
	}
	_, _ = fmt.Fprintf(w, "    write-tool calls succeeded: %d", writes)
	if writes > 0 {
		_, _ = fmt.Fprintf(w, " (%s)", countList(f.writes))
	}
	_, _ = fmt.Fprintln(w, q)
	if f.unclassified > 0 {
		_, _ = fmt.Fprintf(w, "    tool calls succeeded on a resource this configuration does not define: %d (not classified as read or write)%s\n", f.unclassified, q)
	}
	_, _ = fmt.Fprintf(w, "    refused model or tool calls: %d", refused)
	if refused > 0 {
		_, _ = fmt.Fprintf(w, " (%s)", countList(refusedBy))
	}
	_, _ = fmt.Fprintln(w, q)
	if f.doors["exec"]+f.doors["spawn"] > 0 {
		_, _ = fmt.Fprintln(w, "    exec and spawn refusals are not counted here")
	}
	// The block holds this run's own ledger and nothing below it. A spawn
	// door counts attempts, refused ones included, so the note speaks of
	// calls, not of children that ran.
	if f.doors["spawn"] > 0 {
		_, _ = fmt.Fprintln(w, "    this leaf made spawn calls; a run it started has a ledger of its own, and that run's door calls are not counted here")
	}
}

// renderReceipt prints, to w, what ask can say about the run it just did.
// The facts come from the run subtree: the orchestrator's ledger (the invoker
// and, on each parent spawn event, the child's containment tier and measured
// artifact) and every child ledger (the doors that child's run fired), read
// and verified by the investigate timeline. Verification is not repeated
// here. Every door, write and refusal fact is counted from ledger records,
// never from a grant or from the answer; tools (the configured tool
// resources) only labels a recorded tool call as a read or a write. What the
// agents say about themselves is kept apart and labelled, and a leaf agent's
// declared provenance is printed only when its answer was printed and the
// leaf's own ledger shows it generated. A leaf that was started and did not
// answer still gets its block: what it did before it failed is on its ledger.
// It carries digests and verdicts only, never an artifact body.
func renderReceipt(w io.Writer, logDir, runID string, leaf servedLeaf, tools map[string]config.ToolResource) {
	res, err := investigate.Timeline(logDir, "", investigate.Filter{Run: runID}, investigate.Options{})
	if err != nil {
		_, _ = fmt.Fprintf(w, "receipt unavailable: %v\n", err)
		return
	}
	events, _, err := engine.ReadLog(logDir, runID) // a torn or broken ledger is an error here, never a partial receipt
	if err != nil {
		_, _ = fmt.Fprintf(w, "receipt unavailable: the run ledger could not be read in full: %v\n", err)
		return
	}

	facts := map[string]*runFacts{} // run id -> what its ledger recorded
	haveLedger := map[string]bool{}
	integrity := map[string]string{} // run id -> its ledger's chain verdict
	complete := map[string]string{}  // run id -> its ledger's completeness verdict
	for _, src := range res.Sources {
		if src.Kind == "run" {
			id := strings.TrimSuffix(filepath.Base(src.Path), ".jsonl")
			haveLedger[id] = true
			integrity[id] = src.Integrity
			complete[id] = src.Completeness
		}
	}
	for _, r := range res.Events {
		if r.Source == "run" && doorKinds[r.Kind] {
			if facts[r.RunID] == nil {
				facts[r.RunID] = newRunFacts()
			}
			facts[r.RunID].add(r, tools)
		}
	}

	_, _ = fmt.Fprintf(w, "receipt for ask %s\n", runID)
	if leaf.runID != "" && !leaf.answered {
		_, _ = fmt.Fprintf(w, "no answer was produced; run %s was started, and what the ledgers recorded of it follows\n", leaf.runID)
	}
	var invokerAsserted string
	_, _ = fmt.Fprintln(w, "enforced by construction (from the run ledgers — recorded as the run happened, the containment tier as the supervisor reported it — not the agents' own claims):")
	for _, e := range events {
		if e.Type == "workflow_started" {
			inv := e.Binding.Invoker
			if inv.Method == "oidc" {
				_, _ = fmt.Fprintf(w, "  invoker: %s (oidc, verified)\n", inv.Subject)
			} else {
				invokerAsserted = fmt.Sprintf("invoker: %s (%s by the caller, not verified)", inv.Subject, inv.Method)
			}
			break
		}
	}
	for _, e := range events {
		if e.Type != "spawn" || e.ChildRunID == "" {
			continue
		}
		tier := e.ChildConfiner
		if tier == "" {
			tier = "none recorded"
		}
		if len(e.ChildConfinerOpts) > 0 {
			tier += " (" + strings.Join(e.ChildConfinerOpts, ", ") + ")"
		}
		_, _ = fmt.Fprintf(w, "  %s/%s  run %s: containment tier %s", e.ChildRole, e.ChildWorkflow, e.ChildRunID, tier)
		if len(e.ChildArtifact) > 0 {
			agents := make([]string, 0, len(e.ChildArtifact))
			for a := range e.ChildArtifact {
				agents = append(agents, a)
			}
			sort.Strings(agents)
			for _, a := range agents {
				ref := e.ChildArtifact[a]
				_, _ = fmt.Fprintf(w, "; measured artifact %s %s:%s", a, ref.Kind, strings.Join(ref.Values, ","))
			}
		}
		_, _ = fmt.Fprintln(w)
		// The artifact the run handed back, as the parent's spawn event
		// recorded it. An output is not a statement of where it came from: a
		// write summary is an output too.
		if e.OutputSHA != "" {
			_, _ = fmt.Fprintf(w, "    output: artifact %s\n", e.OutputSHA)
		}
		if !haveLedger[e.ChildRunID] {
			_, _ = fmt.Fprintln(w, "    door calls: no ledger found for this run")
			continue
		}
		f := facts[e.ChildRunID]
		if f == nil {
			f = newRunFacts()
		}
		f.render(w, integrity[e.ChildRunID], complete[e.ChildRunID])
	}
	for _, s := range res.Sources {
		if s.Kind != "run" {
			continue
		}
		comp := s.Completeness
		if comp == "" {
			comp = "not checked"
		}
		_, _ = fmt.Fprintf(w, "  ledger %s: chain %s, completeness %s\n", strings.TrimSuffix(filepath.Base(s.Path), ".jsonl"), s.Integrity, comp)
	}
	_, _ = fmt.Fprintln(w, "  door calls count every door the run opened, a refused or denied call included")
	_, _ = fmt.Fprintln(w, "  attempted and succeeded are the statuses the ledger recorded for each model or tool call; a call that failed or was refused may have been stopped at the door or may have reached the provider or resource first — the ledger does not say which")
	_, _ = fmt.Fprintln(w, "  a write-tool call is a tool call outside its resource's read_only_tools: that it happened and succeeded is the ledger's record, that it is a write is the operator's configuration")
	_, _ = fmt.Fprintln(w, "  limits: the chain links each record to the one before it, so edits to a ledger show up; it is evidence, not a guarantee against someone who controls the ledger")

	_, _ = fmt.Fprintln(w, "agent-asserted (declared in configuration or by the caller, not checked by agenthof):")
	if invokerAsserted != "" {
		_, _ = fmt.Fprintf(w, "  %s\n", invokerAsserted)
	}
	// A leaf agent's declared provenance is printed only when its answer was
	// printed and the leaf's own ledger shows that agent generated; the
	// classifier's calls, on another run's ledger, are never evidence for it,
	// and a run that showed no answer has nothing to say the source of.
	leafFacts := facts[leaf.runID]
	if leaf.runID == "" || leafFacts == nil || !leaf.answered {
		leafFacts = newRunFacts()
	}
	declared := false
	for _, a := range leaf.agents {
		ev := leafFacts.agents[a.Name]
		if ev == nil || !ev.generated {
			continue
		}
		declared = true
		// The line rests on the leaf ledger's records; when that ledger's
		// chain did not verify, say so on the line itself.
		line := assertedLine(a, ev.reads)
		if integrity[leaf.runID] != "verified" {
			line += " (leaf ledger integrity not verified)"
		}
		_, _ = fmt.Fprintf(w, "  %s\n", line)
	}
	if declared {
		_, _ = fmt.Fprintln(w, "  an agent's line is printed only when its run ledger shows a chat model call that succeeded or was streamed; where the answer comes from is the agent's declaration, and the retrieval note counts the succeeded read-only tool calls in that ledger — it shows a read happened, not that the answer used what it returned")
	}
}

// doorSummary renders a door-kind count as a stable "kind xN" list, with
// model_call split by the call kind each record carries ("model_call chat x1,
// embeddings x4"). Records written before the call kind existed carry none
// and are counted under the bare kind.
func doorSummary(counts, modelKinds map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if _, bare := modelKinds[""]; k != "model_call" || (bare && len(modelKinds) == 1) {
			parts = append(parts, fmt.Sprintf("%s x%d", k, counts[k]))
			continue
		}
		mk := make([]string, 0, len(modelKinds))
		for c := range modelKinds {
			mk = append(mk, c)
		}
		sort.Strings(mk)
		for i, c := range mk {
			part := fmt.Sprintf("%s x%d", kindLabel(c), modelKinds[c])
			if i == 0 {
				part = "model_call " + part
			}
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ", ")
}

// assertedLine is the agent's own claim about where its answer comes from, as
// its configuration declares it, beside what the leaf's ledger observed:
// reads is the count of that agent's succeeded read-only tool calls. The
// declaration is the agent's word and the retrieval is the evidence, so a
// grounded or mixed declaration with no retrieval behind it is printed as
// declared only, never as an unqualified "from your data"; an agent with no
// grounding declared is reported as exactly that, never as a declared
// "generated". The caller prints it only for an agent whose ledger shows it
// generated.
func assertedLine(a config.AgentDef, reads int) string {
	observed := "no retrieval observed in the run ledger"
	if reads > 0 {
		observed = fmt.Sprintf("retrieval observed (read-tool call ×%d) in the run ledger", reads)
	}
	switch a.Grounding {
	case "grounded":
		if reads == 0 {
			return fmt.Sprintf("%s: declared grounded; %s", a.Name, observed)
		}
		return fmt.Sprintf("%s: grounded — declared to answer from your data; %s", a.Name, observed)
	case "mixed":
		if reads == 0 {
			return fmt.Sprintf("%s: declared mixed; %s", a.Name, observed)
		}
		return fmt.Sprintf("%s: mixed — declared to answer from your notes and the model; %s", a.Name, observed)
	case "generated":
		return fmt.Sprintf("%s: agent-asserted: generated from the model's own knowledge — not your data; %s", a.Name, observed)
	}
	return fmt.Sprintf("%s: no provenance declared; %s", a.Name, observed)
}
