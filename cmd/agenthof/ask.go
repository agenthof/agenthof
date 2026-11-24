package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
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
)

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

// classify asks the installed classifier which menu entry fits the prompt.
// The spawn goes through the gateway's spawn gate, so the classifier is
// subject to the same may_spawn check, caps and parent-ledger record as any
// child. Its answer is read from the artifact store by the recorded digest.
// A spawn that did not succeed, or an answer that is neither a complete pick
// nor null, is an error — never a guessed pick.
func classify(ctx context.Context, gw *rungateway.Gateway, bind engine.Binding, orch config.AgentDef, menu []menuEntry,
	prompt string, store *artifact.Store, appendEvent func(engine.Event), logger *slog.Logger) (role, workflow string, matched bool, err error) {
	in, err := json.Marshal(classifierInput{Menu: menu, Utterance: prompt})
	if err != nil {
		return "", "", false, err
	}
	res, err := gw.AuthorizeAndSpawn(ctx, bind, orch, routerRole, routerWorkflow, string(in), appendEvent, logger)
	if err != nil {
		return "", "", false, errors.New("classifier spawn did not complete")
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

// cmdAsk is `ask "<prompt>"`: a trusted command, not a contained agent. It
// establishes its own run from the installed configuration, offers the
// orchestrator agent's may_spawn list to the classifier, and reports the
// pick. The prompt is the first argument; flags may follow it.
func cmdAsk(args []string, out, stderr io.Writer) int {
	var prompt string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		prompt, args = args[0], args[1:]
	}
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
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if prompt == "" {
		prompt = strings.Join(fs.Args(), " ")
	}
	if strings.TrimSpace(prompt) == "" {
		_, _ = fmt.Fprintln(out, `ask needs a prompt: ask "<prompt>"`)
		return 2
	}
	_ = yes // the confirmation gate that reads it comes with the leaf run
	level, format, err := resolveLogConfig(*logLevel, *logFormat, os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintf(out, "ask: %v\n", err)
		return 2
	}
	logger := obs.New(stderr, level, format)

	r := resolveInvokerForRun(*as, *groups, *token)
	inv := r.inv
	if r.usageErr {
		_, _ = fmt.Fprintln(out, "ask: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	refuse := func(reason string) int {
		runID, refErr := engine.Refuse(*logDir, orchestratorRole, askWorkflow, inv, reason, nil)
		if refErr != nil {
			_, _ = fmt.Fprintln(out, refErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "ask %s refused: %s\n", runID, reason)
		return 1
	}
	if r.refused {
		_, _ = fmt.Fprintf(out, "ask: token authentication failed: %v\n", r.verifyErr)
		return refuse("token verification failed")
	}

	// The installed snapshot, vouched exactly as run vouches it — never the
	// raw configuration directory.
	cfg, reg, h, installed, cfgErrs, unverified := resolveRunConfig(*controlLog, *verifyKey, verifyAndAdvance)
	for _, e := range cfgErrs {
		_, _ = fmt.Fprintln(out, e.Error())
	}
	if len(cfgErrs) > 0 {
		return refuse("configuration invalid: " + cfgErrs[0].Error())
	}
	if unverified != nil {
		if unverified.Transient() {
			_, _ = fmt.Fprintf(out, "ask: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintf(out, "ask: %s\n", unverified.Error())
		return refuse(unverified.Error())
	}
	if !installed {
		_, _ = fmt.Fprintf(out, "ask: %s under %s; run: agenthof apply --config %s --control-log %s\n",
			msgNoConfigInstalled, installedStore(*controlLog), *cfgDir, *controlLog)
		return refuse(msgNoConfigInstalled)
	}
	orch, ok := reg.Agent(orchestratorAgent)
	if !ok {
		_, _ = fmt.Fprintf(out, "ask: the installed configuration has no %q agent\n", orchestratorAgent)
		return 1
	}
	if reason, refused := preRunRefusal(cfg, reg, askWorkflow, inv); refused {
		return refuse(reason)
	}

	var sup refspawn.Provisioner
	if ep := cfg.Gateway.SpawnSupervisor; ep != "" {
		client, err := refspawn.New(ep, logger)
		if err != nil {
			_, _ = fmt.Fprintf(out, "ask: %v\n", err)
			return 2
		}
		sup = client
	}
	deps := newRunDeps(cfg, reg, newBroker(subjectTokenTypeFromEnv(os.Getenv)), logger, *logDir, *artifactDir, h, r.subjectToken, sup)
	store, err := artifact.NewStore(*artifactDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "ask: %v\n", err)
		return 1
	}

	// The orchestrator's own run: a ledger of its own, so every spawn it
	// makes is recorded on a parent the way a spawning agent's are.
	runID := engine.NewRunID()
	bind := engine.Binding{Invoker: inv, Role: orchestratorRole, Workflow: askWorkflow, RunID: runID}
	log, err := engine.OpenLog(*logDir, runID)
	if err != nil {
		_, _ = fmt.Fprintf(out, "ask: %v\n", err)
		return 1
	}
	defer func() { _ = log.Close() }()
	var logErr error
	appendEvent := func(e engine.Event) {
		if logErr != nil {
			return
		}
		e.Time = time.Now().UTC()
		e.Binding = bind
		logErr = log.Append(e)
	}
	appendEvent(engine.Event{Type: "workflow_started", ConfigHash: h, DoorAccounting: engine.DoorAccountingAdmission})
	finish := func(status, reason string, code int) int {
		appendEvent(engine.Event{Type: "workflow_finished", Status: status, Reason: reason})
		if logErr != nil {
			_, _ = fmt.Fprintf(out, "ask %s: run ledger write failed\n", runID)
			return 1
		}
		return code
	}

	gw := rungateway.New(cfg.Gateway, ".", deps.broker, logger, r.subjectToken).WithSpawner(deps)
	menu := projectMenu(orch, reg)
	role, workflow, matched, err := classify(context.Background(), gw, bind, orch, menu, prompt, store, appendEvent, logger)
	if err != nil {
		_, _ = fmt.Fprintf(out, "ask %s: %v\n", runID, err)
		return finish("failed", "classification failed", 1)
	}
	if !matched {
		_, _ = fmt.Fprintf(out, "ask %s: nothing fits that request. Here is what I can do:\n", runID)
		for _, m := range menu {
			_, _ = fmt.Fprintf(out, "  %s/%s: %s\n", m.Role, m.Workflow, m.Description)
		}
		return finish("succeeded", "", 0)
	}
	_, _ = fmt.Fprintf(out, "ask %s: picked %s/%s\n", runID, role, workflow)
	return finish("succeeded", "", 0)
}
