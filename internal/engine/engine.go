package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/registry"
)

// groupsIntersect reports whether any of the invoker's groups appear in the
// role's allowed groups.
func groupsIntersect(invokerGroups, allowedGroups []string) bool {
	for _, g := range invokerGroups {
		for _, a := range allowedGroups {
			if g == a {
				return true
			}
		}
	}
	return false
}

// containsStar reports whether allowed_groups carries the public marker "*",
// which admits any authenticated invoker — including one with no groups.
func containsStar(allowedGroups []string) bool {
	for _, g := range allowedGroups {
		if g == "*" {
			return true
		}
	}
	return false
}

// roleAllows is the default-deny authorization decision: an invoker is allowed
// iff the role is public ("*") or the invoker shares one of the role's groups.
// An empty allowed_groups denies (fail-closed); apply-time validation rejects
// such roles, so the gate should not see one, but it denies defensively.
func roleAllows(invokerGroups, allowedGroups []string) bool {
	return containsStar(allowedGroups) || groupsIntersect(invokerGroups, allowedGroups)
}

type StepResult struct {
	Artifact string
	Success  bool
	Reason   string
}

type StepExecutor interface {
	Execute(ctx context.Context, binding Binding, agent config.AgentDef, input string, artifacts map[string]string) (StepResult, error)
}

// Result is what Run reports back: the run's id and final status, plus — on
// a succeeded run — the sha256 and capped preview of the last step's
// artifact, exactly what that step's step_succeeded event carries. The
// artifact body itself never travels here (Article III); it lives in the
// artifact store under OutputSHA.
type Result struct {
	RunID         string
	Status        string // succeeded | failed | refused | cancelled
	OutputSHA     string
	OutputPreview string
}

type Options struct {
	LogDir      string
	StepTimeout time.Duration
	ArtifactDir string
	ConfigHash  string
	// NewGateway returns the gateway for this run. The engine calls it once,
	// before the step loop, and reuses that instance across the run's steps.
	// Nil means this run has no gateway. A fresh return value per call keeps
	// one run from closing or overwriting another's listener.
	NewGateway func() ToolProxy
	// Logger receives operational diagnostics for this run — never audit
	// events, which go to the run ledger under LogDir. Nil means discard.
	Logger *slog.Logger
	// Parent, when set, links this run under a spawning parent: the run's
	// binding carries Parent.RunID as ParentRunID and Parent.Depth+1 as
	// Depth, and the invoker is expected to be the parent's, unchanged. Nil
	// means a root run.
	Parent *Binding
	// RunID, when set, is the id this run records under instead of a fresh
	// one. A caller that must name resources for the run before it starts
	// — a Spawner provisioning a child's compartments — mints it with
	// NewRunID and passes it here. Empty means mint one.
	RunID string
}

const defaultMaxBounces = 2

func Run(ctx context.Context, reg *registry.Registry, role, workflow, input string,
	inv identity.Invoker, exec StepExecutor, opts Options) (Result, error) {

	if opts.LogDir == "" {
		opts.LogDir = ".agenthof/runs"
	}
	if opts.StepTimeout == 0 {
		opts.StepTimeout = 5 * time.Minute
	}
	if opts.ArtifactDir == "" {
		opts.ArtifactDir = ".agenthof/artifacts"
	}
	runID := opts.RunID
	if runID == "" {
		runID = NewRunID()
	}
	bind := Binding{Invoker: inv, Role: role, Workflow: workflow, RunID: runID}.linkedTo(opts.Parent)
	logger := obs.OrDiscard(opts.Logger).With("run", runID, "role", role, "workflow", workflow)
	failed := func(err error) (Result, error) { return Result{RunID: runID, Status: "failed"}, err }
	log, err := OpenLog(opts.LogDir, runID)
	if err != nil {
		logger.Error("run ledger open failed", "err", err)
		return failed(err)
	}
	defer func() { _ = log.Close() }()
	store, err := artifact.NewStore(opts.ArtifactDir)
	if err != nil {
		logger.Error("artifact store open failed", "err", err)
		return failed(err)
	}
	now := func() time.Time { return time.Now().UTC() }
	var logErr error
	emit := func(e Event) {
		if logErr != nil {
			return
		}
		e.Time = now()
		e.Binding = bind
		logErr = log.Append(e)
	}
	// ledgerFailed is the one exit for a failed ledger append: a local
	// filesystem error, so its text (a path, never a secret) may be logged.
	ledgerFailed := func() (Result, error) {
		logger.Error("ledger write failed", "err", logErr)
		return failed(fmt.Errorf("%w: %w", ErrLedgerWrite, logErr))
	}

	refuse := func(reason string) (Result, error) {
		refusalErr := fmt.Errorf("%s", reason)
		logger.Warn("run refused", "reason", reason)
		emit(Event{Type: "run_refused", Reason: reason})
		if logErr != nil {
			logger.Error("ledger write failed", "err", logErr)
			return Result{RunID: runID, Status: "refused"}, errors.Join(refusalErr, fmt.Errorf("%w: %w", ErrLedgerWrite, logErr))
		}
		return Result{RunID: runID, Status: "refused"}, refusalErr
	}
	ro, ok := reg.Role(role)
	if !ok {
		return refuse(fmt.Sprintf("role %q is not in the registry", role))
	}
	wf, ok := reg.Workflow(workflow)
	if !ok {
		return refuse(fmt.Sprintf("workflow %q is not in the registry", workflow))
	}
	if !reg.RoleOwnsWorkflow(role, workflow) {
		return refuse(fmt.Sprintf("role %q does not own workflow %q", role, workflow))
	}
	if !roleAllows(inv.Groups, ro.AllowedGroups) {
		return refuse(fmt.Sprintf(
			"role %q requires membership in one of its allowed groups (%s); the invoker's groups don't qualify",
			role, strings.Join(ro.AllowedGroups, ", ")))
	}

	emit(Event{Type: "workflow_started", ConfigHash: opts.ConfigHash})
	logger.Debug("run started", "steps", len(wf.Steps))
	var gw ToolProxy
	if opts.NewGateway != nil {
		gw = opts.NewGateway()
	}
	artifacts := map[string]string{}
	bounces := map[string]int{}
	// lastSHA/lastPreview track the most recent succeeded step's artifact;
	// on a succeeded run that is the final artifact Result reports.
	var lastSHA, lastPreview string
	i := 0
	for i < len(wf.Steps) {
		if logErr != nil {
			return ledgerFailed()
		}
		// A run whose context is already over — a spawned child whose parent
		// step was cancelled or timed out, or any caller that gave up — stops
		// here rather than starting the next step: without this, a cancelled
		// child would still walk its fail-back graph, each step paying the
		// gateway's connect timeouts before failing. The exit is bounded to
		// roughly one Start, not instant: the loop only checks between steps.
		if err := ctx.Err(); err != nil {
			logger.Warn("run cancelled", "class", "context")
			emit(Event{Type: "workflow_finished", Status: "cancelled", Reason: "run cancelled"})
			if logErr != nil {
				return ledgerFailed()
			}
			return Result{RunID: runID, Status: "cancelled"}, nil
		}
		step := wf.Steps[i]
		agent, _ := reg.Agent(step.Agent)
		execTier := agent.EffectiveExecution()
		emit(Event{Type: "step_started", Step: step.Name, Agent: agent.Name, Execution: execTier})
		logger.Debug("step started", "step", step.Name, "agent", agent.Name, "execution", execTier)

		stepCtx, cancel := context.WithTimeout(ctx, opts.StepTimeout)
		// Every fronted step gets the per-run listener. It serves whichever
		// doors this agent uses — tools, exec, the model proxy, or spawn — and
		// a listener with no traffic is cheap. The agent receives the proxy
		// URL and run token and ignores the doors it does not call.
		fronted := gw != nil && agent.EffectiveExecution() == "fronted"
		if fronted {
			// appendEvent writes door events on the same serialized ledger
			// writer but must NOT touch the engine-goroutine logErr var.
			appendEvent := func(e Event) {
				e.Time = now()
				e.Binding = bind
				_ = log.Append(e)
			}
			url, token, perr := gw.Start(stepCtx, bind, agent, appendEvent)
			if perr != nil {
				cancel()
				// perr is transport-derived (upstream connect / listen) and can
				// wrap a *url.Error carrying the resource URL, query string and
				// any injected credential included. The gateway already logged
				// the resource id and error class; the ledger reason stays a
				// fixed string so no URL or secret reaches an event (Article
				// III), mirroring the model door's fixed failure reason.
				logger.Error("tool proxy start failed", "step", step.Name, "agent", agent.Name)
				emit(Event{Type: "step_failed", Step: step.Name, Agent: agent.Name, Reason: "tool proxy start failed", Execution: execTier})
				emit(Event{Type: "workflow_finished", Status: "failed", Reason: "tool proxy start failed"})
				if logErr != nil {
					return ledgerFailed()
				}
				return failed(nil)
			}
			stepCtx = WithProxyCoordinates(stepCtx, url, token)
		}
		res, execErr := exec.Execute(stepCtx, bind, agent, input, artifacts)
		cancel()
		if fronted {
			gw.Stop()
		}
		if execErr != nil {
			if errors.Is(execErr, ErrStepConfig) {
				// Configuration errors can't be fixed by retrying: fail the
				// workflow outright instead of bouncing back to a prior step.
				logger.Error("step configuration error", "step", step.Name, "agent", agent.Name)
				emit(Event{Type: "step_failed", Step: step.Name, Agent: agent.Name, Reason: execErr.Error(), Execution: execTier})
				emit(Event{Type: "workflow_finished", Status: "failed", Reason: execErr.Error()})
				if logErr != nil {
					return ledgerFailed()
				}
				return failed(nil)
			}
			res = StepResult{Success: false, Reason: execErr.Error()}
		}

		if res.Success {
			preview, sha := "", ""
			if res.Artifact != "" {
				var perr error
				sha, preview, perr = store.Put(res.Artifact)
				if perr != nil {
					storeErr := fmt.Errorf("artifact store: %w", perr)
					logger.Error("artifact store write failed", "step", step.Name, "err", perr)
					emit(Event{Type: "workflow_finished", Status: "failed", Reason: "artifact store: " + perr.Error()})
					if logErr != nil {
						logger.Error("ledger write failed", "err", logErr)
						return failed(errors.Join(storeErr, fmt.Errorf("%w: %w", ErrLedgerWrite, logErr)))
					}
					return failed(storeErr)
				}
			}
			if agent.Output != "" {
				artifacts[agent.Output] = res.Artifact
			}
			lastSHA, lastPreview = sha, preview
			emit(Event{Type: "step_succeeded", Step: step.Name, Agent: agent.Name, Artifact: preview, ArtifactSHA: sha, Execution: execTier})
			logger.Debug("step succeeded", "step", step.Name, "agent", agent.Name)
			i++
			continue
		}
		// failure: resolve the fail-back target. The executor's reason text
		// goes to the ledger only — it may quote an adapter response.
		logger.Warn("step failed", "step", step.Name, "agent", agent.Name)
		emit(Event{Type: "step_failed", Step: step.Name, Agent: agent.Name, Reason: res.Reason, Execution: execTier})
		target := step.OnFailure
		if target == "" && i > 0 {
			target = wf.Steps[i-1].Name
		}
		cap := step.MaxBounces
		if cap == 0 {
			cap = defaultMaxBounces
		}
		bounces[step.Name]++
		if target == "" || bounces[step.Name] > cap {
			reason := res.Reason
			why := "no fail-back target"
			if target != "" {
				reason = fmt.Sprintf("step %q exhausted its %d bounce(s): %s", step.Name, cap, res.Reason)
				why = "bounces exhausted"
			}
			logger.Warn("run failed", "step", step.Name, "reason", why)
			emit(Event{Type: "workflow_finished", Status: "failed", Reason: reason})
			if logErr != nil {
				return ledgerFailed()
			}
			return failed(nil)
		}
		logger.Warn("step bounced back", "step", step.Name, "target", target, "bounce", bounces[step.Name], "cap", cap)
		emit(Event{Type: "bounced_back", Step: step.Name, Status: target, Reason: res.Reason})
		for j, s := range wf.Steps {
			if s.Name == target {
				i = j
				break
			}
		}
		continue
	}
	emit(Event{Type: "workflow_finished", Status: "succeeded"})
	if logErr != nil {
		return ledgerFailed()
	}
	logger.Debug("run finished", "status", "succeeded")
	return Result{RunID: runID, Status: "succeeded", OutputSHA: lastSHA, OutputPreview: lastPreview}, nil
}
