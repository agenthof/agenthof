package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
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

type StepResult struct {
	Artifact string
	Success  bool
	Reason   string
}

type StepExecutor interface {
	Execute(ctx context.Context, agent config.AgentDef, input string, artifacts map[string]string) (StepResult, error)
}

type Options struct {
	LogDir       string
	StepTimeout  time.Duration
	ArtifactDir  string
	WorkspaceDir string
}

const defaultMaxBounces = 2

func Run(ctx context.Context, reg *registry.Registry, role, workflow, input string,
	inv identity.Invoker, exec StepExecutor, opts Options) (string, string, error) {

	if opts.LogDir == "" {
		opts.LogDir = ".agenthof/runs"
	}
	if opts.StepTimeout == 0 {
		opts.StepTimeout = 5 * time.Minute
	}
	if opts.ArtifactDir == "" {
		opts.ArtifactDir = ".agenthof/artifacts"
	}
	runID := NewRunID()
	bind := Binding{Invoker: inv, Role: role, Workflow: workflow, RunID: runID}
	log, err := OpenLog(opts.LogDir, runID)
	if err != nil {
		return runID, "failed", err
	}
	defer log.Close()
	store, err := artifact.NewStore(opts.ArtifactDir)
	if err != nil {
		return runID, "failed", err
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

	refuse := func(reason string) (string, string, error) {
		refusalErr := fmt.Errorf("%s", reason)
		emit(Event{Type: "run_refused", Reason: reason})
		if logErr != nil {
			return runID, "refused", errors.Join(refusalErr, fmt.Errorf("ledger write failed: %w", logErr))
		}
		return runID, "refused", refusalErr
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
	if len(ro.AllowedGroups) > 0 && !groupsIntersect(inv.Groups, ro.AllowedGroups) {
		return refuse(fmt.Sprintf(
			"role %q requires membership in one of its allowed groups (%s); the invoker's groups don't qualify",
			role, strings.Join(ro.AllowedGroups, ", ")))
	}

	emit(Event{Type: "workflow_started"})
	artifacts := map[string]string{}
	bounces := map[string]int{}
	i := 0
	for i < len(wf.Steps) {
		if logErr != nil {
			return runID, "failed", fmt.Errorf("ledger write failed: %w", logErr)
		}
		step := wf.Steps[i]
		agent, _ := reg.Agent(step.Agent)
		execTier := agent.EffectiveExecution()
		emit(Event{Type: "step_started", Step: step.Name, Agent: agent.Name, Execution: execTier})

		stepCtx, cancel := context.WithTimeout(ctx, opts.StepTimeout)
		res, execErr := exec.Execute(stepCtx, agent, input, artifacts)
		cancel()
		if execErr != nil {
			if errors.Is(execErr, ErrStepConfig) {
				// Configuration errors can't be fixed by retrying: fail the
				// workflow outright instead of bouncing back to a prior step.
				emit(Event{Type: "step_failed", Step: step.Name, Agent: agent.Name, Reason: execErr.Error(), Execution: execTier})
				emit(Event{Type: "workflow_finished", Status: "failed", Reason: execErr.Error()})
				if logErr != nil {
					return runID, "failed", fmt.Errorf("ledger write failed: %w", logErr)
				}
				return runID, "failed", nil
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
					emit(Event{Type: "workflow_finished", Status: "failed", Reason: "artifact store: " + perr.Error()})
					if logErr != nil {
						return runID, "failed", errors.Join(storeErr, fmt.Errorf("ledger write failed: %w", logErr))
					}
					return runID, "failed", storeErr
				}
			}
			if agent.Output != "" {
				artifacts[agent.Output] = res.Artifact
			}
			emit(Event{Type: "step_succeeded", Step: step.Name, Agent: agent.Name, Artifact: preview, ArtifactSHA: sha, Execution: execTier})
			i++
			continue
		}
		// failure: resolve the fail-back target
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
			if target != "" {
				reason = fmt.Sprintf("step %q exhausted its %d bounce(s): %s", step.Name, cap, res.Reason)
			}
			emit(Event{Type: "workflow_finished", Status: "failed", Reason: reason})
			if logErr != nil {
				return runID, "failed", fmt.Errorf("ledger write failed: %w", logErr)
			}
			return runID, "failed", nil
		}
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
		return runID, "failed", fmt.Errorf("ledger write failed: %w", logErr)
	}
	return runID, "succeeded", nil
}
