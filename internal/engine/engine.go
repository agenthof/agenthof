package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

type StepResult struct {
	Artifact string
	Success  bool
	Reason   string
}

type StepExecutor interface {
	Execute(ctx context.Context, agent config.AgentDef, input string, artifacts map[string]string) (StepResult, error)
}

type Options struct {
	LogDir      string
	StepTimeout time.Duration
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
	runID := NewRunID()
	bind := Binding{Invoker: inv, Role: role, Workflow: workflow, RunID: runID}
	log, err := OpenLog(opts.LogDir, runID)
	if err != nil {
		return runID, "failed", err
	}
	defer log.Close()
	now := func() time.Time { return time.Now().UTC() }
	emit := func(e Event) { e.Time = now(); e.Binding = bind; _ = log.Append(e) }

	refuse := func(reason string) (string, string, error) {
		emit(Event{Type: "run_refused", Reason: reason})
		return runID, "refused", fmt.Errorf("%s", reason)
	}
	ro, ok := reg.Role(role)
	if !ok {
		return refuse(fmt.Sprintf("role %q is not in the registry", role))
	}
	_ = ro
	wf, ok := reg.Workflow(workflow)
	if !ok {
		return refuse(fmt.Sprintf("workflow %q is not in the registry", workflow))
	}
	if !reg.RoleOwnsWorkflow(role, workflow) {
		return refuse(fmt.Sprintf("role %q does not own workflow %q", role, workflow))
	}

	emit(Event{Type: "workflow_started"})
	artifacts := map[string]string{}
	bounces := map[string]int{}
	i := 0
	for i < len(wf.Steps) {
		step := wf.Steps[i]
		agent, _ := reg.Agent(step.Agent)
		emit(Event{Type: "step_started", Step: step.Name, Agent: agent.Name})

		stepCtx, cancel := context.WithTimeout(ctx, opts.StepTimeout)
		res, execErr := exec.Execute(stepCtx, agent, input, artifacts)
		cancel()
		if execErr != nil {
			res = StepResult{Success: false, Reason: execErr.Error()}
		}

		if res.Success {
			if agent.Output != "" {
				artifacts[agent.Output] = res.Artifact
			}
			emit(Event{Type: "step_succeeded", Step: step.Name, Agent: agent.Name, Artifact: res.Artifact})
			i++
			continue
		}
		// Failure handling (fail-back) is completed in the next change set;
		// for now any failure ends the workflow honestly.
		emit(Event{Type: "step_failed", Step: step.Name, Agent: agent.Name, Reason: res.Reason})
		emit(Event{Type: "workflow_finished", Status: "failed", Reason: res.Reason})
		return runID, "failed", nil
	}
	_ = bounces
	emit(Event{Type: "workflow_finished", Status: "succeeded"})
	return runID, "succeeded", nil
}
