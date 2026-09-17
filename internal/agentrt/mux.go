package agentrt

import (
	"context"
	"fmt"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// MuxExecutor dispatches a step's execution to Contained or Fronted based
// on the agent's effective execution tier. It implements
// engine.StepExecutor.
type MuxExecutor struct {
	Contained engine.StepExecutor
	Fronted   engine.StepExecutor
}

// Execute routes to Contained when a.EffectiveExecution() is "contained",
// to Fronted when it is "fronted", and otherwise fails with a
// configuration error wrapping engine.ErrStepConfig. Validation should
// already reject any other value, but Execute defends against it directly
// rather than trusting that upstream check.
func (x MuxExecutor) Execute(ctx context.Context, a config.AgentDef, input string, artifacts map[string]string) (engine.StepResult, error) {
	switch a.EffectiveExecution() {
	case "contained":
		return x.Contained.Execute(ctx, a, input, artifacts)
	case "fronted":
		return x.Fronted.Execute(ctx, a, input, artifacts)
	default:
		return engine.StepResult{}, fmt.Errorf("agent %q has unknown execution tier %q: %w", a.Name, a.Execution, engine.ErrStepConfig)
	}
}
