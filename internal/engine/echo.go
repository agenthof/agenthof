package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/config"
)

// EchoExecutor runs workflows offline: no model, no network. It exists so the
// engine, ledger, and CLI are demonstrable and testable end to end without a
// model. The ADK executor implements the same interface.
type EchoExecutor struct{}

func (EchoExecutor) Execute(_ context.Context, agent config.AgentDef, input string, _ map[string]string) (StepResult, error) {
	if strings.Contains(input, "FAIL:"+agent.Name) {
		return StepResult{Success: false,
			Reason: fmt.Sprintf("input requested a synthetic failure for %s", agent.Name)}, nil
	}
	line := input
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	r := []rune(line)
	if len(r) > 80 {
		line = string(r[:80])
	}
	return StepResult{Success: true, Artifact: "[" + agent.Name + "] " + line}, nil
}
