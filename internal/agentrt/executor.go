package agentrt

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	openaimodel "google.golang.org/adk/v2/model/openaimodel"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/gateway"
)

// ADKExecutor runs a config.AgentDef as a real, model-backed ADK agent
// jailed to WorkspaceDir. It implements engine.StepExecutor.
type ADKExecutor struct {
	Gateway      config.GatewayConfig
	RoleKey      string
	WorkspaceDir string
}

// Execute resolves a's model through the gateway, builds a jailed ADK agent
// with a's tool catalog, and runs it once against input plus any prior
// artifacts. A model or transport failure is reported as a failed step
// (Success: false) rather than an engine error, since it reflects the
// agent's own run, not a problem with the engine driving it.
func (x ADKExecutor) Execute(ctx context.Context, _ engine.Binding, a config.AgentDef, input string, artifacts map[string]string) (engine.StepResult, error) {
	route, err := gateway.Resolve(x.Gateway, a.Model, x.RoleKey)
	if err != nil {
		return engine.StepResult{}, err
	}
	m, err := openaimodel.NewModel(ctx, route.Model, &openaimodel.ClientConfig{APIKey: route.APIKey, BaseURL: route.Endpoint})
	if err != nil {
		return engine.StepResult{}, err
	}
	j, err := NewJail(x.WorkspaceDir)
	if err != nil {
		return engine.StepResult{}, err
	}
	tools, err := Tools(j, a.Tools)
	if err != nil {
		return engine.StepResult{}, err
	}
	instr := a.Instruction + "\nYou work inside ONE jailed workspace with ONLY your file tools. There is no shell. When done, reply with your final output; if you produced a file artifact, summarize it."
	ag, err := llmagent.New(llmagent.Config{Name: a.Name, Description: a.Description, Model: m, Instruction: instr, Tools: tools})
	if err != nil {
		return engine.StepResult{}, err
	}
	r, err := runner.New(runner.Config{AppName: "agenthof", Agent: ag, SessionService: session.InMemoryService(), AutoCreateSession: true})
	if err != nil {
		return engine.StepResult{}, err
	}

	var sb strings.Builder
	sb.WriteString(input)
	keys := make([]string, 0, len(artifacts))
	for name := range artifacts {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintf(&sb, "\n\n--- prior artifact %q ---\n%s", name, artifacts[name])
	}
	msg := genai.NewContentFromText(sb.String(), genai.RoleUser)

	var out strings.Builder
	for ev, err := range r.Run(ctx, "agenthof", "step", msg, agent.RunConfig{}) {
		if err != nil {
			return engine.StepResult{Success: false, Reason: err.Error()}, nil
		}
		if ev == nil || ev.Content == nil {
			continue
		}
		for _, p := range ev.Content.Parts {
			// Reasoning/thought parts are internal scratch space, not the
			// agent's answer; splicing them into the artifact would leak
			// chain-of-thought into downstream steps.
			if p.Text != "" && !p.Thought {
				out.WriteString(p.Text)
			}
		}
	}
	text := strings.TrimSpace(out.String())
	if text == "" {
		return engine.StepResult{Success: false, Reason: "agent produced no output"}, nil
	}
	return engine.StepResult{Success: true, Artifact: text}, nil
}
