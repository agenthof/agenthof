package registry

import (
	"fmt"

	"github.com/agenthof/agenthof/internal/config"
)

type ValidationError struct{ File, Entity, Code, Msg string }

func (e ValidationError) Error() string { return fmt.Sprintf("%s: %s: %s", e.File, e.Entity, e.Msg) }

func Validate(cfg config.Config) []ValidationError {
	var errs []ValidationError
	add := func(file, entity, code, msg string) {
		errs = append(errs, ValidationError{File: file, Entity: entity, Code: code, Msg: msg})
	}

	agents := map[string]config.AgentDef{}
	for _, a := range cfg.Agents {
		if a.Name == "" {
			add(a.SourceFile, "(agent)", "missing-name", "agent has no name")
			continue
		}
		if _, dup := agents[a.Name]; dup {
			add(a.SourceFile, a.Name, "duplicate-name", "agent name already defined")
			continue
		}
		agents[a.Name] = a
		model := a.Model
		if model == "" {
			model = cfg.Gateway.Defaults.Model
		}
		if _, ok := cfg.Gateway.Models[model]; !ok {
			add(a.SourceFile, a.Name, "unroutable-model",
				fmt.Sprintf("model %q has no route in gateway.yaml and no default is set", a.Model))
		}
	}

	workflows := map[string]config.WorkflowDef{}
	for _, w := range cfg.Workflows {
		if w.Name == "" {
			add(w.SourceFile, "(workflow)", "missing-name", "workflow has no name")
			continue
		}
		if _, dup := workflows[w.Name]; dup {
			add(w.SourceFile, w.Name, "duplicate-name", "workflow name already defined")
			continue
		}
		workflows[w.Name] = w
		if len(w.Steps) == 0 {
			add(w.SourceFile, w.Name, "no-steps", "workflow has no steps")
			continue
		}
		index := map[string]int{}
		for i, s := range w.Steps {
			index[s.Name] = i
		}
		for i, s := range w.Steps {
			if a, ok := agents[s.Agent]; !ok {
				add(w.SourceFile, w.Name, "dangling-agent-ref",
					fmt.Sprintf("step %q references agent %q, which does not exist", s.Name, s.Agent))
			} else if !a.IsEnabled() {
				add(w.SourceFile, w.Name, "disabled-agent-ref",
					fmt.Sprintf("workflow %q depends on agent %q, which is disabled in the registry", w.Name, s.Agent))
			}
			if s.MaxBounces < 0 || s.MaxBounces > 10 {
				add(w.SourceFile, w.Name, "bad-bounces",
					fmt.Sprintf("step %q: max_bounces must be between 0 and 10", s.Name))
			}
			if s.OnSuccess != "" {
				last := i == len(w.Steps)-1
				if !(last && s.OnSuccess == "finish") {
					j, ok := index[s.OnSuccess]
					if !ok || j != i+1 {
						add(w.SourceFile, w.Name, "bad-graph",
							fmt.Sprintf("step %q: on_success must be the next step (or \"finish\" on the last step); branching is not yet supported", s.Name))
					}
				}
			}
			if s.OnFailure != "" {
				j, ok := index[s.OnFailure]
				if !ok || j >= i {
					add(w.SourceFile, w.Name, "bad-graph",
						fmt.Sprintf("step %q: on_failure must name an earlier step; forward or unknown targets are not supported", s.Name))
				}
			}
		}
	}

	roleNames := map[string]bool{}
	for _, r := range cfg.Roles {
		if r.Name == "" {
			add(r.SourceFile, "(role)", "missing-name", "role has no name")
			continue
		}
		if roleNames[r.Name] {
			add(r.SourceFile, r.Name, "duplicate-name", "role name already defined")
			continue
		}
		roleNames[r.Name] = true
		if len(r.Workflows) == 0 {
			add(r.SourceFile, r.Name, "no-workflows", "role owns no workflows")
		}
		for _, wf := range r.Workflows {
			if _, ok := workflows[wf]; !ok {
				add(r.SourceFile, r.Name, "dangling-workflow-ref",
					fmt.Sprintf("role references workflow %q, which does not exist", wf))
			}
		}
	}
	return errs
}
