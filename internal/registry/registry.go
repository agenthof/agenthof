package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/agenthof/agenthof/internal/config"
)

type Registry struct {
	agents    map[string]config.AgentDef
	workflows map[string]config.WorkflowDef
	roles     map[string]config.RoleDef
}

func Build(cfg config.Config) (*Registry, []ValidationError) {
	if errs := Validate(cfg); len(errs) > 0 {
		return nil, errs
	}
	r := &Registry{
		agents:    map[string]config.AgentDef{},
		workflows: map[string]config.WorkflowDef{},
		roles:     map[string]config.RoleDef{},
	}
	for _, a := range cfg.Agents {
		r.agents[a.Name] = a
	}
	for _, w := range cfg.Workflows {
		r.workflows[w.Name] = w
	}
	for _, ro := range cfg.Roles {
		r.roles[ro.Name] = ro
	}
	return r, nil
}

func (r *Registry) Agent(name string) (config.AgentDef, bool) { a, ok := r.agents[name]; return a, ok }
func (r *Registry) Workflow(name string) (config.WorkflowDef, bool) {
	w, ok := r.workflows[name]
	return w, ok
}
func (r *Registry) Role(name string) (config.RoleDef, bool) { ro, ok := r.roles[name]; return ro, ok }

func (r *Registry) RoleOwnsWorkflow(role, wf string) bool {
	ro, ok := r.roles[role]
	if !ok {
		return false
	}
	return slices.Contains(ro.Workflows, wf)
}

func (r *Registry) List() []string {
	var out []string
	for _, a := range r.agents {
		state := "enabled"
		if !a.IsEnabled() {
			state = "disabled"
		}
		out = append(out, fmt.Sprintf("agent %s (%s)", a.Name, state))
	}
	for _, w := range r.workflows {
		out = append(out, fmt.Sprintf("workflow %s (%d steps)", w.Name, len(w.Steps)))
	}
	for _, ro := range r.roles {
		out = append(out, fmt.Sprintf("role %s (%d workflows)", ro.Name, len(ro.Workflows)))
	}
	sort.Strings(out)
	return out
}

// SetEnabled rewrites the agent's YAML file under <configRoot>/agents/.
// Known limitation: round-tripping through a map drops YAML comments.
func SetEnabled(configRoot, agentName string, enabled bool) error {
	dir := filepath.Join(configRoot, "agents")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("agents directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext != ".yaml" && ext != ".yml" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := yaml.Unmarshal(data, &m); err != nil {
			continue // unparseable files are apply's problem, not the kill switch's
		}
		if name, _ := m["name"].(string); name == agentName {
			m["enabled"] = enabled
			out, err := yaml.Marshal(m)
			if err != nil {
				return err
			}
			// Write atomically: temp file, sync, rename.
			tmp, err := os.CreateTemp(dir, ".enabled-*")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			defer func() {
				if tmpPath != "" {
					os.Remove(tmpPath)
				}
			}()
			if err := os.Chmod(tmpPath, 0o644); err != nil {
				return err
			}
			if _, err := tmp.Write(out); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Sync(); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			if err := os.Rename(tmpPath, p); err != nil {
				return err
			}
			tmpPath = "" // prevent cleanup
			return nil
		}
	}
	return fmt.Errorf("agent %q not found in %s", agentName, dir)
}
