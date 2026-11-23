package agentcard

import (
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/config"
)

// Map turns a card's Agenthof extension into a proposed AgentDef plus a flat
// human-readable list of what the card requested. The result carries
// Provenance (so it is spawn-only) and never an endpoint, exec url, or
// may_spawn. Every requested tool resource, model and embedding model must already exist in
// tools/models; wildcard tool requests and any spawn request are refused.
func Map(ext AgenthofExt, name string, tools map[string]bool, models map[string]bool) (config.AgentDef, []string, error) {
	if len(ext.Spawn) > 0 {
		return config.AgentDef{}, nil, fmt.Errorf("agent card requests spawn rights (%d targets); a card may not grant may_spawn", len(ext.Spawn))
	}
	prov := &config.Provenance{Image: ext.Artifact}
	var requested []string
	if ext.Artifact != "" {
		requested = append(requested, "image "+ext.Artifact)
	}
	if hp := ext.HostProgram; hp != nil {
		prov.Program = hp.Program
		for _, b := range hp.Builds {
			prov.Builds = append(prov.Builds, config.HostBuild{OS: b.OS, Arch: b.Arch, SHA256: b.SHA256})
			// One line per build. Card parse caps the program id, os and arch
			// so each line fits the recorded per-entry cap (see card.go).
			requested = append(requested, fmt.Sprintf("host program %s %s/%s %s", hp.Program, b.OS, b.Arch, b.SHA256))
		}
	}
	def := config.AgentDef{Name: name, Provenance: prov}

	for _, g := range ext.Tools {
		if len(g.Tools) == 0 {
			return config.AgentDef{}, nil, fmt.Errorf("tool request for resource %q names no tools", g.Resource)
		}
		for _, t := range g.Tools {
			if t == "*" {
				return config.AgentDef{}, nil, fmt.Errorf("tool request for resource %q is a wildcard; name the tools explicitly", g.Resource)
			}
		}
		if g.Mode != "read-only" && g.Mode != "read-write" {
			return config.AgentDef{}, nil, fmt.Errorf("tool request for resource %q has mode %q; want read-only or read-write", g.Resource, g.Mode)
		}
		if !tools[g.Resource] {
			return config.AgentDef{}, nil, fmt.Errorf("tool resource %q is not defined", g.Resource)
		}
		def.Tools = append(def.Tools, config.ToolGrant{
			Resource: g.Resource,
			Tools:    append([]string(nil), g.Tools...),
			Mode:     g.Mode,
		})
		requested = append(requested, fmt.Sprintf("tools %s: %s (%s)", g.Resource, strings.Join(g.Tools, ", "), g.Mode))
	}

	if ext.Model != "" {
		if !models[ext.Model] {
			return config.AgentDef{}, nil, fmt.Errorf("model %q is not defined", ext.Model)
		}
		def.Model = ext.Model
		requested = append(requested, "model "+ext.Model)
	}
	if ext.Embedding != "" {
		if !models[ext.Embedding] {
			return config.AgentDef{}, nil, fmt.Errorf("embedding model %q is not defined", ext.Embedding)
		}
		def.EmbeddingModel = ext.Embedding
		requested = append(requested, "embedding model "+ext.Embedding)
	}
	if len(ext.Exec) > 0 {
		requested = append(requested, "exec (not granted): "+strings.Join(ext.Exec, ", "))
	}
	return def, requested, nil
}
