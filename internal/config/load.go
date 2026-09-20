package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// configFiles returns the ordered, slash-relative config file paths under
// root that LoadDir (and HashDir) read: agents/*.yaml|yml sorted, then
// workflows/*, then roles/*, then gateway.yaml if present. A missing
// subdirectory is not an error; validation decides what's required.
func configFiles(root string) ([]string, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("config root %s: %w", root, err)
	}
	var files []string
	listSub := func(sub string) {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return // a missing subdir is not an error; validation decides what's required
		}
		var names []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			files = append(files, filepath.ToSlash(filepath.Join(sub, n)))
		}
	}
	listSub("agents")
	listSub("workflows")
	listSub("roles")
	if _, err := os.Stat(filepath.Join(root, "gateway.yaml")); !os.IsNotExist(err) {
		files = append(files, "gateway.yaml")
	}
	return files, nil
}

func LoadDir(root string) (Config, []error) {
	var cfg Config
	var errs []error
	files, err := configFiles(root)
	if err != nil {
		return cfg, []error{err}
	}
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rel, err))
			continue
		}
		var parseErr error
		switch path.Dir(rel) {
		case "agents":
			var a AgentDef
			if parseErr = yaml.Unmarshal(data, &a); parseErr == nil {
				a.SourceFile = rel
				cfg.Agents = append(cfg.Agents, a)
			}
		case "workflows":
			var w WorkflowDef
			if parseErr = yaml.Unmarshal(data, &w); parseErr == nil {
				w.SourceFile = rel
				cfg.Workflows = append(cfg.Workflows, w)
			}
		case "roles":
			var r RoleDef
			if parseErr = yaml.Unmarshal(data, &r); parseErr == nil {
				r.SourceFile = rel
				cfg.Roles = append(cfg.Roles, r)
			}
		default: // gateway.yaml
			parseErr = yaml.Unmarshal(data, &cfg.Gateway)
		}
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rel, parseErr))
		}
	}
	return cfg, errs
}
