package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

func LoadDir(root string) (Config, []error) {
	var cfg Config
	var errs []error
	if _, err := os.Stat(root); err != nil {
		return cfg, []error{fmt.Errorf("config root %s: %w", root, err)}
	}
	load := func(sub string, each func(rel string, data []byte) error) {
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
			rel := filepath.ToSlash(filepath.Join(sub, n))
			data, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", rel, err))
				continue
			}
			if err := each(rel, data); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", rel, err))
			}
		}
	}
	load("agents", func(rel string, data []byte) error {
		var a AgentDef
		if err := yaml.Unmarshal(data, &a); err != nil {
			return err
		}
		a.SourceFile = rel
		cfg.Agents = append(cfg.Agents, a)
		return nil
	})
	load("workflows", func(rel string, data []byte) error {
		var w WorkflowDef
		if err := yaml.Unmarshal(data, &w); err != nil {
			return err
		}
		w.SourceFile = rel
		cfg.Workflows = append(cfg.Workflows, w)
		return nil
	})
	load("roles", func(rel string, data []byte) error {
		var r RoleDef
		if err := yaml.Unmarshal(data, &r); err != nil {
			return err
		}
		r.SourceFile = rel
		cfg.Roles = append(cfg.Roles, r)
		return nil
	})
	gw := filepath.Join(root, "gateway.yaml")
	if data, err := os.ReadFile(gw); err == nil {
		if err := yaml.Unmarshal(data, &cfg.Gateway); err != nil {
			errs = append(errs, fmt.Errorf("gateway.yaml: %w", err))
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("gateway.yaml: %w", err))
	}
	return cfg, errs
}
