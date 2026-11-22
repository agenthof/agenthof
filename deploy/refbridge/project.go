package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// unixScheme prefixes a tool resource url that names a Unix socket (the same
// value as config.UnixScheme; deploy/ does not import the core package).
const unixScheme = "unix://"

// The projection runs on the HOST, before the containerized bridge starts. It
// reads the installed gateway.yaml (the authority), picks the one refbridge
// resource, and writes a side-file holding only that resource's launch spec.
// The bridge — and the untrusted MCP child that shares its filesystem — is
// then given that slice and never the gateway.yaml, so neither can read the
// rest of the control-plane map.

// projectedResource is the part of a gateway.yaml tool resource that the
// projection reads. Its yaml tags mirror config.ToolResource exactly (a test
// pins them); every other key of the resource is ignored, never copied.
type projectedResource struct {
	Runtime        string   `yaml:"runtime"`
	URL            string   `yaml:"url"`
	Command        []string `yaml:"command"`
	EnvPassthrough []string `yaml:"env_passthrough"`
	Egress         []string `yaml:"egress"`
}

type projectedGateway struct {
	Tools map[string]projectedResource `yaml:"tools"`
}

// projectOps are the operational settings that belong to the bridge's
// deployment, not to the governed resource.
type projectOps struct {
	CredentialEnv   string // the variable refbridge sets on the child; distinct from the resource's token_env (the gateway-side bearer source)
	MaxSessions     int
	IdleTimeout     string
	MaxLifetime     string
	Materialization string
}

// projectSlice renders the side-file for one resource. The result is
// validated by the bridge's own strict reader before it is returned, so a
// slice that would not launch is never written.
func projectSlice(gateway []byte, id string, ops projectOps) ([]byte, error) {
	if id == "" {
		return nil, errors.New("refbridge project: -resource is required")
	}
	var gw projectedGateway
	if err := yaml.Unmarshal(gateway, &gw); err != nil {
		return nil, fmt.Errorf("refbridge project: gateway config: %w", err)
	}
	res, ok := gw.Tools[id]
	if !ok {
		return nil, fmt.Errorf("refbridge project: resource %q not found under tools", id)
	}
	if res.Runtime != "refbridge" {
		return nil, fmt.Errorf("refbridge project: resource %q is not runtime: refbridge", id)
	}
	if len(res.Command) == 0 {
		return nil, fmt.Errorf("refbridge project: resource %q declares no command; it launches from a side-file, not a governed spec", id)
	}
	if !strings.HasPrefix(res.URL, unixScheme) || !filepath.IsAbs(strings.TrimPrefix(res.URL, unixScheme)) {
		return nil, fmt.Errorf("refbridge project: resource %q url must be %s<absolute socket path>", id, unixScheme)
	}
	socket := strings.TrimPrefix(res.URL, unixScheme)
	pass, allow := res.EnvPassthrough, res.Egress
	if pass == nil {
		pass = []string{}
	}
	if allow == nil {
		allow = []string{}
	}
	out, err := yaml.Marshal(map[string]any{
		"socket":          socket,
		"command":         res.Command,
		"credential":      map[string]any{"env": ops.CredentialEnv, "materialization": ops.Materialization},
		"env_passthrough": pass,
		"egress":          map[string]any{"allow": allow},
		"sessions": map[string]any{
			"max":          ops.MaxSessions,
			"idle_timeout": ops.IdleTimeout,
			"max_lifetime": ops.MaxLifetime,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("refbridge project: %w", err)
	}
	if _, err := parseConfig(out); err != nil {
		return nil, fmt.Errorf("refbridge project: resource %q: %w", id, err)
	}
	return out, nil
}

// runProject reads the installed gateway.yaml and writes the slice to out.
func runProject(gatewayPath, id, out string, ops projectOps) error {
	data, err := os.ReadFile(gatewayPath)
	if err != nil {
		return fmt.Errorf("refbridge project: %w", err)
	}
	slice, err := projectSlice(data, id, ops)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, slice, 0o600); err != nil {
		return fmt.Errorf("refbridge project: %w", err)
	}
	return nil
}
