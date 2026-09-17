// Package gateway resolves logical model names to concrete LLM gateway
// routes and manages per-role API keys.
package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agenthof/agenthof/internal/config"
)

// Route is a resolved gateway destination for a single model call.
type Route struct {
	Endpoint string
	Model    string
	APIKey   string
}

// Resolve looks up the gateway route for a logical model name. An empty
// logical name falls back to cfg.Defaults.Model. The returned route's
// APIKey is roleKey when non-empty, otherwise the value of the route's
// configured environment variable.
func Resolve(cfg config.GatewayConfig, logical string, roleKey string) (Route, error) {
	name := logical
	if name == "" {
		name = cfg.Defaults.Model
	}

	route, ok := cfg.Models[name]
	if !ok {
		return Route{}, fmt.Errorf("model %q has no gateway route", name)
	}

	apiKey := roleKey
	if apiKey == "" {
		apiKey = os.Getenv(route.APIKeyEnv)
	}
	if apiKey == "" {
		return Route{}, fmt.Errorf("gateway route %q: environment variable %s is not set and no role key is provisioned", name, route.APIKeyEnv)
	}

	return Route{
		Endpoint: route.Endpoint,
		Model:    route.Model,
		APIKey:   apiKey,
	}, nil
}

// RoleKeyPath returns the path where a provisioned API key for role is
// stored, rooted at root.
func RoleKeyPath(root, role string) string {
	return filepath.Join(root, ".agenthof", "keys", role+".key")
}

// LoadRoleKey reads and trims the provisioned key for role, returning ""
// if the key file is absent or unreadable.
func LoadRoleKey(root, role string) string {
	data, err := os.ReadFile(RoleKeyPath(root, role))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
