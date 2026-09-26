// Package gateway resolves logical model names to concrete LLM gateway
// routes and manages per-role API keys. Credentials are resolved through
// the broker seam (internal/broker), never read directly from the
// environment.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
)

// Route is a resolved gateway destination for a single model call.
type Route struct {
	Endpoint string
	Model    string
	APIKey   string
}

// LogValue makes a Route render as "REDACTED" when it is passed to a
// slog.Logger as an attribute value, so a Route can never put its APIKey in
// an operational log line. Defense in depth only: it fires for slog attribute
// values, not for fmt verbs — the secret-absence test in internal/engine is
// the guarantee.
func (Route) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// Resolve looks up the gateway route for a logical model name. An empty
// logical name falls back to cfg.Defaults.Model. The returned route's
// APIKey is roleKey when non-empty, otherwise the value resolved through
// the broker for the route's configured environment variable.
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
		v, err := broker.StaticEnv{}.Resolve(context.Background(), broker.CredentialRef{Source: "static_env", Grant: "", TokenEnv: route.APIKeyEnv})
		if err != nil {
			return Route{}, fmt.Errorf("gateway route %q: %w; no role key provisioned", name, err)
		}
		apiKey = v
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
