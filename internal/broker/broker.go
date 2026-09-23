// Package broker resolves resource credentials at call time so agents stay
// credential-starved: the value is injected into a transport and never held by
// an agent, logged, or written to the ledger (Article I, Article III).
package broker

import (
	"context"
	"fmt"
	"os"
)

// CredentialRef describes which credential to resolve and how. Only Mode
// "static_env" is implemented; the remaining shape is reserved for later modes
// (client_credentials, token_exchange) and carries no behavior yet.
type CredentialRef struct {
	Mode   string // "static_env" (the only supported mode today)
	EnvVar string // static_env: environment variable holding the secret
}

// Broker resolves a credential value for a resource at call time. The returned
// string is a secret: callers inject it into an outbound transport and never
// log it or write it to the ledger.
type Broker interface {
	Resolve(ctx context.Context, ref CredentialRef) (string, error)
}

// StaticEnv resolves credentials from environment variables (dev / self-hosted;
// parallel to identity.Static for invokers).
type StaticEnv struct{}

var _ Broker = StaticEnv{}

// Resolve returns the value of ref.EnvVar for a static_env ref. Errors name the
// variable, never a value.
func (StaticEnv) Resolve(_ context.Context, ref CredentialRef) (string, error) {
	if ref.Mode != "static_env" {
		return "", fmt.Errorf("broker: unsupported credential mode %q", ref.Mode)
	}
	if ref.EnvVar == "" {
		return "", fmt.Errorf("broker: static_env credential has no env var configured")
	}
	v := os.Getenv(ref.EnvVar)
	if v == "" {
		return "", fmt.Errorf("broker: environment variable %s is not set", ref.EnvVar)
	}
	return v, nil
}
