// Package broker resolves resource credentials at call time so agents stay
// credential-starved: the value is injected into a transport and never held by
// an agent, logged, or written to the ledger (Article I, Article III).
package broker

import (
	"context"
	"fmt"
	"os"
)

// CredentialRef describes which credential to resolve and how, along three
// orthogonal axes (grant type × client-auth method × credential source) plus
// the (resource, issuer) key. It is internal (never published config or
// ledger), so its shape may change freely as new grants land. Only the
// direct-bearer path (Grant == "") and client_credentials are implemented.
type CredentialRef struct {
	ResourceID string // (resource, issuer) cache-key component; never a secret
	Source     string // credential source: "static_env" (the only source today)
	Grant      string // "" = env value IS the bearer; "client_credentials" = mint
	ClientAuth string // client_credentials: "client_secret_basic" (only method today)
	Issuer     string // AS identity; (resource, issuer) cache-key component
	TokenURL   string // client_credentials: token endpoint
	Scope      string // client_credentials: optional, space-delimited

	// Environment-variable NAMES (never values); only names may appear in errors.
	TokenEnv        string // direct-bearer secret (Grant == "")
	ClientIDEnv     string // client_credentials
	ClientSecretEnv string // client_credentials
}

// Broker resolves a credential value for a resource at call time. The returned
// string is a secret: callers inject it into an outbound transport and never
// log it or write it to the ledger.
type Broker interface {
	Resolve(ctx context.Context, ref CredentialRef) (string, error)
}

// StaticEnv resolves the direct-bearer path: the value of ref.TokenEnv IS the
// upstream bearer (dev / self-hosted; parallel to identity.Static for invokers).
type StaticEnv struct{}

var _ Broker = StaticEnv{}

// Resolve returns the value of ref.TokenEnv for a direct-bearer static_env ref.
// It handles only Grant == "" (the env value is the final bearer); a non-empty
// grant is another broker's job. Errors name the variable, never a value.
func (StaticEnv) Resolve(_ context.Context, ref CredentialRef) (string, error) {
	if ref.Grant != "" {
		return "", fmt.Errorf("broker: static_env handles the direct-bearer grant only, not %q", ref.Grant)
	}
	if ref.Source != "" && ref.Source != "static_env" {
		return "", fmt.Errorf("broker: unsupported credential source %q", ref.Source)
	}
	if ref.TokenEnv == "" {
		return "", fmt.Errorf("broker: static_env credential has no env var configured")
	}
	v := os.Getenv(ref.TokenEnv)
	if v == "" {
		return "", fmt.Errorf("broker: environment variable %s is not set", ref.TokenEnv)
	}
	return v, nil
}

// Dispatch routes a CredentialRef to the concrete broker for its grant type:
// the direct-bearer path (Grant == "") to StaticEnv, client_credentials to the
// minting broker. It is the broker the tool proxy is constructed with.
type Dispatch struct {
	StaticEnv         Broker
	ClientCredentials Broker
}

var _ Broker = Dispatch{}

func (d Dispatch) Resolve(ctx context.Context, ref CredentialRef) (string, error) {
	switch ref.Grant {
	case "":
		return d.StaticEnv.Resolve(ctx, ref)
	case "client_credentials":
		return d.ClientCredentials.Resolve(ctx, ref)
	default:
		return "", fmt.Errorf("broker: unsupported grant type %q", ref.Grant)
	}
}
