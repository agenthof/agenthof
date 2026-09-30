// Package broker resolves resource credentials at call time so agents stay
// credential-starved: the value is injected into a transport and never held by
// an agent, logged, or written to the ledger (Article I, Article III).
package broker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// CredentialRef describes which credential to resolve and how, along three
// orthogonal axes (grant type × client-auth method × credential source) plus
// the cache key. It is internal (never published config or ledger), so its
// shape may change freely as new grants land. Three grants are implemented:
// the direct-bearer path (Grant == ""), client_credentials, and
// token_exchange (on behalf of the invoker).
type CredentialRef struct {
	ResourceID string // cache-key component; never a secret
	Source     string // credential source: "static_env" (the only source today)
	Grant      string // "" = env value IS the bearer; "client_credentials" = mint; "token_exchange" = exchange the invoker's token
	ClientAuth string // client_credentials / token_exchange: "client_secret_basic" (only method today)
	Issuer     string // client_credentials: AS identity; (resource, issuer) cache-key component. token_exchange does not use Issuer.
	TokenURL   string // client_credentials / token_exchange: token endpoint
	Scope      string // client_credentials / token_exchange: optional, space-delimited
	Audience   string // token_exchange: the audience the exchanged token is for (RFC 8693 audience)

	// Environment-variable NAMES (never values); only names may appear in errors.
	TokenEnv        string // direct-bearer secret (Grant == "")
	ClientIDEnv     string // client_credentials / token_exchange
	ClientSecretEnv string // client_credentials / token_exchange

	// SubjectToken is the invoker's verified inbound token — the RFC 8693
	// subject token. It is a VALUE, not a name: the gateway sets it only on
	// a token_exchange ref, and LogValue below keeps it out of any log line.
	SubjectToken string
}

// LogValue makes a CredentialRef render as "REDACTED" when it is passed to
// a slog.Logger as an attribute value, so a ref can never put its
// SubjectToken in an operational log line — the pattern gateway.Route uses
// for its APIKey. Defense in depth: it fires for slog attribute values, not
// for fmt verbs; the no-leak tests in rungateway are the guarantee.
func (CredentialRef) LogValue() slog.Value { return slog.StringValue("REDACTED") }

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
// the direct-bearer path (Grant == "") to StaticEnv, client_credentials to
// the minting broker, token_exchange to the on-behalf-of broker. It is the
// broker the tool proxy is constructed with.
type Dispatch struct {
	StaticEnv         Broker
	ClientCredentials Broker
	TokenExchange     Broker
}

var _ Broker = Dispatch{}

func (d Dispatch) Resolve(ctx context.Context, ref CredentialRef) (string, error) {
	switch ref.Grant {
	case "":
		return d.StaticEnv.Resolve(ctx, ref)
	case "client_credentials":
		return d.ClientCredentials.Resolve(ctx, ref)
	case "token_exchange":
		return d.TokenExchange.Resolve(ctx, ref)
	default:
		return "", fmt.Errorf("broker: unsupported grant type %q", ref.Grant)
	}
}
