package broker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// KeyPair is a SigV4 signing credential: an access key id, its secret, and an
// optional session token. The values are injected into a request signature and
// nowhere else — never logged, never written to the ledger. Errors name
// variables, never values.
type KeyPair struct {
	ID      string
	Secret  string
	Session string // empty for permanent keys
}

// LogValue makes a KeyPair render as "REDACTED" when it is passed to a
// slog.Logger as an attribute value, so a key pair can never put its secret in
// an operational log line. Defense in depth: it fires for slog attribute
// values, not for fmt verbs.
func (KeyPair) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// KeyPairBroker resolves a signing key pair for a resource at call time. It is
// the key-pair counterpart of Broker, which returns a single bearer string.
type KeyPairBroker interface {
	ResolveKeyPair(ctx context.Context, ref CredentialRef) (KeyPair, error)
}

// StaticEnvKeyPair resolves a sigv4 key pair from three environment-variable
// names: ref.ClientIDEnv (access key id), ref.ClientSecretEnv (secret) and,
// optionally, ref.TokenEnv (the AWS session token).
type StaticEnvKeyPair struct{}

var _ KeyPairBroker = StaticEnvKeyPair{}

// ResolveKeyPair returns the key pair named by ref. It handles only
// client_auth sigv4 with no grant. A named but unset variable is an error,
// including TokenEnv: a session env that is named and unset is a
// misconfiguration, never silently "no session". Errors name the variable,
// never a value.
func (StaticEnvKeyPair) ResolveKeyPair(_ context.Context, ref CredentialRef) (KeyPair, error) {
	if ref.ClientAuth != "sigv4" {
		return KeyPair{}, fmt.Errorf("broker: static_env key pair handles client_auth sigv4 only, not %q", ref.ClientAuth)
	}
	if ref.Source != "" && ref.Source != "static_env" {
		return KeyPair{}, fmt.Errorf("broker: unsupported credential source %q", ref.Source)
	}
	if ref.Grant != "" {
		return KeyPair{}, fmt.Errorf("broker: a sigv4 key pair is used directly; grant %q is not supported", ref.Grant)
	}
	if ref.ClientIDEnv == "" || ref.ClientSecretEnv == "" {
		return KeyPair{}, fmt.Errorf("broker: sigv4 key pair needs client_id_env and client_secret_env")
	}
	id, err := requireEnv(ref.ClientIDEnv)
	if err != nil {
		return KeyPair{}, err
	}
	secret, err := requireEnv(ref.ClientSecretEnv)
	if err != nil {
		return KeyPair{}, err
	}
	kp := KeyPair{ID: id, Secret: secret}
	if ref.TokenEnv != "" {
		if kp.Session, err = requireEnv(ref.TokenEnv); err != nil {
			return KeyPair{}, err
		}
	}
	return kp, nil
}

// requireEnv returns the value of the named variable, or an error naming it
// when it is unset or empty.
func requireEnv(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("broker: environment variable %s is not set", name)
	}
	return v, nil
}
