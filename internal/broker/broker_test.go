package broker

import (
	"context"
	"strings"
	"testing"
)

func TestStaticEnvResolves(t *testing.T) {
	t.Setenv("MY_SECRET", "sk-123")
	got, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{Mode: "static_env", EnvVar: "MY_SECRET"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sk-123" {
		t.Fatalf("got %q, want sk-123", got)
	}
}

func TestStaticEnvUnsetErrorsNamesVarNotValue(t *testing.T) {
	t.Setenv("MY_SECRET", "")
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{Mode: "static_env", EnvVar: "MY_SECRET"})
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
	if !strings.Contains(err.Error(), "MY_SECRET") {
		t.Fatalf("error should name the env var, got %q", err.Error())
	}
}

func TestStaticEnvNeverLeaksValueInError(t *testing.T) {
	t.Setenv("MY_SECRET", "super-secret-value")
	// Force an error path (unsupported mode) while the value IS set, and assert
	// the value never appears in the error (Article III).
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{Mode: "bogus", EnvVar: "MY_SECRET"})
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Fatalf("error leaked the secret value: %q", err.Error())
	}
}

func TestStaticEnvEmptyEnvVarErrors(t *testing.T) {
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{Mode: "static_env", EnvVar: ""})
	if err == nil {
		t.Fatal("expected error for empty EnvVar")
	}
}

func TestStaticEnvUnsupportedModeErrors(t *testing.T) {
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{Mode: "client_credentials", EnvVar: "X"})
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}
