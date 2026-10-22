package broker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestStaticEnvKeyPairResolvesThreeNames(t *testing.T) {
	t.Setenv("W_ID", "AKIDEXAMPLE")
	t.Setenv("W_SECRET", "s3cret")
	t.Setenv("W_SESSION", "tok")
	ctx := context.Background()

	kp, err := StaticEnvKeyPair{}.ResolveKeyPair(ctx, CredentialRef{
		Source: "static_env", ClientAuth: "sigv4",
		ClientIDEnv: "W_ID", ClientSecretEnv: "W_SECRET", TokenEnv: "W_SESSION",
	})
	if err != nil {
		t.Fatalf("ResolveKeyPair: %v", err)
	}
	if want := (KeyPair{ID: "AKIDEXAMPLE", Secret: "s3cret", Session: "tok"}); kp != want {
		t.Fatalf("key pair = %+v, want %+v", kp, want)
	}

	// No token_env means permanent keys: no session token.
	kp, err = StaticEnvKeyPair{}.ResolveKeyPair(ctx, CredentialRef{
		ClientAuth: "sigv4", ClientIDEnv: "W_ID", ClientSecretEnv: "W_SECRET",
	})
	if err != nil {
		t.Fatalf("ResolveKeyPair (permanent keys): %v", err)
	}
	if kp.Session != "" {
		t.Fatalf("Session = %q, want empty for a ref with no token_env", kp.Session)
	}
}

func TestStaticEnvKeyPairRefusals(t *testing.T) {
	t.Setenv("W_ID", "AKIDEXAMPLE")
	t.Setenv("W_SECRET", "s3cret")
	tests := []struct {
		name string
		ref  CredentialRef
		want string
	}{
		{
			"not sigv4",
			CredentialRef{ClientAuth: "client_secret_basic", ClientIDEnv: "W_ID", ClientSecretEnv: "W_SECRET"},
			`broker: static_env key pair handles client_auth sigv4 only, not "client_secret_basic"`,
		},
		{
			"unsupported source",
			CredentialRef{ClientAuth: "sigv4", Source: "web_identity", ClientIDEnv: "W_ID", ClientSecretEnv: "W_SECRET"},
			`broker: unsupported credential source "web_identity"`,
		},
		{
			"grant set",
			CredentialRef{ClientAuth: "sigv4", Grant: "client_credentials", ClientIDEnv: "W_ID", ClientSecretEnv: "W_SECRET"},
			`broker: a sigv4 key pair is used directly; grant "client_credentials" is not supported`,
		},
		{
			"secret env name missing",
			CredentialRef{ClientAuth: "sigv4", ClientIDEnv: "W_ID"},
			"broker: sigv4 key pair needs client_id_env and client_secret_env",
		},
		{
			"id env name missing",
			CredentialRef{ClientAuth: "sigv4", ClientSecretEnv: "W_SECRET"},
			"broker: sigv4 key pair needs client_id_env and client_secret_env",
		},
		{
			"secret env unset",
			CredentialRef{ClientAuth: "sigv4", ClientIDEnv: "W_ID", ClientSecretEnv: "W_UNSET"},
			"broker: environment variable W_UNSET is not set",
		},
		{
			"id env unset",
			CredentialRef{ClientAuth: "sigv4", ClientIDEnv: "W_UNSET_ID", ClientSecretEnv: "W_SECRET"},
			"broker: environment variable W_UNSET_ID is not set",
		},
		{
			"named session env unset",
			CredentialRef{ClientAuth: "sigv4", ClientIDEnv: "W_ID", ClientSecretEnv: "W_SECRET", TokenEnv: "W_UNSET_SESSION"},
			"broker: environment variable W_UNSET_SESSION is not set",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := StaticEnvKeyPair{}.ResolveKeyPair(context.Background(), tc.ref)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if err.Error() != tc.want {
				t.Fatalf("error = %q, want %q", err.Error(), tc.want)
			}
			if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "AKIDEXAMPLE") {
				t.Fatalf("error leaks a credential value: %q", err.Error())
			}
			if kp != (KeyPair{}) {
				t.Fatalf("key pair = %+v on error, want zero", kp)
			}
		})
	}
}

// TestKeyPairLogValueRedacts: a KeyPair carries secret VALUES, so it must
// render as REDACTED whenever it is passed to slog as an attribute value — as a
// bare value and via slog.Any.
func TestKeyPairLogValueRedacts(t *testing.T) {
	const secret = "zq9secretAAAA"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	kp := KeyPair{ID: "AKIDEXAMPLE", Secret: secret, Session: "tok"}
	logger.Debug("signing", "key_pair", kp)
	logger.Debug("signing", slog.Any("key_pair", kp))
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret reached the log: %s", out)
	}
	if strings.Count(out, "REDACTED") != 2 {
		t.Fatalf("expected both log lines to render the key pair as REDACTED:\n%s", out)
	}
}
