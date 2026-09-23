package broker

import (
	"context"
	"strings"
	"testing"
)

func TestStaticEnvReturnsDirectBearer(t *testing.T) {
	t.Setenv("AGENTHOF_TEST_TOKEN", "s3cret-bearer")
	got, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{
		Source: "static_env", Grant: "", TokenEnv: "AGENTHOF_TEST_TOKEN",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "s3cret-bearer" {
		t.Fatalf("token = %q, want %q", got, "s3cret-bearer")
	}
}

func TestStaticEnvRejectsNonEmptyGrant(t *testing.T) {
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{
		Source: "static_env", Grant: "client_credentials", TokenEnv: "X",
	})
	if err == nil {
		t.Fatal("expected error for non-direct grant, got nil")
	}
}

func TestStaticEnvErrorNamesVarNotValue(t *testing.T) {
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{
		Source: "static_env", TokenEnv: "AGENTHOF_MISSING_VAR",
	})
	if err == nil {
		t.Fatal("expected error for missing var")
	}
	if got := err.Error(); !strings.Contains(got, "AGENTHOF_MISSING_VAR") {
		t.Fatalf("error %q should name the env var", got)
	}
}

// fakeBroker records which ref it saw and returns a fixed token.
type fakeBroker struct {
	last  CredentialRef
	token string
}

func (f *fakeBroker) Resolve(_ context.Context, ref CredentialRef) (string, error) {
	f.last = ref
	return f.token, nil
}

func TestDispatchRoutesOnGrant(t *testing.T) {
	static := &fakeBroker{token: "static-tok"}
	cc := &fakeBroker{token: "minted-tok"}
	d := Dispatch{StaticEnv: static, ClientCredentials: cc}

	got, err := d.Resolve(context.Background(), CredentialRef{Grant: ""})
	if err != nil || got != "static-tok" {
		t.Fatalf("empty grant routed wrong: got %q err %v", got, err)
	}
	got, err = d.Resolve(context.Background(), CredentialRef{Grant: "client_credentials"})
	if err != nil || got != "minted-tok" {
		t.Fatalf("client_credentials routed wrong: got %q err %v", got, err)
	}
	if _, err := d.Resolve(context.Background(), CredentialRef{Grant: "token_exchange"}); err == nil {
		t.Fatal("unknown grant should error")
	}
}
