package main

import (
	"context"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/broker"
)

func TestSubjectTokenTypeFromEnv(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if got := subjectTokenTypeFromEnv(getenv); got != broker.SubjectTokenTypeAccessToken {
		t.Fatalf("default = %q, want the access_token URN", got)
	}
	env["AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE"] = "urn:ietf:params:oauth:token-type:id_token"
	if got := subjectTokenTypeFromEnv(getenv); got != "urn:ietf:params:oauth:token-type:id_token" {
		t.Fatalf("env override ignored: %q", got)
	}
}

// TestNewBrokerRoutesTokenExchange: the process broker routes a
// token_exchange ref to the TokenExchange broker (its fixed-vocabulary
// error proves which broker answered), never to StaticEnv.
func TestNewBrokerRoutesTokenExchange(t *testing.T) {
	t.Setenv("AGENTHOF_TEST_UNSET_TE_ID", "")
	ref := broker.CredentialRef{
		ResourceID: "github", Source: "static_env", Grant: "token_exchange",
		ClientAuth: "client_secret_basic", TokenURL: "https://token.example.test/",
		Audience: "https://up.example.test", SubjectToken: "zq9subjectAAAA",
		ClientIDEnv: "AGENTHOF_TEST_UNSET_TE_ID", ClientSecretEnv: "AGENTHOF_TEST_UNSET_TE_SECRET",
	}
	_, err := newBroker(broker.SubjectTokenTypeAccessToken).Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("resolve must fail with the client-id env unset")
	}
	if !strings.Contains(err.Error(), "client id env AGENTHOF_TEST_UNSET_TE_ID") {
		t.Fatalf("token_exchange must route to the TokenExchange broker, got: %v", err)
	}
	if strings.Contains(err.Error(), "zq9subjectAAAA") {
		t.Fatalf("error leaked the subject token: %v", err)
	}
}
