package main

import (
	"context"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/registry"
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

func oboTestConfig(grant string) config.Config {
	tools := map[string]config.ToolResource{
		"plain": {Kind: "mcp", URL: "https://mcp.example.com/", CredentialSource: "static_env", TokenEnv: "T"},
		"obo": {Kind: "mcp", URL: "https://mcp.example.com/", CredentialSource: "static_env", GrantType: "token_exchange",
			ClientAuth: "client_secret_basic", TokenEndpoint: "https://idp.example.com/token", Audience: "https://mcp.example.com",
			ClientIDEnv: "TE_ID", ClientSecretEnv: "TE_SECRET"},
	}
	return config.Config{
		Agents: []config.AgentDef{
			{Name: "planner", Model: "fast", Endpoint: "https://example.test/run", Tools: []config.ToolGrant{{Resource: grant, Mode: "all"}}},
			{Name: "coder", Model: "fast", Endpoint: "https://example.test/run"},
		},
		Workflows: []config.WorkflowDef{
			{Name: "with-planner", Steps: []config.Step{{Name: "plan", Agent: "planner"}, {Name: "code", Agent: "coder"}}},
			{Name: "planner-last", Steps: []config.Step{{Name: "code", Agent: "coder"}, {Name: "plan", Agent: "planner"}}},
			{Name: "coder-only", Steps: []config.Step{{Name: "code", Agent: "coder"}}},
		},
		Roles:   []config.RoleDef{{Name: "se", Workflows: []string{"with-planner", "planner-last", "coder-only"}, AllowedGroups: []string{"*"}}},
		Gateway: config.GatewayConfig{Tools: tools, Models: map[string]config.ModelRoute{"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"}}},
	}
}

func TestWorkflowRequiresOBO(t *testing.T) {
	cfg := oboTestConfig("obo")
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	if !workflowRequiresOBO(cfg, reg, "with-planner") {
		t.Fatal("a workflow whose step agent grants a token_exchange resource requires OBO")
	}
	// Every step is examined, not just the first: the refusal happens
	// before the engine, so a later step's grant must be seen up front.
	if !workflowRequiresOBO(cfg, reg, "planner-last") {
		t.Fatal("a workflow whose SECOND step grants a token_exchange resource requires OBO")
	}
	if workflowRequiresOBO(cfg, reg, "coder-only") {
		t.Fatal("a workflow whose agents grant no token_exchange resource does not require OBO")
	}
	if workflowRequiresOBO(cfg, reg, "nope") {
		t.Fatal("an unknown workflow is the engine's refusal, not an OBO one")
	}
	plain := oboTestConfig("plain")
	regPlain, errs := registry.Build(plain)
	if regPlain == nil {
		t.Fatal(errs)
	}
	if workflowRequiresOBO(plain, regPlain, "with-planner") {
		t.Fatal("a static_env grant does not require OBO")
	}
}
