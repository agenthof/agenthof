package agentrt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

// newStubGateway builds a config.GatewayConfig routing the logical model
// "fast" at srvURL, with the API key sourced from an environment variable
// (set via t.Setenv), matching how a real deployment provisions per-role
// keys.
func newStubGateway(t *testing.T, srvURL string) config.GatewayConfig {
	t.Helper()
	const envVar = "AGENTHOF_TEST_STUB_KEY"
	t.Setenv(envVar, "sk-test-stub-key")
	return config.GatewayConfig{
		Models: map[string]config.ModelRoute{
			"fast": {
				Endpoint:  srvURL,
				Model:     "stub-model",
				APIKeyEnv: envVar,
			},
		},
	}
}

// TestADKExecutor_Execute_Success proves the full wire path end to end
// against an httptest stub speaking the OpenAI *Responses* API (not Chat
// Completions): adk v2.3.0's openaimodel calls client.Responses.New, which
// POSTs to "{BaseURL}/responses" and expects a "response" object back, not
// a "chat.completion". See task-6-report.md for the discovery trail.
func TestADKExecutor_Execute_Success(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotBody   map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "resp_1",
			"object": "response",
			"created_at": 0,
			"model": "stub-model",
			"status": "completed",
			"output": [
				{
					"id": "msg_1",
					"type": "message",
					"role": "assistant",
					"status": "completed",
					"content": [
						{"type": "output_text", "text": "stub answer", "annotations": []}
					]
				}
			],
			"usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
		}`))
	}))
	defer srv.Close()

	gw := newStubGateway(t, srv.URL)
	x := ADKExecutor{Gateway: gw, WorkspaceDir: t.TempDir()}

	agentDef := config.AgentDef{
		Name:        "stub_agent",
		Description: "a no-tools test agent",
		Model:       "fast",
		Instruction: "You are a test agent. Reply with whatever the tool result says.",
	}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected engine error: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute: Success = false, Reason = %q", res.Reason)
	}
	if res.Artifact != "stub answer" {
		t.Errorf("Artifact = %q, want %q", res.Artifact, "stub answer")
	}

	if gotMethod != http.MethodPost {
		t.Errorf("request method = %q, want POST", gotMethod)
	}
	if gotPath != "/responses" {
		t.Errorf("request path = %q, want /responses (adk's openaimodel speaks the Responses API, not /chat/completions)", gotPath)
	}
	if gotBody["model"] != "stub-model" {
		t.Errorf("request body model = %v, want %q", gotBody["model"], "stub-model")
	}
}

// TestADKExecutor_Execute_BudgetRefusal proves the budget-refusal path is
// observable offline: a 429 with an OpenAI-shaped error envelope surfaces as
// a failed step (not an engine error) whose Reason names the refusal.
func TestADKExecutor_Execute_BudgetRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Tell the openai-go client not to retry: a bare 429 is retried
		// (with backoff) up to its default MaxRetries, which would make
		// this test slow and multiply the stub hit count for no benefit.
		w.Header().Set("X-Should-Retry", "false")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"Budget has been exceeded"}}`))
	}))
	defer srv.Close()

	gw := newStubGateway(t, srv.URL)
	x := ADKExecutor{Gateway: gw, WorkspaceDir: t.TempDir()}

	agentDef := config.AgentDef{
		Name:        "stub_agent",
		Description: "a no-tools test agent",
		Model:       "fast",
		Instruction: "You are a test agent.",
	}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected engine error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false (budget refusal)")
	}
	if !strings.Contains(res.Reason, "Budget") {
		t.Errorf("Reason = %q, want it to contain %q", res.Reason, "Budget")
	}
}
