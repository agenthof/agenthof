package agentrt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
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
// a "chat.completion".
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

	res, err := x.Execute(context.Background(), engine.Binding{}, agentDef, "hello", nil)
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

	res, err := x.Execute(context.Background(), engine.Binding{}, agentDef, "hello", nil)
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

// TestADKExecutor_Execute_ToolDispatchRoundTrip proves tool dispatch works
// end to end against the Responses API's function-calling wire shape: a
// first request/response pair where the model asks to call read_file, and a
// second request that must carry the tool's result back as a
// function_call_output item, followed by a final text answer.
//
// Wire shapes below were confirmed by reading adk v2.3.0's converters
// directly (not guessed then iterated):
//   - output item -> genai.Part: model/openaimodel/response.go
//     (convertFunctionCall reads item.Name/item.CallID/item.Arguments, the
//     last a JSON *string*)
//   - genai.FunctionCall -> input item: model/openaimodel/request.go
//     (newFunctionCall marshals Args to a JSON string under "arguments")
//   - tool result -> genai.FunctionResponse -> input item: newFunctionResponse
//     marshals fr.Response to a JSON string under "output"; the openai-go
//     struct tags (github.com/openai/openai-go/v3/responses ResponseFunctionToolCallParam,
//     ResponseInputItemFunctionCallOutputParam) confirm the exact field
//     names asserted below (call_id, name, arguments, type=function_call /
//     function_call_output).
func TestADKExecutor_Execute_ToolDispatchRoundTrip(t *testing.T) {
	const seedContent = "hello agenthof workspace"
	const seedPath = "seed.txt"

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, seedPath), []byte(seedContent), 0o644); err != nil {
		t.Fatalf("seed workspace file: %v", err)
	}

	var (
		requestN   int
		turn1Body  string
		turn2Body  string
		turn2Items []map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestN++
		body, _ := io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		switch requestN {
		case 1:
			turn1Body = string(body)
			// The model's first turn: a single function_call output item
			// invoking read_file on the seeded file. No output_text here —
			// convertOutputItems would append it to the artifact, which
			// would defeat the point of proving the round trip.
			_, _ = w.Write([]byte(`{
				"id": "resp_1",
				"object": "response",
				"created_at": 0,
				"model": "stub-model",
				"status": "completed",
				"output": [
					{
						"id": "fc_1",
						"type": "function_call",
						"call_id": "call_1",
						"name": "read_file",
						"arguments": "{\"path\":\"seed.txt\",\"start_line\":0,\"end_line\":0}",
						"status": "completed"
					}
				],
				"usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
			}`))
		case 2:
			turn2Body = string(body)
			var decoded map[string]any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Errorf("decode request 2 body: %v", err)
			} else if items, ok := decoded["input"].([]any); ok {
				for _, it := range items {
					if m, ok := it.(map[string]any); ok {
						turn2Items = append(turn2Items, m)
					}
				}
			}
			_, _ = w.Write([]byte(`{
				"id": "resp_2",
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
							{"type": "output_text", "text": "done: ` + seedContent + `", "annotations": []}
						]
					}
				],
				"usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
			}`))
		default:
			t.Errorf("unexpected request %d", requestN)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	gw := newStubGateway(t, srv.URL)
	x := ADKExecutor{Gateway: gw, WorkspaceDir: ws}

	agentDef := config.AgentDef{
		Name:        "stub_agent",
		Description: "an agent with the read_file tool",
		Model:       "fast",
		Instruction: "You are a test agent. Call read_file on seed.txt, then reply with what it returned.",
		Tools:       []string{"read_file"},
	}

	res, err := x.Execute(context.Background(), engine.Binding{}, agentDef, "read the seed file", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected engine error: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute: Success = false, Reason = %q", res.Reason)
	}
	if !strings.Contains(res.Artifact, seedContent) {
		t.Errorf("Artifact = %q, want it to contain seeded content %q", res.Artifact, seedContent)
	}

	if requestN != 2 {
		t.Fatalf("requestN = %d, want exactly 2 requests (tool call + follow-up)", requestN)
	}

	// Request 2 must carry the tool's result back as a function_call_output
	// item, and that item's "output" must embed the seeded file content.
	var found bool
	for _, item := range turn2Items {
		if item["type"] != "function_call_output" {
			continue
		}
		found = true
		if item["call_id"] != "call_1" {
			t.Errorf("function_call_output call_id = %v, want %q", item["call_id"], "call_1")
		}
		out, _ := item["output"].(string)
		if !strings.Contains(out, seedContent) {
			t.Errorf("function_call_output output = %q, want it to contain %q", out, seedContent)
		}
	}
	if !found {
		t.Errorf("request 2 input items = %+v, want a function_call_output item", turn2Items)
	}
	if !strings.Contains(turn2Body, seedContent) {
		t.Errorf("request 2 raw body does not contain seeded content %q:\n%s", seedContent, turn2Body)
	}

	t.Logf("request 1 body: %s", turn1Body)
	t.Logf("request 2 body: %s", turn2Body)
}
