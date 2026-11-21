package rungateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// embedGateway starts a gateway routing a chat model, the defaults model and an
// embeddings model, all at the stub.
func embedGateway(t *testing.T, up *modelUpstream, agent config.AgentDef) (*Gateway, string, string, *[]engine.Event) {
	t.Helper()
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)
	gw := config.GatewayConfig{Models: map[string]config.ModelRoute{
		"planner-model": {Endpoint: ts.URL, Model: "gpt-4o", APIKeyEnv: "MODEL_KEY"},
		"chat-model":    {Endpoint: ts.URL, Model: "gpt-4o-mini", APIKeyEnv: "MODEL_KEY"},
		"embed-model":   {Endpoint: ts.URL, Model: "text-embedding-3-small", APIKeyEnv: "MODEL_KEY"},
	}}
	gw.Defaults.Model = "planner-model"
	return startRoutedGateway(t, gw, agent, t.TempDir())
}

func postEmbed(t *testing.T, base, token, body string, extra http.Header) *http.Response {
	t.Helper()
	return postDoor(t, base, token, "v1/embeddings", body, extra)
}

func embedAgent(model, embedding string) config.AgentDef {
	return config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: model, EmbeddingModel: embedding}
}

func TestEmbeddingsUnsetRefusesEveryModel(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	cases := []struct{ body, wantModel string }{
		{`{"input":"x"}`, ""},
		{`{"model":"","input":"x"}`, ""},
		{`{"model":7,"input":"x"}`, ""},
		{`{"model":"chat-model","input":"x"}`, "chat-model"},
		{`{"model":"planner-model","input":"x"}`, "planner-model"},
		{`{"model":"embed-model","input":"x"}`, "embed-model"},
	}
	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			up := &modelUpstream{mode: "embed"}
			p, base, token, events := embedGateway(t, up, embedAgent("chat-model", ""))
			resp := postEmbed(t, base, token, tc.body, nil)
			code := resp.StatusCode
			got := readBody(t, resp)
			if code != http.StatusForbidden || got != reasonEmbeddingsNotAllowed+"\n" {
				t.Fatalf("answer = %d %q", code, got)
			}
			if calls, _, _, _, _ := up.snapshot(); calls != 0 {
				t.Fatalf("upstream calls = %d, want 0", calls)
			}
			if len(*events) != 1 {
				t.Fatalf("events = %+v", *events)
			}
			ev := (*events)[0]
			if ev.Type != "model_call" || ev.Status != "refused" || ev.Reason != reasonEmbeddingsNotAllowed || ev.Model != tc.wantModel {
				t.Fatalf("event = %+v", ev)
			}
			if n := p.Stop(); n != 1 {
				t.Fatalf("Stop() = %d, want 1", n)
			}
		})
	}
}

func TestEmbeddingsUnsetCapsOversizedModel(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", ""))
	resp := postEmbed(t, base, token, `{"model":"`+strings.Repeat("é", 300)+`","input":"x"}`, nil)
	_ = readBody(t, resp)
	if len(*events) != 1 {
		t.Fatalf("events = %+v", *events)
	}
	ev := (*events)[0]
	if n := utf8.RuneCountInString(ev.Model); n != 200 {
		t.Fatalf("model runes = %d, want 200", n)
	}
	if ev.Reason != reasonEmbeddingsNotAllowed {
		t.Fatalf("reason = %q", ev.Reason)
	}
	raw, _ := json.Marshal(ev)
	if len(raw) >= 1024 {
		t.Fatalf("event is %d bytes", len(raw))
	}
}

func TestEmbeddingsRefusesOtherModel(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	bodies := []string{
		`{"input":"x"}`,
		`{"model":"","input":"x"}`,
		`{"model":7,"input":"x"}`,
		`{"model":"chat-model","input":"x"}`,
		`{"model":"planner-model","input":"x"}`,
		`{"model":"` + strings.Repeat("é", 300) + `","input":"x"}`,
	}
	for _, body := range bodies {
		up := &modelUpstream{mode: "embed"}
		_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
		resp := postEmbed(t, base, token, body, nil)
		code := resp.StatusCode
		got := readBody(t, resp)
		if code != http.StatusForbidden || got != "model not allowed\n" {
			t.Fatalf("answer = %d %q", code, got)
		}
		if calls, _, _, _, _ := up.snapshot(); calls != 0 {
			t.Fatalf("upstream calls = %d, want 0", calls)
		}
		if len(*events) != 1 {
			t.Fatalf("events = %+v", *events)
		}
		ev := (*events)[0]
		if ev.Status != "refused" || ev.Reason != fmt.Sprintf("model %q is not allowed for this agent", ev.Model) || utf8.RuneCountInString(ev.Model) > 200 {
			t.Fatalf("event = %+v", ev)
		}
	}
}

func TestEmbeddingsAndChatDoNotShareAGrant(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed"}
	_, base, token, _ := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	resp := postModel(t, base, token, `{"model":"embed-model","messages":[]}`, nil)
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("chat with the embeddings model = %d, want 403", resp.StatusCode)
	}
	resp = postEmbed(t, base, token, `{"model":"chat-model","input":"x"}`, nil)
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("embeddings with the chat model = %d, want 403", resp.StatusCode)
	}
	if calls, _, _, _, _ := up.snapshot(); calls != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls)
	}

	up2 := &modelUpstream{mode: "embed"}
	_, base, token, _ = embedGateway(t, up2, embedAgent("embed-model", "embed-model"))
	for name, resp := range map[string]*http.Response{
		"chat":       postModel(t, base, token, `{"model":"embed-model","messages":[]}`, nil),
		"embeddings": postEmbed(t, base, token, `{"model":"embed-model","input":"x"}`, nil),
	} {
		_ = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d, want 200", name, resp.StatusCode)
		}
	}
}

func TestEmbeddingsInjectsKeyRewritesModelAndStripsPassthrough(t *testing.T) {
	const marker = "DISTINCTIVE-INPUT-MARKER-4c1e"
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))

	extra := http.Header{}
	extra.Set("X-Agenthof-Foo", "leak")
	extra.Set("Cookie", "session=secret")
	extra.Set("Accept-Encoding", "br")
	resp := postDoor(t, base, token, "v1/embeddings?key=q-secret",
		`{"model":"embed-model","input":["`+marker+`",[1,2,3]],"encoding_format":"base64","dimensions":9007199254740993}`, extra)
	code := resp.StatusCode
	out := readBody(t, resp)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(out, `"embedding":[0.1,0.2,0.3]`) {
		t.Fatalf("agent did not receive the vector: %s", out)
	}
	path, q := up.target()
	if path != "/v1/embeddings" || q != "" {
		t.Fatalf("upstream target = %q ? %q", path, q)
	}
	_, auth, model, body, hdr := up.snapshot()
	if auth != "Bearer sk-provider" || strings.Contains(auth, token) {
		t.Fatalf("upstream auth = %q", auth)
	}
	if model != "text-embedding-3-small" {
		t.Fatalf("upstream model = %q", model)
	}
	for _, want := range []string{`"input":["` + marker + `",[1,2,3]]`, `"dimensions":9007199254740993`, `"encoding_format":"base64"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("upstream body lost %s: %s", want, body)
		}
	}
	for k := range hdr {
		if strings.HasPrefix(k, "X-Agenthof-") {
			t.Fatalf("header %s leaked upstream", k)
		}
	}
	if hdr.Get("Cookie") != "" || hdr.Get("Accept-Encoding") == "br" {
		t.Fatalf("passthrough headers leaked: %v", hdr)
	}
	if len(*events) != 1 {
		t.Fatalf("events = %+v", *events)
	}
	ev := (*events)[0]
	if ev.Status != "succeeded" || ev.Model != "embed-model" || ev.PromptTokens == nil || *ev.PromptTokens != 8 || ev.CompletionTokens != nil {
		t.Fatalf("event = %+v", ev)
	}
	raw, _ := json.Marshal(*events)
	if strings.Contains(string(raw), marker) || strings.Contains(string(raw), "0.1,0.2,0.3") {
		t.Fatalf("ledger carries the input or the vector: %s", raw)
	}
}

func TestEmbeddingsNeverRecordsCompletionTokens(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed-ct"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	_ = readBody(t, postEmbed(t, base, token, `{"model":"embed-model","input":"x"}`, nil))
	if len(*events) != 1 {
		t.Fatalf("events = %+v", *events)
	}
	ev := (*events)[0]
	if ev.CompletionTokens != nil || ev.PromptTokens == nil || *ev.PromptTokens != 8 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEmbeddingsWithoutUsageSucceeds(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed-nousage"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	resp := postEmbed(t, base, token, `{"model":"embed-model","input":"x"}`, nil)
	code := resp.StatusCode
	_ = readBody(t, resp)
	if code != http.StatusOK || len(*events) != 1 {
		t.Fatalf("status = %d, events = %+v", code, *events)
	}
	ev := (*events)[0]
	if ev.Status != "succeeded" || ev.PromptTokens != nil || ev.CompletionTokens != nil {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEmbeddingsPrefersProvisionedRoleKey(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	root := t.TempDir()
	dir := filepath.Join(root, ".agenthof", "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "se.key"), []byte("sk-role\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up := &modelUpstream{mode: "embed"}
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)
	gw := config.GatewayConfig{Models: map[string]config.ModelRoute{
		"embed-model": {Endpoint: ts.URL, Model: "text-embedding-3-small", APIKeyEnv: "MODEL_KEY"},
	}}
	gw.Defaults.Model = "embed-model"
	_, base, token, _ := startRoutedGateway(t, gw, embedAgent("", "embed-model"), root)
	_ = readBody(t, postEmbed(t, base, token, `{"model":"embed-model","input":"x"}`, nil))
	if _, auth, _, _, _ := up.snapshot(); auth != "Bearer sk-role" {
		t.Fatalf("upstream auth = %q, want the provisioned role key", auth)
	}
}

func TestEmbeddingsUnroutedModelFails(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "ghost"))
	resp := postEmbed(t, base, token, `{"model":"ghost","input":"x"}`, nil)
	code := resp.StatusCode
	_ = readBody(t, resp)
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", code)
	}
	if calls, _, _, _, _ := up.snapshot(); calls != 0 {
		t.Fatalf("upstream calls = %d", calls)
	}
	if len(*events) != 1 || (*events)[0].Status != "failed" || (*events)[0].Reason != "model route not resolved" {
		t.Fatalf("events = %+v", *events)
	}
}
