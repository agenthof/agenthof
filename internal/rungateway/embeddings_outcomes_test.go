package rungateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

const embedReq = `{"model":"embed-model","input":"x"}`

func onlyModelCall(t *testing.T, events *[]engine.Event) engine.Event {
	t.Helper()
	if len(*events) != 1 || (*events)[0].Type != "model_call" {
		t.Fatalf("events = %+v, want exactly one model_call", *events)
	}
	return (*events)[0]
}

func TestEmbeddingsStreamAnswerFails(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	for name, body := range map[string]string{
		"stream requested": `{"model":"embed-model","input":"x","stream":true}`,
		"no stream flag":   embedReq,
	} {
		t.Run(name, func(t *testing.T) {
			up := &modelUpstream{mode: "stream"}
			_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
			resp := postEmbed(t, base, token, body, nil)
			code := resp.StatusCode
			got := readBody(t, resp)
			if code != http.StatusBadGateway || got != "upstream error\n" || strings.Contains(got, "data:") {
				t.Fatalf("answer = %d %q", code, got)
			}
			ev := onlyModelCall(t, events)
			if ev.Status != "failed" || ev.Reason != reasonUnexpectedStream || ev.Model != "embed-model" {
				t.Fatalf("event = %+v", ev)
			}
		})
	}
}

func TestEmbeddingsStreamFlagWithJSONAnswerSucceeds(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	resp := postEmbed(t, base, token, `{"model":"embed-model","input":"x","stream":true}`, nil)
	code := resp.StatusCode
	_ = readBody(t, resp)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if ev := onlyModelCall(t, events); ev.Status != "succeeded" {
		t.Fatalf("event = %+v", ev)
	}
	if _, _, _, body, _ := up.snapshot(); !strings.Contains(string(body), `"stream":true`) {
		t.Fatalf("forwarded body = %s, want it to carry stream:true untouched", body)
	}
}

func TestEmbeddingsResponseCapIsItsOwn(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed-big"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	resp := postEmbed(t, base, token, embedReq, nil)
	code := resp.StatusCode
	got := readBody(t, resp)
	if code != http.StatusOK || len(got) != maxChatResponse+1 {
		t.Fatalf("answer = %d, %d bytes", code, len(got))
	}
	if ev := onlyModelCall(t, events); ev.Status != "succeeded" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEmbeddingsOversizedResponseFails(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed-huge"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	resp := postEmbed(t, base, token, embedReq, nil)
	code := resp.StatusCode
	_ = readBody(t, resp)
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", code)
	}
	if ev := onlyModelCall(t, events); ev.Status != "failed" || ev.Reason != "upstream response too large" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEmbeddingsDecodesGzippedResponse(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed-gzip"}
	_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	resp := postEmbed(t, base, token, embedReq, http.Header{"Accept-Encoding": {"gzip"}})
	code := resp.StatusCode
	_ = readBody(t, resp)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	ev := onlyModelCall(t, events)
	if ev.Status != "succeeded" || ev.PromptTokens == nil || *ev.PromptTokens != 8 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEmbeddingsUpstreamErrors(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	for _, tc := range []struct {
		mode, reason string
		code         int
	}{
		{"429", "budget", http.StatusTooManyRequests},
		{"500", "upstream 500 Internal Server Error", http.StatusInternalServerError},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			up := &modelUpstream{mode: tc.mode}
			_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
			resp := postEmbed(t, base, token, embedReq, nil)
			code := resp.StatusCode
			_ = readBody(t, resp)
			if code != tc.code {
				t.Fatalf("status = %d, want %d", code, tc.code)
			}
			ev := onlyModelCall(t, events)
			if ev.Status != "refused" || ev.Reason != tc.reason {
				t.Fatalf("event = %+v", ev)
			}
			if b, _ := json.Marshal(*events); strings.Contains(string(b), "SECRET-UPSTREAM-BODY") {
				t.Fatalf("events carry the upstream body: %s", b)
			}
		})
	}
}

func TestEmbeddingsUnreachableFails(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	gw := config.GatewayConfig{Models: map[string]config.ModelRoute{
		"embed-model": {Endpoint: closedURL, Model: "text-embedding-3-small", APIKeyEnv: "MODEL_KEY"},
	}}
	gw.Defaults.Model = "embed-model"
	_, base, token, events := startRoutedGateway(t, gw, embedAgent("", "embed-model"), t.TempDir())
	resp := postEmbed(t, base, token, embedReq, nil)
	code := resp.StatusCode
	_ = readBody(t, resp)
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", code)
	}
	if ev := onlyModelCall(t, events); ev.Status != "failed" || ev.Reason != "model call did not complete" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEmbeddingsCallAcrossStopIsRecordedOnce(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "hang"}
	p, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))

	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		// Stop cuts this connection, so the client is expected to see an
		// error: the request is built here, not through postEmbed, which
		// fails the test on one.
		req, err := http.NewRequest(http.MethodPost, base+"v1/embeddings", strings.NewReader(embedReq))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	waitFor(t, "the embeddings call to reach the upstream", func() bool { c, _, _, _, _ := up.snapshot(); return c == 1 })

	stopped := make(chan int, 1)
	go func() { stopped <- p.Stop() }()
	var n int
	select {
	case n = <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return: the in-flight embeddings call was not cancelled")
	}
	<-callDone
	if ev := onlyModelCall(t, events); ev.Status != "failed" || ev.Reason != "model call did not complete" {
		t.Fatalf("event = %+v", ev)
	}
	if n != 1 {
		t.Fatalf("Stop() = %d, want 1", n)
	}
}

func TestEmbeddingsPreAdmissionAnswersAreNotDoorCalls(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	p, base, token, events := embedGateway(t, &modelUpstream{mode: "embed"}, embedAgent("chat-model", "embed-model"))
	get, _ := http.NewRequest(http.MethodGet, base+"v1/embeddings", nil)
	get.Header.Set("Authorization", "Bearer "+token)
	if resp, err := http.DefaultClient.Do(get); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %v %v", resp, err)
	}
	if resp := postEmbed(t, base, token, `[1]`, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("array body: %d, want 400", resp.StatusCode)
	}
	big := `{"model":"embed-model","input":"` + strings.Repeat("x", maxDoorBody) + `"}`
	if resp := postEmbed(t, base, token, big, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: %d, want 400", resp.StatusCode)
	}
	if resp := postEmbed(t, base, "nope", embedReq, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: %d, want 401", resp.StatusCode)
	}
	if n := p.Stop(); n != 0 || len(*events) != 0 {
		t.Fatalf("Stop() = %d, events = %+v; want 0 and none", n, *events)
	}
}

func TestV1NearMissPathsAreNotDoors(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "embed"}
	p, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
	for _, path := range []string{"v1/embeddings/", "v1/embeddings/x", "v1/moderations"} {
		resp := postDoor(t, base, token, path, embedReq, nil)
		code := resp.StatusCode
		_ = readBody(t, resp)
		if code >= 200 && code < 300 {
			t.Fatalf("%s answered %d, want a non-2xx", path, code)
		}
	}
	if calls, _, _, _, _ := up.snapshot(); calls != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls)
	}
	if n := p.Stop(); n != 0 || len(*events) != 0 {
		t.Fatalf("Stop() = %d, events = %+v; want 0 and none", n, *events)
	}
}
