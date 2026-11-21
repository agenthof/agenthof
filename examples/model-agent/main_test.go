package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerReturnsModelReply(t *testing.T) {
	const marker = "DISTINCTIVE-PROMPT-MARKER-9f3a"
	var gotAuth, gotModel, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		var req map[string]any
		_ = json.Unmarshal(b, &req)
		gotModel, _ = req["model"].(string)
		if !strings.HasSuffix(r.URL.Path, "/v1/chat/completions") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"the patch"}}]}`))
	}))
	defer upstream.Close()

	h := &handler{model: "planner-model", client: upstream.Client()}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"input":"`+marker+`","agent":"coder"}`))
	req.Header.Set("X-Agenthof-Proxy-URL", upstream.URL+"/")
	req.Header.Set("X-Agenthof-Run-Token", "run-tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Artifact string `json:"artifact"`
		Success  bool   `json:"success"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success || resp.Artifact != "the patch" {
		t.Fatalf("response = %+v", resp)
	}
	if gotAuth != "Bearer run-tok" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotModel != "planner-model" {
		t.Fatalf("model = %q", gotModel)
	}
	if !strings.Contains(gotBody, marker) {
		t.Fatalf("prompt not forwarded: %s", gotBody)
	}
}

func TestHandlerMissingCoordinates(t *testing.T) {
	h := &handler{model: "planner-model", client: http.DefaultClient}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"input":"x","agent":"coder"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp struct {
		Success bool   `json:"success"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Success || resp.Reason == "" {
		t.Fatalf("response = %+v", resp)
	}
}

type embedResult struct {
	Artifact string `json:"artifact"`
	Success  bool   `json:"success"`
	Reason   string `json:"reason"`
}

// embedStep posts one step to an embed-mode handler backed by a stub proxy
// that answers status/body, and returns the decoded step response.
func embedStep(t *testing.T, status int, body string, inspect func(r *http.Request, b []byte)) embedResult {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if inspect != nil {
			inspect(r, b)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()

	h := &handler{model: "embed", embed: true, client: upstream.Client()}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"input":"hello","agent":"embedder"}`))
	req.Header.Set("X-Agenthof-Proxy-URL", upstream.URL+"/")
	req.Header.Set("X-Agenthof-Run-Token", "run-tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp embedResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHandlerEmbedsInput(t *testing.T) {
	resp := embedStep(t, http.StatusOK, `{"data":[{"embedding":[0.1,0.2,0.3]}]}`, func(r *http.Request, b []byte) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer run-tok" {
			t.Errorf("auth = %q", got)
		}
		var req map[string]any
		_ = json.Unmarshal(b, &req)
		if req["model"] != "embed" || req["input"] != "hello" {
			t.Errorf("body = %s", b)
		}
	})
	if !resp.Success || resp.Artifact != "embedded: 3 dimensions" {
		t.Fatalf("response = %+v", resp)
	}
}

func TestHandlerEmbedRefused(t *testing.T) {
	resp := embedStep(t, http.StatusForbidden, `{"error":"denied"}`, nil)
	if resp.Success || resp.Reason != "embeddings door returned 403" {
		t.Fatalf("response = %+v", resp)
	}
}

func TestHandlerEmbedEmptyReply(t *testing.T) {
	resp := embedStep(t, http.StatusOK, `{"data":[]}`, nil)
	if resp.Success || resp.Reason != "embeddings reply carried no vector" {
		t.Fatalf("response = %+v", resp)
	}
}
