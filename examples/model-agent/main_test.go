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
