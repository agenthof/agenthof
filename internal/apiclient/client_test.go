package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientSendsBearerAndDecodes(t *testing.T) {
	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/runs":
			var req RunRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Role != "se" {
				t.Errorf("role = %q", req.Role)
			}
			w.Header().Set("Location", "/v1/runs/r-1")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(RunAccepted{RunID: "r-1", Status: StatusRunning})
		case "GET /v1/runs/r-1":
			polls++
			st := RunStatus{RunID: "r-1", Status: StatusRunning}
			if polls >= 2 {
				st.Status = "succeeded"
			}
			_ = json.NewEncoder(w).Encode(st)
		case "GET /v1/runs/r-1/audit":
			w.Header().Set(IntegrityHeader, IntegrityTorn)
			_, _ = w.Write([]byte("run r-1 — w (role se)\n"))
		case "GET /v1/investigate":
			if r.URL.Query().Get("run") != "r-1" {
				t.Errorf("query = %v", r.URL.Query())
			}
			_, _ = w.Write([]byte(`{"v":"investigate/1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "tok-1", srv.Client())
	ctx := context.Background()
	acc, err := c.StartRun(ctx, RunRequest{Role: "se", Workflow: "w", Input: "x"})
	if err != nil || acc.RunID != "r-1" || acc.Status != StatusRunning {
		t.Fatalf("acc=%+v err=%v", acc, err)
	}
	st, err := c.WaitRun(ctx, "r-1", time.Millisecond)
	if err != nil || st.Status != "succeeded" || polls < 2 {
		t.Fatalf("st=%+v err=%v polls=%d", st, err, polls)
	}
	text, integrity, err := c.Audit(ctx, "r-1")
	if err != nil || integrity != IntegrityTorn || !strings.HasPrefix(text, "run r-1") {
		t.Fatalf("text=%q integrity=%q err=%v", text, integrity, err)
	}
	doc, err := c.Investigate(ctx, InvestigateQuery{Run: "r-1"})
	if err != nil || string(doc) != `{"v":"investigate/1"}` {
		t.Fatalf("doc=%s err=%v", doc, err)
	}
}

func TestClientRefusalAndErrorsNeverEchoTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runs":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(RunAccepted{RunID: "r-2", Status: StatusRefused, Reason: "no"})
		case "/v1/runs/r-9":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		default:
			http.Error(w, "boom "+strings.Repeat("x", 1000), http.StatusBadGateway)
		}
	}))
	t.Cleanup(srv.Close)
	const token = "super-secret-token"
	c := New(srv.URL, token, srv.Client())
	acc, err := c.StartRun(context.Background(), RunRequest{Role: "se", Workflow: "w", Input: "x"})
	if err != nil || acc.Status != StatusRefused || acc.Reason != "no" {
		t.Fatalf("a 403 is a refusal, not an error: acc=%+v err=%v", acc, err)
	}
	_, err = c.GetRun(context.Background(), "r-9")
	if !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), token) {
		t.Fatalf("err = %v", err)
	}
	_, _, err = c.Audit(context.Background(), "r-3")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadGateway || len(se.Body) > 200 || strings.Contains(err.Error(), token) {
		t.Fatalf("err = %v", err)
	}
}
