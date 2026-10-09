package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func TestClientApplySendsPreconditionAndDecodesEveryStatus(t *testing.T) {
	var gotIfMatch, gotIfNoneMatch, gotBody string
	status := http.StatusOK
	body := `{"status":"installed","config_hash":"sha256:ab","head":{"hash":"h","count":1},"agents":1}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Method != http.MethodPost || r.URL.Path != "/v1/config/apply" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		gotIfMatch, gotIfNoneMatch = r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok", nil)
	req := ApplyRequest{Files: map[string]string{"roles/ops.yaml": "name: ops\n"}}

	res, err := c.Apply(context.Background(), req, Precondition{ExpectInstalled: "sha256:cd"})
	if err != nil || res.Status != ApplyInstalled || res.ConfigHash != "sha256:ab" || res.Head == nil || res.Agents != 1 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if gotIfMatch != "sha256:cd" || gotIfNoneMatch != "" || gotBody != `{"files":{"roles/ops.yaml":"name: ops\n"}}` {
		t.Fatalf("If-Match %q If-None-Match %q body %q", gotIfMatch, gotIfNoneMatch, gotBody)
	}
	if _, err := c.Apply(context.Background(), req, Precondition{ExpectNone: true}); err != nil || gotIfNoneMatch != "*" || gotIfMatch != "" {
		t.Fatalf("bootstrap: If-None-Match %q If-Match %q err %v", gotIfNoneMatch, gotIfMatch, err)
	}

	for _, c2 := range []struct {
		code int
		body string
		want string
	}{
		{http.StatusForbidden, `{"status":"refused","reason":"no"}`, ApplyRefused},
		{http.StatusPreconditionFailed, `{"status":"precondition_failed","current_hash":"sha256:ef"}`, ApplyPreconditionFailed},
		{http.StatusUnprocessableEntity, `{"status":"rejected","errors":["a","b"]}`, ApplyRejected},
		{http.StatusConflict, `{"status":"busy"}`, ApplyBusy},
		{http.StatusInternalServerError, `{"status":"ledger_damaged","reason":"control ledger damaged"}`, ApplyLedgerDamaged},
	} {
		status, body = c2.code, c2.body
		res, err := c.Apply(context.Background(), req, Precondition{ExpectNone: true})
		if err != nil || res.Status != c2.want {
			t.Fatalf("%d: res %+v err %v", c2.code, res, err)
		}
	}
	status, body = http.StatusServiceUnavailable, "identity provider unavailable\n"
	_, err = c.Apply(context.Background(), req, Precondition{ExpectNone: true})
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 503 || se.Body != "identity provider unavailable" {
		t.Fatalf("503 must be a StatusError: %v", err)
	}
	if _, err := New(srv.URL, "wrong", nil).Apply(context.Background(), req, Precondition{ExpectNone: true}); !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("401 → ErrUnauthorized without the token: %v", err)
	}
}

func TestClientPullConfigAndConfigHash(t *testing.T) {
	status := http.StatusOK
	body := `{"hash":"sha256:ab","version":3,"installed_at":"2026-10-09T02:12:01Z","files":{"roles/ops.yaml":"name: ops\n"}}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Method != http.MethodGet {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok", nil)
	snap, err := c.PullConfig(context.Background())
	if err != nil || gotPath != "/v1/config" || snap.Hash != "sha256:ab" || snap.Version != 3 || snap.Files["roles/ops.yaml"] != "name: ops\n" || snap.InstalledAt.Year() != 2026 {
		t.Fatalf("snap %+v err %v path %q", snap, err, gotPath)
	}
	body = `{"hash":"sha256:ab","version":3,"installed_at":"2026-10-09T02:12:01Z"}`
	snap, err = c.ConfigHash(context.Background())
	if err != nil || gotPath != "/v1/config/hash" || snap.Hash != "sha256:ab" || snap.Files != nil {
		t.Fatalf("hash route: snap %+v err %v path %q", snap, err, gotPath)
	}
	status, body = http.StatusServiceUnavailable, PullBodyNotRecorded+"\n"
	_, err = c.PullConfig(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 503 || se.Body != PullBodyNotRecorded {
		t.Fatalf("503 must be a StatusError with the body: %v", err)
	}
	status, body = http.StatusForbidden, PullBodyRefused+"\n"
	if _, err := c.ConfigHash(context.Background()); !errors.As(err, &se) || se.Code != 403 || se.Body != PullBodyRefused {
		t.Fatalf("403: %v", err)
	}
	if _, err := New(srv.URL, "wrong", nil).PullConfig(context.Background()); !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("401 → ErrUnauthorized without the token: %v", err)
	}
}

// TestPullConfigOverCapIsMalformedAnswer: a 200 body past the client's
// 8 MiB read cap is truncated by readBody and refused as a malformed answer
// — never a partial snapshot handed to the caller.
func TestPullConfigOverCapIsMalformedAnswer(t *testing.T) {
	big := strings.Repeat("a", 9<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hash":"sha256:ab","version":1,"installed_at":"2026-10-09T02:12:01Z","files":{"roles/ops.yaml":"`+big+`"}}`)
	}))
	defer srv.Close()
	_, err := New(srv.URL, "tok", nil).PullConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "malformed answer") {
		t.Fatalf("over-cap body must be a malformed answer: %v", err)
	}
}
