package agentrt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// TestAdapterExecutor_Execute_Success proves the happy-path wire contract:
// the adapter POSTs {"input", "artifacts", "agent"} with the
// X-Agenthof-Agent header and JSON content type, and a 200 response with
// success:true maps verbatim onto StepResult.
func TestAdapterExecutor_Execute_Success(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotAgentHeader string
		gotBody        map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAgentHeader = r.Header.Get("X-Agenthof-Agent")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"artifact":"out","success":true}`))
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", map[string]string{})
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute: Success = false, Reason = %q", res.Reason)
	}
	if res.Artifact != "out" {
		t.Errorf("Artifact = %q, want %q", res.Artifact, "out")
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAgentHeader != "fronted_agent" {
		t.Errorf("X-Agenthof-Agent = %q, want %q", gotAgentHeader, "fronted_agent")
	}
	if _, ok := gotBody["input"]; !ok {
		t.Errorf("request body missing %q field: %+v", "input", gotBody)
	}
	if _, ok := gotBody["artifacts"]; !ok {
		t.Errorf("request body missing %q field: %+v", "artifacts", gotBody)
	}
	if gotBody["agent"] != "fronted_agent" {
		t.Errorf("request body agent = %v, want %q", gotBody["agent"], "fronted_agent")
	}
	if gotBody["input"] != "hello" {
		t.Errorf("request body input = %v, want %q", gotBody["input"], "hello")
	}
}

// TestAdapterExecutor_Execute_SuccessFalse proves success:false plus a
// reason string is propagated verbatim onto StepResult.
func TestAdapterExecutor_Execute_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"reason":"agent declined"}`))
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false")
	}
	if res.Reason != "agent declined" {
		t.Errorf("Reason = %q, want %q", res.Reason, "agent declined")
	}
}

// TestAdapterExecutor_Execute_NonOK proves a non-200 response is reported
// as a failed step (not an engine error) naming the status code.
func TestAdapterExecutor_Execute_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false")
	}
	if res.Reason != "adapter returned 500" {
		t.Errorf("Reason = %q, want %q", res.Reason, "adapter returned 500")
	}
}

// TestAdapterExecutor_Execute_Timeout proves a slow adapter is reported as
// a failed step whose reason mentions the timeout/deadline, not an engine
// error.
func TestAdapterExecutor_Execute_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"too late"}`))
	}))
	defer srv.Close()

	x := AdapterExecutor{Timeout: 100 * time.Millisecond}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false (timeout)")
	}
	reason := res.Reason
	if !strings.Contains(strings.ToLower(reason), "deadline") && !strings.Contains(strings.ToLower(reason), "timeout") {
		t.Errorf("Reason = %q, want it to mention deadline/timeout", res.Reason)
	}
}

// TestAdapterExecutor_Execute_ArtifactsTransmitted proves the artifacts map
// is transmitted intact to the adapter endpoint.
func TestAdapterExecutor_Execute_ArtifactsTransmitted(t *testing.T) {
	var gotBody struct {
		Artifacts map[string]string `json:"artifacts"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"ok"}`))
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}
	artifacts := map[string]string{"prior_step": "prior value"}

	_, err := x.Execute(context.Background(), agentDef, "hello", artifacts)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if gotBody.Artifacts["prior_step"] != "prior value" {
		t.Errorf("artifacts[prior_step] = %q, want %q", gotBody.Artifacts["prior_step"], "prior value")
	}
}

// TestAdapterExecutor_Execute_OversizedResponse proves a fronted-agent
// response body larger than the 1 MiB cap is reported as a failed step
// naming the limit, not read into memory without bound and not surfaced as
// an engine error. The adapter is a trust boundary: a misbehaving or
// compromised fronted agent must not be able to exhaust platform memory by
// returning an unbounded body.
func TestAdapterExecutor_Execute_OversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// One byte over the 1 MiB cap, wrapped in a JSON string so a
		// hypothetical unbounded implementation would still parse it.
		big := strings.Repeat("a", maxAdapterResponseBytes+1)
		_, _ = w.Write([]byte(`{"success":true,"artifact":"` + big + `"}`))
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false (oversized response)")
	}
	if !strings.Contains(res.Reason, "1 MiB") {
		t.Errorf("Reason = %q, want it to mention the 1 MiB limit", res.Reason)
	}
}

// TestAdapterExecutor_Execute_MalformedJSON proves a 200 response whose
// body isn't valid JSON is reported as a failed step with a non-empty
// reason, not an engine error.
func TestAdapterExecutor_Execute_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false (malformed JSON)")
	}
	if res.Reason == "" {
		t.Errorf("Reason = %q, want a non-empty reason", res.Reason)
	}
}

// TestAdapterExecutor_Execute_DoesNotFollowRedirects proves the adapter
// treats a 3xx response as a failed step naming the status code, rather than
// following the redirect to whatever Location the fronted agent names. The
// adapter is a trust boundary: a misbehaving or compromised fronted agent
// must not be able to redirect the platform's outbound request to an
// arbitrary third party.
func TestAdapterExecutor_Execute_DoesNotFollowRedirects(t *testing.T) {
	var secondHits int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"should never be reached"}`))
	}))
	defer second.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL, http.StatusFound)
	}))
	defer first.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: first.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false (redirect must not be followed)")
	}
	if res.Reason != "adapter returned 302" {
		t.Errorf("Reason = %q, want %q", res.Reason, "adapter returned 302")
	}
	if hits := atomic.LoadInt32(&secondHits); hits != 0 {
		t.Errorf("second server hit %d time(s), want 0 — the adapter followed the redirect", hits)
	}
}

// TestAdapterExecutor_Execute_ReasonTruncated proves an oversized
// endpoint-supplied reason (success:false path) is capped, so a
// misbehaving fronted agent can't bloat the ledger/audit output with an
// unbounded string.
func TestAdapterExecutor_Execute_ReasonTruncated(t *testing.T) {
	longReason := strings.Repeat("a", 10000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(map[string]any{"success": false, "reason": longReason})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: srv.URL}

	res, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatalf("Execute: Success = true, want false")
	}
	if len(res.Reason) > 320 {
		t.Errorf("Reason length = %d, want bounded (~313)", len(res.Reason))
	}
	if !strings.Contains(res.Reason, "truncated") {
		t.Errorf("Reason = %q, want a truncation marker", res.Reason)
	}
}

// TestAdapterExecutor_Execute_EmptyEndpoint proves a missing endpoint (a
// configuration problem that validation should have already caught) is
// reported as an engine.ErrStepConfig-wrapping error.
func TestAdapterExecutor_Execute_EmptyEndpoint(t *testing.T) {
	x := AdapterExecutor{}
	agentDef := config.AgentDef{Name: "fronted_agent", Execution: "fronted", Endpoint: ""}

	_, err := x.Execute(context.Background(), agentDef, "hello", nil)
	if err == nil {
		t.Fatalf("Execute: want error for empty endpoint, got nil")
	}
	if !errors.Is(err, engine.ErrStepConfig) {
		t.Errorf("Execute error = %v, want it to wrap engine.ErrStepConfig", err)
	}
}
