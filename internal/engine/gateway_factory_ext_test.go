package engine_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// TestConcurrentRunsIsolateRealGateways is the load-bearing isolation test.
// The leader's run completes (and stops its gateway) before the follower
// places its model call. With the old shared *Gateway this could fail two
// distinct ways depending on which run's Start stored its state last:
//
//   - If the follower's srv was stored last, the leader's Stop() closes the
//     follower's listener out from under it, so the follower's model call
//     gets connection-refused and its run status is not "succeeded".
//   - If the leader's srv was stored last, the leader's Stop() sets the
//     shared closing flag, so the follower's guardedAppend silently drops
//     its ledger event even though the HTTP call itself returns 200 — the
//     follower's ledger ends up with no model_call.
//
// So the load-bearing assertions are "each run status == succeeded" and
// "each run's ledger has a model_call"; the distinct-URL/token and
// no-cross-bleed checks below pass even under the shared-instance bug, since
// the listener, token, and bind are created fresh on every Start() call. A
// per-run factory avoids both failure modes.
func TestConcurrentRunsIsolateRealGateways(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("MODEL_KEY", "provider-secret")

	cfg := config.Config{
		Agents: []config.AgentDef{{
			Name: "fe", Output: "out", SourceFile: "a", Execution: "fronted",
			Endpoint: "https://agent.example", Model: "fast",
		}},
		Workflows: []config.WorkflowDef{{
			Name: "wf", SourceFile: "w",
			Steps: []config.Step{{Name: "step1", Agent: "fe"}},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
		Gateway: config.GatewayConfig{Models: map[string]config.ModelRoute{
			"fast": {Endpoint: upstream.URL, Model: "gpt-test", APIKeyEnv: "MODEL_KEY"},
		}},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}

	dir := t.TempDir()
	keyRoot := t.TempDir()
	b := broker.Dispatch{}
	opts := engine.Options{
		LogDir: dir, ArtifactDir: dir + "/a",
		NewGateway: func() engine.ToolProxy {
			return rungateway.New(cfg.Gateway, keyRoot, b, nil)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var idMu sync.Mutex
	var leaderID string
	followerEntered := make(chan struct{})
	leaderDone := make(chan struct{})
	var closeLeader sync.Once

	var coordMu sync.Mutex
	var coords []coord

	exec := &staggeredModelCall{
		leaderID:        &leaderID,
		idMu:            &idMu,
		followerEntered: followerEntered,
		leaderDone:      leaderDone,
		coordMu:         &coordMu,
		coords:          &coords,
	}

	type outcome struct {
		id, status string
		err        error
	}
	out := make([]outcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, status, err := engine.Run(ctx, reg, "se", "wf", "x", identity.Static("dev@x"), exec, opts)
			idMu.Lock()
			lid := leaderID
			idMu.Unlock()
			if id == lid {
				closeLeader.Do(func() { close(leaderDone) })
			}
			out[i] = outcome{id, status, err}
		}(i)
	}
	wg.Wait()

	for i, o := range out {
		if o.err != nil || o.status != "succeeded" {
			t.Fatalf("run %d: status=%q err=%v", i, o.status, o.err)
		}
	}
	if out[0].id == out[1].id {
		t.Fatalf("runs share id %q", out[0].id)
	}
	coordMu.Lock()
	defer coordMu.Unlock()
	if len(coords) != 2 {
		t.Fatalf("model calls = %d, want 2", len(coords))
	}
	if coords[0].url == coords[1].url || coords[0].token == coords[1].token {
		t.Fatalf("runs shared a listener: %+v", coords)
	}
	for _, id := range []string{out[0].id, out[1].id} {
		events, _, err := engine.ReadLog(dir, id)
		if err != nil {
			t.Fatalf("ledger %s: %v", id, err)
		}
		sawModel := false
		for _, e := range events {
			if e.Binding.RunID != id {
				t.Fatalf("ledger %s contains run %s (%s)", id, e.Binding.RunID, e.Type)
			}
			if e.Type == "model_call" {
				sawModel = true
				if e.Status != "succeeded" {
					t.Fatalf("model_call on %s: %+v", id, e)
				}
			}
		}
		if !sawModel {
			t.Fatalf("ledger %s has no model_call", id)
		}
	}
}

// staggeredModelCall lets the first run stop before the second run calls the model.
type staggeredModelCall struct {
	leaderID        *string
	idMu            *sync.Mutex
	followerEntered chan struct{}
	leaderDone      chan struct{}
	coordMu         *sync.Mutex
	coords          *[]coord
}

type coord struct{ run, url, token string }

func (s *staggeredModelCall) Execute(ctx context.Context, bind engine.Binding, _ config.AgentDef, _ string, _ map[string]string) (engine.StepResult, error) {
	url, token, ok := engine.ProxyCoordinatesFrom(ctx)
	if !ok {
		return engine.StepResult{Success: false, Reason: "no proxy coordinates"}, nil
	}
	s.coordMu.Lock()
	*s.coords = append(*s.coords, coord{bind.RunID, url, token})
	s.coordMu.Unlock()

	s.idMu.Lock()
	leader := *s.leaderID == ""
	if leader {
		*s.leaderID = bind.RunID
	}
	s.idMu.Unlock()

	fail := func(reason string) (engine.StepResult, error) {
		return engine.StepResult{Success: false, Reason: reason}, nil
	}
	if leader {
		select {
		case <-s.followerEntered:
		case <-ctx.Done():
			return fail("leader timed out waiting for the other run")
		}
		if err := postModel(ctx, url, token); err != nil {
			return fail(err.Error())
		}
		return engine.StepResult{Success: true, Artifact: "ok"}, nil
	}
	close(s.followerEntered)
	select {
	case <-s.leaderDone:
	case <-ctx.Done():
		return fail("follower timed out waiting for the other run to stop")
	}
	if err := postModel(ctx, url, token); err != nil {
		return fail(err.Error())
	}
	return engine.StepResult{Success: true, Artifact: "ok"}, nil
}

func postModel(ctx context.Context, url, token string) error {
	body := `{"model":"fast","messages":[{"role":"user","content":"ping"}]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return errStatus(resp.StatusCode, string(b))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

type statusErr struct {
	code int
	body string
}

func (e statusErr) Error() string {
	return "model proxy status " + http.StatusText(e.code) + ": " + e.body
}

func errStatus(code int, body string) error { return statusErr{code, body} }
