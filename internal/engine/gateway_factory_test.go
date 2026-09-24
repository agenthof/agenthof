package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/registry"
)

// spyGateway records which run started it. One instance per factory call.
type spyGateway struct {
	mu      sync.Mutex
	lastRun string
}

func (s *spyGateway) Start(bind Binding, _ config.AgentDef, _ func(Event)) (string, string, error) {
	s.mu.Lock()
	s.lastRun = bind.RunID
	s.mu.Unlock()
	return "http://127.0.0.1:9/", "tok", nil
}

func (s *spyGateway) Stop() {}

func (s *spyGateway) runs() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRun
}

func frontedReg() *registry.Registry {
	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "fe", Output: "out", SourceFile: "a", Execution: "fronted", Endpoint: "https://x"},
		},
		Workflows: []config.WorkflowDef{{
			Name: "wf", SourceFile: "w",
			Steps: []config.Step{{Name: "step1", Agent: "fe"}},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		panic(errs)
	}
	return reg
}

func TestRunUsesAFreshGatewayPerRun(t *testing.T) {
	dir := t.TempDir()
	reg := frontedReg()
	var mu sync.Mutex
	var made []*spyGateway
	opts := Options{
		LogDir: dir, ArtifactDir: dir + "/a",
		NewGateway: func() ToolProxy {
			s := &spyGateway{}
			mu.Lock()
			made = append(made, s)
			mu.Unlock()
			return s
		},
	}
	var wg sync.WaitGroup
	ids := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, status, err := Run(context.Background(), reg, "se", "wf", "x", staticInvoker(), &coordExec{}, opts)
			if err != nil || status != "succeeded" {
				t.Errorf("run %d: status=%q err=%v", i, status, err)
				return
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(made) != 2 {
		t.Fatalf("factory calls = %d, want 2 (one per run)", len(made))
	}
	run0 := made[0].runs()
	run1 := made[1].runs()
	if run0 == "" || run1 == "" || run0 == run1 {
		t.Fatalf("gateways saw runs %q and %q, want two distinct run ids", run0, run1)
	}
	if ids[0] == ids[1] {
		t.Fatalf("runs share id %q", ids[0])
	}
}

func TestRunNilFactoryRunsWithoutGateway(t *testing.T) {
	dir := t.TempDir()
	ce := &coordExec{}
	_, status, err := Run(context.Background(), frontedReg(), "se", "wf", "x",
		staticInvoker(), ce, Options{LogDir: dir, ArtifactDir: dir + "/a"})
	if err != nil || status != "succeeded" {
		t.Fatalf("run: status=%q err=%v", status, err)
	}
	if ce.ok {
		t.Fatal("nil factory must not hand the step proxy coordinates")
	}
}
