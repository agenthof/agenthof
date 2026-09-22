package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

func TestEchoSucceeds(t *testing.T) {
	res, err := EchoExecutor{}.Execute(context.Background(), Binding{},
		config.AgentDef{Name: "planner"}, "fix the login bug\nmore detail", nil)
	if err != nil || !res.Success {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Artifact != "[planner] fix the login bug" {
		t.Fatalf("artifact: %q", res.Artifact)
	}
}

func TestEchoSyntheticFailure(t *testing.T) {
	res, err := EchoExecutor{}.Execute(context.Background(), Binding{},
		config.AgentDef{Name: "coder"}, "do the thing FAIL:coder", nil)
	if err != nil || res.Success {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(res.Reason, "coder") {
		t.Fatalf("reason: %q", res.Reason)
	}
}
