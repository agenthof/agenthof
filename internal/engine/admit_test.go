package engine

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

func TestAdmitReasonsMatchRunsRefusals(t *testing.T) {
	reg := engCfg()
	cases := []struct {
		name           string
		role, workflow string
		inv            identity.Invoker
		wantReason     string
	}{
		{"unknown role", "nobody", "fix-bug", identity.Static("dev@x"), `role "nobody" is not in the registry`},
		{"unknown workflow", "se", "nope", identity.Static("dev@x"), `workflow "nope" is not in the registry`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := Admit(reg, tc.role, tc.workflow, tc.inv)
			if ok || reason != tc.wantReason {
				t.Fatalf("Admit = (%q, %v), want (%q, false)", reason, ok, tc.wantReason)
			}
			dir := t.TempDir()
			res, _ := Run(context.Background(), reg, tc.role, tc.workflow, "x", tc.inv,
				&fakeExec{fail: map[string]int{}}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
			events, _, err := ReadLog(dir, res.RunID)
			if err != nil || len(events) != 1 {
				t.Fatalf("events=%+v err=%v", events, err)
			}
			if events[0].Reason != reason {
				t.Fatalf("Run ledgered %q, Admit returned %q — they must be the same bytes", events[0].Reason, reason)
			}
		})
	}
	if reason, ok := Admit(reg, "se", "fix-bug", identity.Static("dev@x")); !ok || reason != "" {
		t.Fatalf("an admitted run must be (\"\", true), got (%q, %v)", reason, ok)
	}
}

func TestAdmitGroupRefusalNamesTheAllowedGroups(t *testing.T) {
	reg := gatedCfg(t)
	inv := identity.Invoker{Subject: "x", Issuer: "i", Method: "oidc", Groups: []string{"marketing"}}
	reason, ok := Admit(reg, "finance-role", "fix-bug", inv)
	want := `role "finance-role" requires membership in one of its allowed groups (finance, audit); the invoker's groups don't qualify`
	if ok || reason != want {
		t.Fatalf("Admit = (%q, %v), want (%q, false)", reason, ok, want)
	}
}

func TestRecordRefusedWritesRunsRefusalBytes(t *testing.T) {
	dir := t.TempDir()
	o := &Origin{Via: "api", UserAgent: "ua\x1b[0m"}
	inv := identity.Static("dev@x")
	id, err := RecordRefused(Options{LogDir: dir, Origin: o}, inv, "nobody", "fix-bug", `role "nobody" is not in the registry`)
	if err != nil {
		t.Fatal(err)
	}
	recorded, _, err := ReadLog(dir, id)
	if err != nil || len(recorded) != 1 {
		t.Fatalf("events=%+v err=%v", recorded, err)
	}
	res, _ := Run(context.Background(), engCfg(), "nobody", "fix-bug", "x", inv,
		&fakeExec{fail: map[string]int{}}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Origin: o})
	viaRun, _, err := ReadLog(dir, res.RunID)
	if err != nil || len(viaRun) != 1 {
		t.Fatalf("events=%+v err=%v", viaRun, err)
	}
	a, b := recorded[0], viaRun[0]
	a.Time, b.Time = time.Time{}, time.Time{}
	a.Binding.RunID, b.Binding.RunID = "", ""
	// Binding holds a slice (Invoker.Groups), so it is compared with DeepEqual.
	if a.Type != "run_refused" || a.Origin == nil || *a.Origin != *b.Origin || a.Reason != b.Reason || !reflect.DeepEqual(a.Binding, b.Binding) || a.Prev != b.Prev {
		t.Fatalf("RecordRefused wrote\n%+v\nRun wrote\n%+v\n— they must be the same event", a, b)
	}
	if a.Origin.UserAgent != "ua[0m" {
		t.Fatalf("RecordRefused must sanitize too: %q", a.Origin.UserAgent)
	}
}

func TestRecordRefusedHonoursRunIDAndParent(t *testing.T) {
	dir := t.TempDir()
	parent := &Binding{RunID: "r-parent", Depth: 1}
	id, err := RecordRefused(Options{LogDir: dir, RunID: "r-given02", Parent: parent}, identity.Static("dev@x"), "se", "fix-bug", "why")
	if err != nil || id != "r-given02" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	events, _, _ := ReadLog(dir, id)
	if events[0].Binding.ParentRunID != "r-parent" || events[0].Binding.Depth != 2 || events[0].Origin != nil {
		t.Fatalf("binding=%+v origin=%+v", events[0].Binding, events[0].Origin)
	}
}

// gatedCfg is engCfg plus a role whose allowed_groups are real group names.
func gatedCfg(t *testing.T) *registry.Registry {
	t.Helper()
	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "planner", Model: "fast", Output: "plan", Endpoint: "https://example.test/run", SourceFile: "a"},
		},
		Workflows: []config.WorkflowDef{{Name: "fix-bug", SourceFile: "w", Steps: []config.Step{{Name: "plan", Agent: "planner"}}}},
		Roles: []config.RoleDef{
			{Name: "finance-role", Workflows: []string{"fix-bug"}, AllowedGroups: []string{"finance", "audit"}, SourceFile: "r"},
		},
		Gateway: config.GatewayConfig{Models: map[string]config.ModelRoute{"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"}}},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	return reg
}
