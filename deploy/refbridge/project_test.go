package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
)

const multiGateway = `tools:
  stdio-tool:
    kind: mcp
    url: unix:///run/agenthof-bridge/stdio-tool.sock
    runtime: refbridge
    credential_source: static_env
    token_env: DEMO_TOOL_TOKEN
    command: ["/stdio-tool", "-credential-env", "DEMO_TOKEN"]
    env_passthrough: ["LANG"]
    egress: ["api.example.com:443"]
  other-secret-tool:
    kind: mcp
    url: https://other.internal.example/mcp
    credential_source: static_env
    token_env: OTHER_SECRET_TOKEN
models:
  fast:
    endpoint: http://localhost:4000
    model: fast
`

var testOps = projectOps{CredentialEnv: "DEMO_TOKEN", MaxSessions: 4, IdleTimeout: "10m", MaxLifetime: "30m", Materialization: matEnvAtSpawn}

func TestProjectMapsGovernedFieldsAndRoundTrips(t *testing.T) {
	out, err := projectSlice([]byte(multiGateway), "stdio-tool", testOps)
	if err != nil {
		t.Fatalf("projectSlice: %v", err)
	}
	cfg, err := parseConfig(out) // the existing strict reader consumes it unchanged
	if err != nil {
		t.Fatalf("parseConfig(slice): %v\n%s", err, out)
	}
	want := bridgeConfig{
		Socket:          "/run/agenthof-bridge/stdio-tool.sock",
		Command:         []string{"/stdio-tool", "-credential-env", "DEMO_TOKEN"},
		CredentialEnv:   "DEMO_TOKEN",
		Materialization: matEnvAtSpawn,
		EnvPassthrough:  []string{"LANG"},
		EgressAllow:     []string{"api.example.com:443"},
		MaxSessions:     4,
		IdleTimeout:     10 * time.Minute,
		MaxLifetime:     30 * time.Minute,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("got %+v\nwant %+v", cfg, want)
	}
}

// The slice must name nothing but the one resource.
func TestProjectExcludesOtherResources(t *testing.T) {
	out, err := projectSlice([]byte(multiGateway), "stdio-tool", testOps)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"other-secret-tool", "OTHER_SECRET_TOKEN", "DEMO_TOOL_TOKEN", "other.internal", "models", "fast", "localhost:4000", "stdio-tool:"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("slice leaks %q:\n%s", leak, out)
		}
	}
}

func TestProjectAbsentListsDefaultToDeny(t *testing.T) {
	gw := "tools:\n  t:\n    runtime: refbridge\n    url: unix:///run/b/t.sock\n    command: [\"/x\"]\n"
	out, err := projectSlice([]byte(gw), "t", testOps)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.EnvPassthrough) != 0 || len(cfg.EgressAllow) != 0 {
		t.Fatalf("want empty passthrough and no egress, got %+v", cfg)
	}
}

func TestProjectRefusals(t *testing.T) {
	cases := map[string]struct{ gw, id, want string }{
		"no command":    {"tools:\n  t:\n    runtime: refbridge\n    url: unix:///r/s\n", "t", "no command"},
		"not refbridge": {"tools:\n  t:\n    url: unix:///r/s\n    command: [\"/x\"]\n", "t", "runtime: refbridge"},
		"unknown id":    {multiGateway, "nope", "not found"},
		"no url":        {"tools:\n  t:\n    runtime: refbridge\n    command: [\"/x\"]\n", "t", "url must be unix://"},
		"http url":      {"tools:\n  t:\n    runtime: refbridge\n    url: http://x/y\n    command: [\"/x\"]\n", "t", "url must be unix://"},
		"relative sock": {"tools:\n  t:\n    runtime: refbridge\n    url: unix://rel.sock\n    command: [\"/x\"]\n", "t", "url must be unix://"},
		"empty id":      {multiGateway, "", "-resource is required"},
		"no tools":      {"models: {}\n", "t", "not found"},
		"bad yaml":      {"tools: [", "t", "gateway"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := projectSlice([]byte(c.gw), c.id, testOps)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestProjectReservedMaterializationNotAccepted(t *testing.T) {
	ops := testOps
	ops.Materialization = matEgressBroker
	_, err := projectSlice([]byte(multiGateway), "stdio-tool", ops)
	if err == nil || !strings.Contains(err.Error(), "egress-broker is reserved and not implemented") {
		t.Fatalf("want reserved-materialization error, got %v", err)
	}
}

// An on-behalf-of resource forbids token_env; it must still project.
func TestProjectWithoutTokenEnv(t *testing.T) {
	gw := "tools:\n  t:\n    runtime: refbridge\n    url: unix:///run/b/t.sock\n    grant_type: token_exchange\n    command: [\"/x\"]\n"
	out, err := projectSlice([]byte(gw), "t", testOps)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig(out)
	if err != nil || cfg.Socket != "/run/b/t.sock" || cfg.CredentialEnv != "DEMO_TOKEN" {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestProjectRequiresCredentialEnv(t *testing.T) {
	ops := testOps
	ops.CredentialEnv = ""
	if _, err := projectSlice([]byte(multiGateway), "stdio-tool", ops); err == nil || !strings.Contains(err.Error(), "credential.env") {
		t.Fatalf("want credential.env error, got %v", err)
	}
}

// The slice shape is strict: an unknown launch-spec field fails closed.
func TestSliceUnknownFieldFailsClosed(t *testing.T) {
	bad := strings.Replace(validYAML, "env_passthrough: []", "env_passthrough: []\nargs_extra: [\"--x\"]", 1)
	if _, err := parseConfig([]byte(bad)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

// A slice lacking a command errors clearly.
func TestSliceWithoutCommandErrors(t *testing.T) {
	noCmd := strings.Replace(validYAML, `command: ["/stdio-tool", "-credential-env", "DEMO_TOKEN"]`+"\n", "", 1)
	_, err := parseConfig([]byte(noCmd))
	if err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("want command error, got %v", err)
	}
}

// The local projection struct must track the governed ToolResource tags.
func TestProjectTagsMatchToolResource(t *testing.T) {
	for _, f := range []struct{ field, tag string }{
		{"Command", "command"},
		{"EnvPassthrough", "env_passthrough"},
		{"Egress", "egress"},
		{"URL", "url"},
		{"Runtime", "runtime"},
	} {
		sf, ok := reflect.TypeOf(config.ToolResource{}).FieldByName(f.field)
		if !ok || strings.Split(sf.Tag.Get("yaml"), ",")[0] != f.tag {
			t.Fatalf("ToolResource.%s tag drifted from %q", f.field, f.tag)
		}
		pf, ok := reflect.TypeOf(projectedResource{}).FieldByName(f.field)
		if !ok || strings.Split(pf.Tag.Get("yaml"), ",")[0] != f.tag {
			t.Fatalf("projectedResource.%s tag != %q", f.field, f.tag)
		}
	}
	if reflect.TypeOf(projectedResource{}).NumField() != 5 {
		t.Fatal("projectedResource must carry exactly the five projected fields")
	}
}

func TestRunProjectWritesSliceFile(t *testing.T) {
	dir := t.TempDir()
	gw := filepath.Join(dir, "gateway.yaml")
	out := filepath.Join(dir, "slice.yaml")
	if err := os.WriteFile(gw, []byte(multiGateway), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runProject(gw, "stdio-tool", out, testOps); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(out) // the existing -config path
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command[0] != "/stdio-tool" {
		t.Fatalf("got %+v", cfg)
	}
	if err := runProject(filepath.Join(dir, "missing.yaml"), "stdio-tool", out, testOps); err == nil {
		t.Fatal("missing gateway.yaml must error")
	}
}
