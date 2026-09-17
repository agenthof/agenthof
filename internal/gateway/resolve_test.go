package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

func testConfig() config.GatewayConfig {
	cfg := config.GatewayConfig{
		Models: map[string]config.ModelRoute{
			"fast": {
				Endpoint:  "https://gw.example.com/fast",
				Model:     "gpt-fast",
				APIKeyEnv: "FAST_API_KEY",
			},
		},
	}
	cfg.Defaults.Model = "fast"
	return cfg
}

func TestResolveKnownLogical(t *testing.T) {
	cfg := testConfig()
	t.Setenv("FAST_API_KEY", "env-key")

	route, err := Resolve(cfg, "fast", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route.Endpoint != "https://gw.example.com/fast" {
		t.Fatalf("endpoint = %q", route.Endpoint)
	}
	if route.Model != "gpt-fast" {
		t.Fatalf("model = %q", route.Model)
	}
	if route.APIKey != "env-key" {
		t.Fatalf("apiKey = %q", route.APIKey)
	}
}

func TestResolveEmptyLogicalUsesDefault(t *testing.T) {
	cfg := testConfig()
	t.Setenv("FAST_API_KEY", "env-key")

	route, err := Resolve(cfg, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route.Model != "gpt-fast" {
		t.Fatalf("model = %q, want default route's model", route.Model)
	}
}

func TestResolveUnknownLogicalErrors(t *testing.T) {
	cfg := testConfig()

	_, err := Resolve(cfg, "nonexistent", "")
	if err == nil {
		t.Fatal("expected error for unknown logical model")
	}
	want := `model "nonexistent" has no gateway route`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestResolveRoleKeyOverridesEnv(t *testing.T) {
	cfg := testConfig()
	t.Setenv("FAST_API_KEY", "env-key")

	route, err := Resolve(cfg, "fast", "role-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route.APIKey != "role-key" {
		t.Fatalf("apiKey = %q, want role-key to win over env", route.APIKey)
	}
}

func TestResolveEnvFallback(t *testing.T) {
	cfg := testConfig()
	t.Setenv("FAST_API_KEY", "env-key")

	route, err := Resolve(cfg, "fast", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route.APIKey != "env-key" {
		t.Fatalf("apiKey = %q, want env fallback", route.APIKey)
	}
}

func TestResolveMissingBothErrors(t *testing.T) {
	cfg := testConfig()
	t.Setenv("FAST_API_KEY", "")

	_, err := Resolve(cfg, "fast", "")
	if err == nil {
		t.Fatal("expected error when neither role key nor env var is set")
	}
	want := `gateway route "fast": environment variable FAST_API_KEY is not set and no role key is provisioned`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestRoleKeyPath(t *testing.T) {
	got := RoleKeyPath("/root", "coder")
	want := filepath.Join("/root", ".agenthof", "keys", "coder.key")
	if got != want {
		t.Fatalf("RoleKeyPath = %q, want %q", got, want)
	}
}

func TestLoadRoleKeyTrimsContent(t *testing.T) {
	root := t.TempDir()
	path := RoleKeyPath(root, "coder")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("sk-abc\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := LoadRoleKey(root, "coder")
	if got != "sk-abc" {
		t.Fatalf("LoadRoleKey = %q, want %q", got, "sk-abc")
	}
}

func TestLoadRoleKeyMissingFile(t *testing.T) {
	root := t.TempDir()
	got := LoadRoleKey(root, "nobody")
	if got != "" {
		t.Fatalf("LoadRoleKey = %q, want empty string for missing file", got)
	}
}
