package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// validYAML is the complete shape; every key is required (config is law).
const validYAML = `socket: /run/agenthof-bridge/stdio-tool.sock
command: ["/stdio-tool", "-credential-env", "DEMO_TOKEN"]
credential:
  env: DEMO_TOKEN
  materialization: env-at-spawn
env_passthrough: []
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
`

func TestParseConfigValid(t *testing.T) {
	cfg, err := parseConfig([]byte(validYAML))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := bridgeConfig{
		Socket:          "/run/agenthof-bridge/stdio-tool.sock",
		Command:         []string{"/stdio-tool", "-credential-env", "DEMO_TOKEN"},
		CredentialEnv:   "DEMO_TOKEN",
		Materialization: matEnvAtSpawn,
		EnvPassthrough:  []string{},
		EgressAllow:     []string{},
		MaxSessions:     4,
		IdleTimeout:     10 * time.Minute,
		MaxLifetime:     30 * time.Minute,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parseConfig = %+v, want %+v", cfg, want)
	}
	if cfg.EnvPassthrough == nil || cfg.EgressAllow == nil {
		t.Fatal("empty allowlists must be non-nil empty slices, never nil")
	}
	if got := cfg.egressLine(); got != "egress=none" {
		t.Fatalf("egressLine = %q, want egress=none", got)
	}
}

func TestParseConfigRejectsOmissions(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(string) string
		wantErr string
	}{
		{"no materialization", func(s string) string { return strings.Replace(s, "  materialization: env-at-spawn\n", "", 1) }, "credential.materialization"},
		{"no credential env", func(s string) string { return strings.Replace(s, "  env: DEMO_TOKEN\n", "", 1) }, "credential.env"},
		{"no credential block", func(s string) string {
			return strings.Replace(s, "credential:\n  env: DEMO_TOKEN\n  materialization: env-at-spawn\n", "", 1)
		}, "credential is required"},
		{"no env_passthrough", func(s string) string { return strings.Replace(s, "env_passthrough: []\n", "", 1) }, "env_passthrough is required"},
		{"null env_passthrough", func(s string) string { return strings.Replace(s, "env_passthrough: []\n", "env_passthrough:\n", 1) }, "env_passthrough is required"},
		{"no egress", func(s string) string { return strings.Replace(s, "egress:\n  allow: []\n", "", 1) }, "egress.allow is required"},
		{"null egress allow", func(s string) string { return strings.Replace(s, "  allow: []\n", "  allow:\n", 1) }, "egress.allow is required"},
		{"no sessions", func(s string) string {
			return strings.Replace(s, "sessions:\n  max: 4\n  idle_timeout: 10m\n  max_lifetime: 30m\n", "", 1)
		}, "sessions is required"},
		{"zero max", func(s string) string { return strings.Replace(s, "  max: 4\n", "  max: 0\n", 1) }, "sessions.max"},
		{"no idle_timeout", func(s string) string { return strings.Replace(s, "  idle_timeout: 10m\n", "", 1) }, "sessions.idle_timeout"},
		{"bad max_lifetime", func(s string) string { return strings.Replace(s, "  max_lifetime: 30m\n", "  max_lifetime: soon\n", 1) }, "sessions.max_lifetime"},
		{"relative socket", func(s string) string { return strings.Replace(s, "socket: /run/", "socket: run/", 1) }, "socket must be an absolute"},
		{"no command", func(s string) string {
			return strings.Replace(s, `command: ["/stdio-tool", "-credential-env", "DEMO_TOKEN"]`, "command: []", 1)
		}, "command must name"},
		{"egress-broker reserved", func(s string) string { return strings.Replace(s, "env-at-spawn", "egress-broker", 1) }, "reserved"},
		{"unknown materialization", func(s string) string { return strings.Replace(s, "env-at-spawn", "inherit", 1) }, `"inherit"`},
		{"bad env name", func(s string) string {
			return strings.Replace(s, "env_passthrough: []", `env_passthrough: ["not a name"]`, 1)
		}, "not an environment variable name"},
		{"credential in passthrough", func(s string) string {
			return strings.Replace(s, "env_passthrough: []", `env_passthrough: ["DEMO_TOKEN"]`, 1)
		}, "must not also be in env_passthrough"},
		{"bad egress host", func(s string) string {
			return strings.Replace(s, "  allow: []", `  allow: ["https://api.example.com/v1"]`, 1)
		}, "must be a host or host:port"},
		{"unknown key", func(s string) string { return s + "network: host\n" }, "field network not found"},
		{"egress entry with comma", func(s string) string {
			return strings.Replace(s, "  allow: []", `  allow: ["a.example.com,b.example.com"]`, 1)
		}, "egress.allow[0] must be a host or host:port"},
		{"egress credential in url", func(s string) string {
			return strings.Replace(s, "  allow: []", `  allow: ["user:tok@api.example.com"]`, 1)
		}, "egress.allow[0] must be a host or host:port"},
		{"egress empty host", func(s string) string { return strings.Replace(s, "  allow: []", `  allow: [":443"]`, 1) }, "egress.allow[0]"},
		{"egress extra colon", func(s string) string { return strings.Replace(s, "  allow: []", `  allow: ["host:443:x"]`, 1) }, "egress.allow[0]"},
		{"egress port zero", func(s string) string { return strings.Replace(s, "  allow: []", `  allow: ["host:0"]`, 1) }, "egress.allow[0]"},
		{"egress port too large", func(s string) string { return strings.Replace(s, "  allow: []", `  allow: ["host:65536"]`, 1) }, "egress.allow[0]"},
		{"egress port not numeric", func(s string) string { return strings.Replace(s, "  allow: []", `  allow: ["host:https"]`, 1) }, "egress.allow[0]"},
		{"env_passthrough scalar inherit", func(s string) string {
			return strings.Replace(s, "env_passthrough: []", "env_passthrough: inherit", 1)
		}, "refbridge config"},
		{"env_passthrough inherit entry", func(s string) string {
			return strings.Replace(s, "env_passthrough: []", `env_passthrough: ["inherit"]`, 1)
		}, `env_passthrough takes an explicit list; "inherit" is not supported`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig([]byte(tc.mut(validYAML)))
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestParseConfigErrorsNeverEchoEntries(t *testing.T) {
	y := strings.Replace(validYAML, "env_passthrough: []", `env_passthrough: ["PATH", "TOKEN=abc123"]`, 1)
	y = strings.Replace(y, "  allow: []", `  allow: ["https://user:s3cr3t@api.example.com"]`, 1)
	_, err := parseConfig([]byte(y))
	if err == nil {
		t.Fatal("expected malformed entries to be rejected")
	}
	for _, want := range []string{"env_passthrough[1]", "egress.allow[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name position %s", err.Error(), want)
		}
	}
	for _, secret := range []string{"abc123", "s3cr3t"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q echoes the rejected value", err.Error())
		}
	}
}

func TestParseConfigAcceptsHostPortShapes(t *testing.T) {
	y := strings.Replace(validYAML, "  allow: []", `  allow: ["api.example.com", "api.example.com:443", "[2001:db8::1]:8443"]`, 1)
	cfg, err := parseConfig([]byte(y))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if got := cfg.egressLine(); got != "egress=api.example.com,api.example.com:443,[2001:db8::1]:8443" {
		t.Fatalf("egressLine = %q", got)
	}
}

func TestParseConfigRotationAndEgressList(t *testing.T) {
	y := strings.Replace(validYAML, "env-at-spawn", "respawn-on-rotation", 1)
	y = strings.Replace(y, "  allow: []", `  allow: ["api.example.com:443", "registry.example.com"]`, 1)
	y = strings.Replace(y, "env_passthrough: []", `env_passthrough: ["PATH", "HOME"]`, 1)
	cfg, err := parseConfig([]byte(y))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.Materialization != matRespawnOnRotation {
		t.Fatalf("Materialization = %q", cfg.Materialization)
	}
	if !reflect.DeepEqual(cfg.EnvPassthrough, []string{"PATH", "HOME"}) {
		t.Fatalf("EnvPassthrough = %v", cfg.EnvPassthrough)
	}
	if got := cfg.egressLine(); got != "egress=api.example.com:443,registry.example.com" {
		t.Fatalf("egressLine = %q", got)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "refbridge.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CredentialEnv != "DEMO_TOKEN" || cfg.MaxSessions != 4 {
		t.Fatalf("loadConfig = %+v", cfg)
	}

	missing := filepath.Join(dir, "absent.yaml")
	_, err = loadConfig(missing)
	if err == nil {
		t.Fatal("loadConfig of a missing file: expected an error")
	}
	if !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "refbridge config") {
		t.Fatalf("error %q does not name the path and refbridge config", err.Error())
	}
}
