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
const validYAML = `socket: /run/agenthof-exec/refexec.sock
image: docker.io/library/busybox:1.36.1
workspace:
  volume: agenthof-work
  path: /work
timeout: 2m
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
`

func TestParseConfigValid(t *testing.T) {
	cfg, err := parseConfig([]byte(validYAML))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := execConfig{
		Socket: "/run/agenthof-exec/refexec.sock", Image: "docker.io/library/busybox:1.36.1",
		WorkspaceVolume: "agenthof-work", WorkspacePath: "/work", Timeout: 2 * time.Minute,
		Memory: "256m", CPUs: "1", PIDs: 64, MaxCompartments: 2, EnvAllow: []string{},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parseConfig = %+v, want %+v", cfg, want)
	}
	if cfg.EnvAllow == nil {
		t.Fatal("an empty env_allow must be a non-nil empty slice, never nil")
	}
	if got := cfg.checkLines(); got != "socket=/run/agenthof-exec/refexec.sock\nworkspace=agenthof-work:/work\n" {
		t.Fatalf("checkLines = %q", got)
	}
}

func TestParseConfigRejectsOmissions(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(string) string
		wantErr string
	}{
		{"relative socket", func(s string) string { return strings.Replace(s, "socket: /run/", "socket: run/", 1) }, "socket must be an absolute"},
		{"no image", func(s string) string { return strings.Replace(s, "image: docker.io/library/busybox:1.36.1\n", "", 1) }, "image is required"},
		{"image with whitespace", func(s string) string { return strings.Replace(s, "busybox:1.36.1", "busybox:1.36.1 --privileged", 1) }, "image must be an image reference"},
		{"no workspace", func(s string) string {
			return strings.Replace(s, "workspace:\n  volume: agenthof-work\n  path: /work\n", "", 1)
		}, "workspace is required"},
		{"bad volume name", func(s string) string { return strings.Replace(s, "volume: agenthof-work", "volume: ../etc", 1) }, "workspace.volume"},
		{"relative workspace path", func(s string) string { return strings.Replace(s, "path: /work", "path: work", 1) }, "workspace.path must be an absolute"},
		{"no timeout", func(s string) string { return strings.Replace(s, "timeout: 2m\n", "", 1) }, "timeout is required"},
		{"bad timeout", func(s string) string { return strings.Replace(s, "timeout: 2m", "timeout: soon", 1) }, "timeout must be a positive duration"},
		{"sub-second timeout", func(s string) string { return strings.Replace(s, "timeout: 2m", "timeout: 500ms", 1) }, "timeout must be a positive duration"},
		{"no limits", func(s string) string {
			return strings.Replace(s, "limits:\n  memory: 256m\n  cpus: \"1\"\n  pids: 64\n", "", 1)
		}, "limits is required"},
		{"bad memory", func(s string) string { return strings.Replace(s, "memory: 256m", "memory: lots", 1) }, "limits.memory"},
		{"bad cpus", func(s string) string { return strings.Replace(s, `cpus: "1"`, `cpus: "all"`, 1) }, "limits.cpus"},
		{"zero pids", func(s string) string { return strings.Replace(s, "pids: 64", "pids: 0", 1) }, "limits.pids"},
		{"no compartments", func(s string) string { return strings.Replace(s, "compartments:\n  max: 2\n", "", 1) }, "compartments is required"},
		{"zero max", func(s string) string { return strings.Replace(s, "  max: 2", "  max: 0", 1) }, "compartments.max"},
		{"no env_allow", func(s string) string { return strings.Replace(s, "env_allow: []\n", "", 1) }, "env_allow is required"},
		{"null env_allow", func(s string) string { return strings.Replace(s, "env_allow: []\n", "env_allow:\n", 1) }, "env_allow is required"},
		{"bad env name", func(s string) string { return strings.Replace(s, "env_allow: []", `env_allow: ["not a name"]`, 1) }, "env_allow[0] is not an environment variable name"},
		{"unknown key", func(s string) string { return s + "network: host\n" }, "field network not found"},
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
	y := strings.Replace(validYAML, "env_allow: []", `env_allow: ["PATH", "TOKEN=abc123"]`, 1)
	_, err := parseConfig([]byte(y))
	if err == nil {
		t.Fatal("expected the malformed entry to be rejected")
	}
	if !strings.Contains(err.Error(), "env_allow[1]") || strings.Contains(err.Error(), "abc123") {
		t.Fatalf("error %q must name the position and never echo the value", err.Error())
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "refexec.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Image != "docker.io/library/busybox:1.36.1" || cfg.MaxCompartments != 2 {
		t.Fatalf("loadConfig = %+v", cfg)
	}
	missing := filepath.Join(dir, "absent.yaml")
	if _, err := loadConfig(missing); err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "refexec config") {
		t.Fatalf("loadConfig of a missing file: err = %v", err)
	}
}
