package main

import (
	"strings"
	"testing"
	"time"
)

const goodConfig = `socket: /run/agenthof-spawn/refspawn.sock
spawn_root: /run/agenthof-spawn/children
images:
  refbox-echo: refbox-echo:test
  reader: localhost/refbox-echo-b:test
timeout: 10m
ready_timeout: 60s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 4
refexec:
  command: [refexec]
  image: docker.io/library/busybox:1.36.1
  timeout: 2m
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
`

func TestParseConfigHappyPath(t *testing.T) {
	cfg, err := parseConfig([]byte(goodConfig))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Socket != "/run/agenthof-spawn/refspawn.sock" || cfg.SpawnRoot != "/run/agenthof-spawn/children" ||
		cfg.Images["refbox-echo"] != "refbox-echo:test" || cfg.Images["reader"] != "localhost/refbox-echo-b:test" ||
		cfg.Timeout != 10*time.Minute || cfg.ReadyTimeout != 60*time.Second ||
		cfg.Limits != (limits{Memory: "256m", CPUs: "1", PIDs: 64}) || cfg.MaxCompartments != 4 ||
		len(cfg.Refexec.Command) != 1 || cfg.Refexec.Command[0] != "refexec" || cfg.Refexec.Image != "docker.io/library/busybox:1.36.1" ||
		cfg.Refexec.Timeout != 2*time.Minute || cfg.Refexec.Limits != (limits{Memory: "256m", CPUs: "1", PIDs: 64}) ||
		cfg.Refexec.MaxCompartments != 2 || cfg.Refexec.EnvAllow == nil || len(cfg.Refexec.EnvAllow) != 0 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestParseConfigEveryKeyRequiredAndUnknownRejected(t *testing.T) {
	cases := map[string]string{ // a line to drop (or add) -> the message fragment
		"socket:":               "socket must be an absolute",
		"spawn_root:":           "spawn_root must be an absolute",
		"timeout: 10m":          "timeout is required",
		"ready_timeout:":        "ready_timeout is required",
		"max_compartments: 4":   "max_compartments must be a positive",
		"  command:":            "refexec.command is required",
		"  image:":              "refexec.image is required",
		"  timeout: 2m":         "refexec.timeout is required",
		"  max_compartments: 2": "refexec.max_compartments must be a positive",
		"  env_allow:":          "refexec.env_allow is required",
	}
	for drop, fragment := range cases {
		var kept []string
		for _, l := range strings.Split(goodConfig, "\n") {
			if !strings.HasPrefix(l, drop) {
				kept = append(kept, l)
			}
		}
		_, err := parseConfig([]byte(strings.Join(kept, "\n")))
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Errorf("without %q: err = %v, want %q", drop, err, fragment)
		}
	}
	// images and limits are whole blocks: dropping only the key would leave
	// orphaned indented lines (a YAML error, not the message under test).
	noImages := strings.Replace(goodConfig, "images:\n  refbox-echo: refbox-echo:test\n  reader: localhost/refbox-echo-b:test\n", "", 1)
	if _, err := parseConfig([]byte(noImages)); err == nil || !strings.Contains(err.Error(), "images is required") {
		t.Errorf("without images: err = %v", err)
	}
	noLimits := strings.Replace(goodConfig, "limits:\n  memory: 256m\n  cpus: \"1\"\n  pids: 64\nmax", "max", 1)
	if _, err := parseConfig([]byte(noLimits)); err == nil || !strings.Contains(err.Error(), "limits is required") {
		t.Errorf("without limits: err = %v", err)
	}
	if _, err := parseConfig([]byte(goodConfig + "surprise: 1\n")); err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Errorf("an unknown key must be rejected, got %v", err)
	}
}

func TestParseConfigShapes(t *testing.T) {
	cases := []struct{ name, from, to, fragment string }{
		{"agent name with a slash", "  refbox-echo: refbox-echo:test", "  bad/agent: refbox-echo:test", "images key"},
		{"image with a space", "refbox-echo:test\n  reader", "refbox echo\n  reader", "images value"},
		{"socket under spawn_root", "socket: /run/agenthof-spawn/refspawn.sock", "socket: /run/agenthof-spawn/children/refspawn.sock", "socket must not be under spawn_root"},
		{"sub-second timeout", "timeout: 10m", "timeout: 500ms", "timeout must be a positive duration of at least 1s"},
		{"empty refexec command", "  command: [refexec]", "  command: []", "refexec.command is required"},
		{"refexec image with a space", "docker.io/library/busybox:1.36.1", "busy box", "refexec.image must be an image reference"},
		{"bad env name", "  env_allow: []", "  env_allow: [\"1BAD\"]", "env_allow[0] is not an environment variable name"},
	}
	for _, c := range cases {
		src := strings.Replace(goodConfig, c.from, c.to, 1)
		if src == goodConfig {
			t.Fatalf("%s: the replacement did not apply", c.name)
		}
		if _, err := parseConfig([]byte(src)); err == nil || !strings.Contains(err.Error(), c.fragment) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.fragment)
		}
	}
}

func TestCheckLines(t *testing.T) {
	cfg, err := parseConfig([]byte(goodConfig))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.checkLines(); got != "socket=/run/agenthof-spawn/refspawn.sock\nspawn_root=/run/agenthof-spawn/children\n" {
		t.Fatalf("checkLines = %q", got)
	}
}
