package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

const goodConfig = `confiner: podman
socket: /run/agenthof-spawn/refspawn.sock
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
	// Every backend key is optional here: which of them the selected confiner
	// consumes is the factory's decision, so a config without refexec.image
	// still parses.
	if cfg, err := parseConfig([]byte(withoutExecImage(t, goodConfig))); err != nil || cfg.Refexec.Image != "" || cfg.Keys.Image != "" {
		t.Errorf("a config without refexec.image must parse with an empty image: refexec=%+v err=%v", cfg.Refexec, err)
	}
	if _, err := parseConfig([]byte(goodConfig + "surprise: 1\n")); err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Errorf("an unknown key must be rejected, got %v", err)
	}
}

func TestParseConfigShapes(t *testing.T) {
	cases := []struct{ name, from, to, fragment string }{
		{"agent name with a slash", "  refbox-echo: refbox-echo:test", "  bad/agent: refbox-echo:test", "images key"},
		{"empty image value", "refbox-echo:test\n  reader", "\"\"\n  reader", "images value"},
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

// withoutExecImage drops the refexec.image line: the Seatbelt shape.
func withoutExecImage(t *testing.T, src string) string {
	t.Helper()
	out := strings.Replace(src, "  image: docker.io/library/busybox:1.36.1\n", "", 1)
	if out == src {
		t.Fatal("the refexec.image line was not found")
	}
	return out
}

func TestParseConfigDecodesConfinerAndSeatbeltKeys(t *testing.T) {
	podman, err := parseConfig([]byte(goodConfig))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wantPodman := confiner.Keys{Image: "docker.io/library/busybox:1.36.1"}
	if podman.Confiner != confiner.TierPodman || !reflect.DeepEqual(podman.Keys, wantPodman) {
		t.Fatalf("podman: Confiner %q Keys %+v, want podman and %+v", podman.Confiner, podman.Keys, wantPodman)
	}

	// Seatbelt-shaped: no refexec.image, the Seatbelt keys at the top level.
	seatbelt := strings.Replace(goodConfig, "confiner: podman\n",
		"confiner: seatbelt\nstore_root: /var/agenthof/stores\npid_dir: /var/agenthof/pids\ndeny_read: [/home/op/secrets, /etc/agenthof]\nshared_host_scratch: true\n", 1)
	sb, err := parseConfig([]byte(withoutExecImage(t, seatbelt)))
	if err != nil {
		t.Fatalf("parse seatbelt: %v", err)
	}
	wantSB := confiner.Keys{StoreRoot: "/var/agenthof/stores", PIDDir: "/var/agenthof/pids",
		DenyRead: []string{"/home/op/secrets", "/etc/agenthof"}, SharedHostScratch: true}
	if sb.Confiner != confiner.TierSeatbelt || !reflect.DeepEqual(sb.Keys, wantSB) {
		t.Fatalf("seatbelt: Confiner %q Keys %+v, want seatbelt and %+v", sb.Confiner, sb.Keys, wantSB)
	}

	// Omitted: the OS default is the factory's call, so parsing keeps "" and no keys.
	omitted, err := parseConfig([]byte(withoutExecImage(t, strings.Replace(goodConfig, "confiner: podman\n", "", 1))))
	if err != nil || omitted.Confiner != "" || !reflect.DeepEqual(omitted.Keys, confiner.Keys{}) {
		t.Fatalf("omitted: Confiner %q Keys %+v err %v", omitted.Confiner, omitted.Keys, err)
	}
}

// The two socket names the supervisor derives under <spawn_root>/<run id>/
// (a gateway-minted run id is 18 chars) are <agent>.sock and
// gw-<run id>-<16 hex>.sock (43 chars); whichever is longer must bind.
func TestParseConfigSunPath(t *testing.T) {
	build := func(rootLen int, agent string) string {
		root := "/" + strings.Repeat("s", rootLen-1)
		src := strings.Replace(goodConfig, "spawn_root: /run/agenthof-spawn/children", "spawn_root: "+root, 1)
		src = strings.Replace(src, "  refbox-echo: refbox-echo:test", "  "+agent+": refbox-echo:test", 1)
		if src == goodConfig {
			t.Fatal("the replacement did not apply")
		}
		return src
	}
	short := "refbox-echo" // 11 chars: the gateway's socket name (43) is the longer one
	long := strings.Repeat("a", 50)
	cases := []struct {
		name     string
		rootLen  int
		agent    string
		goos     string
		wantFail bool
	}{
		{"darwin, gateway name, 40-char root binds", 40, short, "darwin", false},
		{"darwin, gateway name, 41-char root does not", 41, short, "darwin", true},
		{"darwin, 50-char agent, 28-char root binds", 28, long, "darwin", false},
		{"darwin, 50-char agent, 29-char root does not", 29, long, "darwin", true},
		{"linux limit is 108: a 41-char root binds", 41, short, "linux", false},
		{"linux, 45-char root does not", 45, short, "linux", true},
	}
	for _, c := range cases {
		_, err := parseConfigOn([]byte(build(c.rootLen, c.agent)), c.goos)
		switch {
		case c.wantFail && (err == nil || !strings.Contains(err.Error(), "unix socket path too long")):
			t.Errorf("%s: err = %v, want a path-too-long refusal", c.name, err)
		case !c.wantFail && err != nil:
			t.Errorf("%s: err = %v, want it to parse", c.name, err)
		}
	}

	// The supervisor's own socket is checked too.
	longSock := strings.Replace(goodConfig, "socket: /run/agenthof-spawn/refspawn.sock", "socket: /"+strings.Repeat("x", 110)+"/s.sock", 1)
	if _, err := parseConfigOn([]byte(longSock), "darwin"); err == nil || !strings.Contains(err.Error(), "unix socket path too long") {
		t.Errorf("long socket: err = %v", err)
	}
}
