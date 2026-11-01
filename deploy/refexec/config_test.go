package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/confiner/confinertest"
)

// validYAML is the complete shape; every key is required (config is law).
const validYAML = `confiner: podman
socket: /run/agenthof-exec/refexec.sock
image: docker.io/library/busybox:1.36.1
workspace:
  store: agenthof-work
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
		Socket: "/run/agenthof-exec/refexec.sock", Confiner: "podman", Store: "agenthof-work",
		Keys:    confiner.Keys{Image: "docker.io/library/busybox:1.36.1", WorkspacePath: "/work"},
		Limits:  confiner.Limits{Memory: "256m", CPUs: "1", PIDs: 64},
		Timeout: 2 * time.Minute, MaxCompartments: 2, EnvAllow: []string{},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parseConfig = %+v, want %+v", cfg, want)
	}
	if cfg.EnvAllow == nil {
		t.Fatal("an empty env_allow must be a non-nil empty slice, never nil")
	}
}

// The confiner key is optional, and a Seatbelt-shaped config has no image and
// no workspace.path. parseConfig decodes every backend key as written; which of
// them the selected backend consumes is the factory's decision.
func TestParseConfigOptionalConfinerAndBackendKeysDecode(t *testing.T) {
	noConfiner := strings.Replace(validYAML, "confiner: podman\n", "", 1)
	cfg, err := parseConfig([]byte(noConfiner))
	if err != nil || cfg.Confiner != "" || cfg.Store != "agenthof-work" {
		t.Fatalf("no confiner line: %+v, %v", cfg, err)
	}

	const seatbeltYAML = `confiner: seatbelt
socket: /private/var/run/refexec/refexec.sock
workspace:
  store: agenthof-work
store_root: /private/var/agenthof/stores
pid_dir: /private/var/agenthof/pids
deny_read: [/x]
shared_host_scratch: true
timeout: 2m
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
`
	cfg, err = parseConfig([]byte(seatbeltYAML))
	if err != nil {
		t.Fatalf("seatbelt-shaped config: %v", err)
	}
	wantKeys := confiner.Keys{
		StoreRoot: "/private/var/agenthof/stores", PIDDir: "/private/var/agenthof/pids",
		DenyRead: []string{"/x"}, SharedHostScratch: true,
	}
	if cfg.Confiner != confiner.TierSeatbelt || !reflect.DeepEqual(cfg.Keys, wantKeys) {
		t.Fatalf("seatbelt-shaped config = %+v, want Keys %+v", cfg, wantKeys)
	}
	// No tier branching: a podman config that also sets a Seatbelt key parses;
	// the factory refuses it later (TestSelectConfinerRejectsUnconsumedKeysAtLoad).
	if _, err = parseConfig([]byte(validYAML + "pid_dir: /p\n")); err != nil {
		t.Fatalf("parseConfig must not branch on the tier: %v", err)
	}
}

func TestParseConfigRejects(t *testing.T) {
	longSock := "/" + strings.Repeat("s", 104) // 105 bytes
	cases := []struct {
		name    string
		goos    string
		mut     func(string) string
		wantErr string
	}{
		{"confiner not a token", "linux", func(s string) string { return strings.Replace(s, "confiner: podman", "confiner: Podman", 1) }, "confiner must be a lowercase backend name"},
		{"store traversal", "linux", func(s string) string { return strings.Replace(s, "store: agenthof-work", "store: ../etc", 1) }, "workspace.store"},
		{"store is the scratch dir", "linux", func(s string) string { return strings.Replace(s, "store: agenthof-work", "store: .scratch", 1) }, "workspace.store"},
		// The startup Reap sweeps every compartment AND store under reapPrefix
		// (podman volumes, Seatbelt store directories); a store named into that
		// prefix would be deleted on every restart.
		{"store under the reap prefix", "linux", func(s string) string { return strings.Replace(s, "store: agenthof-work", "store: refexec-foo", 1) }, `workspace.store must not start with "refexec-"`},
		{"store under the reap prefix on darwin", "darwin", func(s string) string { return strings.Replace(s, "store: agenthof-work", "store: refexec-foo", 1) }, `workspace.store must not start with "refexec-"`},
		{"no store", "linux", func(s string) string { return strings.Replace(s, "  store: agenthof-work\n", "", 1) }, "workspace.store"},
		{"retired volume key", "linux", func(s string) string { return strings.Replace(s, "store: agenthof-work", "volume: agenthof-work", 1) }, "field volume not found"},
		{"socket too long on darwin", "darwin", func(s string) string {
			return strings.Replace(s, "/run/agenthof-exec/refexec.sock", longSock, 1)
		}, "unix socket path too long"},
		{"store_root too long on darwin", "darwin", func(s string) string {
			return s + "store_root: /" + strings.Repeat("r", 70) + "\n"
		}, "unix socket path too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigOn([]byte(tc.mut(validYAML)), tc.goos)
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
	// The same 105-byte socket fits where the limit is 108.
	if _, err := parseConfigOn([]byte(strings.Replace(validYAML, "/run/agenthof-exec/refexec.sock", longSock, 1)), "linux"); err != nil {
		t.Fatalf("a 105-byte socket on linux: %v", err)
	}
	// The reap-prefix error names the prefix, never the rejected store.
	_, err := parseConfig([]byte(strings.Replace(validYAML, "store: agenthof-work", "store: refexec-foo", 1)))
	if err == nil || strings.Contains(err.Error(), "refexec-foo") {
		t.Fatalf("error %v must not echo the rejected store name", err)
	}
}

// Stores off the reap prefix parse: the fixture's agenthof-work, and the store
// refspawn renders for a child refexec (agenthof-spawn-<id>-work, from its own
// agenthof-spawn- prefix), which the guard must never refuse. A name that merely
// contains "refexec-" is fine too; only the prefix is reserved.
func TestParseConfigAcceptsStoresOffReapPrefix(t *testing.T) {
	for _, store := range []string{"agenthof-work", "agenthof-spawn-r-1-work", "my-refexec-work", "refexec"} {
		t.Run(store, func(t *testing.T) {
			cfg, err := parseConfig([]byte(strings.Replace(validYAML, "store: agenthof-work", "store: "+store, 1)))
			if err != nil || cfg.Store != store {
				t.Fatalf("store %q: cfg.Store=%q, err=%v", store, cfg.Store, err)
			}
		})
	}
}

func TestCheckLinesPerBackend(t *testing.T) {
	cfg := execConfig{Socket: "/s/refexec.sock", Store: "agenthof-work", Keys: confiner.Keys{WorkspacePath: "/work"}}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The branch is on Tier(), never on how the Confiner was built: the stub's
	// fake-argv podman prints the podman form.
	fakeArgv := confiner.NewPodman(confiner.PodmanConfig{Argv: []string{exe, fakePodmanFlag}, GuestWorkspace: "/work"})
	for _, tc := range []struct {
		name string
		c    confiner.Confiner
		want string
	}{
		{"fake-argv podman", fakeArgv, "socket=/s/refexec.sock\nworkspace=agenthof-work:/work\n"},
		{"podman tier whatever StorePath says", &confinertest.Fake{TierName: "podman", Root: "/x"}, "socket=/s/refexec.sock\nworkspace=agenthof-work:/x/agenthof-work\n"},
		{"seatbelt", &confinertest.Fake{TierName: "seatbelt", Root: "/private/var/s"}, "socket=/s/refexec.sock\nworkspace=agenthof-work\nstore_path=/private/var/s/agenthof-work\n"},
		{"any future non-podman tier", &confinertest.Fake{TierName: "zz-future", Root: "/r"}, "socket=/s/refexec.sock\nworkspace=agenthof-work\nstore_path=/r/agenthof-work\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkLines(cfg, tc.c); got != tc.want {
				t.Fatalf("checkLines = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseConfigRejectsOmissions(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(string) string
		wantErr string
	}{
		{"relative socket", func(s string) string { return strings.Replace(s, "socket: /run/", "socket: run/", 1) }, "socket must be an absolute"},
		{"no workspace", func(s string) string {
			return strings.Replace(s, "workspace:\n  store: agenthof-work\n  path: /work\n", "", 1)
		}, "workspace is required"},
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
	if cfg.Keys.Image != "docker.io/library/busybox:1.36.1" || cfg.MaxCompartments != 2 {
		t.Fatalf("loadConfig = %+v", cfg)
	}
	missing := filepath.Join(dir, "absent.yaml")
	if _, err := loadConfig(missing); err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "refexec config") {
		t.Fatalf("loadConfig of a missing file: err = %v", err)
	}
}
