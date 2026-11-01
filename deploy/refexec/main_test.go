package main

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/confiner/confinertest"
)

// A config that names the seatbelt backend but sets podman's image is refused
// when the confiner is selected, before anything starts, naming the key.
func TestSelectConfinerRejectsUnconsumedKeysAtLoad(t *testing.T) {
	const y = `confiner: seatbelt
socket: /private/var/run/refexec/refexec.sock
image: docker.io/library/busybox:1.36.1
workspace:
  store: agenthof-work
store_root: /private/var/agenthof/stores
pid_dir: /private/var/agenthof/pids
timeout: 2m
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: []
`
	cfg, err := parseConfig([]byte(y))
	if err != nil {
		t.Fatalf("parseConfig must accept it (the factory owns key consumption): %v", err)
	}
	_, err = selectConfiner(cfg)
	if !errors.Is(err, confiner.ErrUnconsumedKeys) || !strings.Contains(err.Error(), "image") {
		t.Fatalf("selectConfiner err = %v, want ErrUnconsumedKeys naming image", err)
	}
}

func TestStartupRefusesOnProbeOrReapFailure(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	// A short temp root keeps the socket path inside sun_path's limit.
	newCfg := func(t *testing.T) execConfig {
		t.Helper()
		dir, err := os.MkdirTemp("", "rx")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		return execConfig{Socket: filepath.Join(dir, "r.sock"), Store: "work", MaxCompartments: 1}
	}

	t.Run("probe failure", func(t *testing.T) {
		cfg := newCfg(t)
		fake := confinertest.New(t.TempDir())
		fake.ProbeErr = errors.New("engine down")
		r, ln, err := startup(cfg, logger, fake)
		if err == nil || !strings.Contains(err.Error(), "engine down") {
			t.Fatalf("startup err = %v, want the probe failure", err)
		}
		if r != nil || ln != nil {
			t.Fatalf("a failed probe must yield no runner and no listener, got %v, %v", r, ln)
		}
		if _, statErr := os.Stat(cfg.Socket); !os.IsNotExist(statErr) {
			t.Fatalf("the socket must not exist after a failed probe: %v", statErr)
		}
		if ops := fake.OpsSnapshot(); !reflect.DeepEqual(ops, []string{"probe"}) {
			t.Fatalf("ops = %v, want only the probe (no reap once the probe fails)", ops)
		}
	})

	t.Run("reap failure", func(t *testing.T) {
		cfg := newCfg(t)
		fake := confinertest.New(t.TempDir())
		fake.ReapErr = errors.New("cannot list")
		r, ln, err := startup(cfg, logger, fake)
		if err == nil || !strings.Contains(err.Error(), "cannot list") {
			t.Fatalf("startup err = %v, want the reap failure", err)
		}
		if r != nil || ln != nil {
			t.Fatalf("a failed reap must yield no runner and no listener, got %v, %v", r, ln)
		}
		if _, statErr := os.Stat(cfg.Socket); !os.IsNotExist(statErr) {
			t.Fatalf("the socket must not exist after a failed reap: %v", statErr)
		}
	})

	t.Run("success probes, reaps, then listens", func(t *testing.T) {
		cfg := newCfg(t)
		fake := confinertest.New(t.TempDir())
		r, ln, err := startup(cfg, logger, fake)
		if err != nil {
			t.Fatalf("startup: %v", err)
		}
		defer func() { _ = ln.Close() }()
		if r == nil {
			t.Fatal("no runner")
		}
		if _, ok := ln.(*net.UnixListener); !ok {
			t.Fatalf("listener is %T, want a Unix listener", ln)
		}
		ops := fake.OpsSnapshot()
		if len(ops) < 2 || ops[0] != "probe" || ops[1] != "reap refexec-" {
			t.Fatalf("ops = %v, want to begin probe, reap refexec-", ops)
		}
	})
}
