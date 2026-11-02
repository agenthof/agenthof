package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/confiner/confinertest"
)

// rejectingFake is a confiner whose ValidateProgram refuses one program, so a
// test can prove startup asks the backend about every image it will launch.
type rejectingFake struct {
	*confinertest.Fake
	reject string
}

func (f rejectingFake) ValidateProgram(program string) error {
	if program == f.reject {
		return errors.New("not a program this backend can run")
	}
	return nil
}

func startupConfig(t *testing.T, images map[string]string) spawnConfig {
	t.Helper()
	cfg := testConfig(t, images)
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o700); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// notStarted fails the test if startup got as far as preparing spawn_root or
// binding the supervisor socket.
func notStarted(t *testing.T, cfg spawnConfig) {
	t.Helper()
	if _, err := os.Lstat(cfg.Socket); err == nil {
		t.Errorf("the supervisor socket exists: startup listened despite refusing")
	}
	if _, err := os.Lstat(cfg.SpawnRoot); err == nil {
		t.Errorf("spawn_root exists: startup went on to serve despite refusing")
	}
}

func TestMainValidatesEveryImageBehindTheSeam(t *testing.T) {
	cfg := startupConfig(t, map[string]string{"good": "/ok/program", "worker": "bad"})
	fake := rejectingFake{Fake: confinertest.New(t.TempDir()), reject: "bad"}
	var logs bytes.Buffer

	if code := startup(cfg, slog.New(slog.NewTextHandler(&logs, nil)), fake); code != 1 {
		t.Fatalf("startup = %d, want 1\n%s", code, logs.String())
	}
	out := logs.String()
	if !strings.Contains(out, "worker") || strings.Contains(out, "good") {
		t.Fatalf("the refusal must name exactly the agent whose image is refused (worker):\n%s", out)
	}
	if ops := fake.OpsSnapshot(); len(ops) != 1 || ops[0] != "probe" {
		t.Fatalf("ops = %v, want the probe first and nothing after the refusal", ops)
	}
	notStarted(t, cfg)
}

func TestMainProbeFailureRefusesBeforeAnythingElse(t *testing.T) {
	cfg := startupConfig(t, map[string]string{"worker": "bad"})
	fake := confinertest.New(t.TempDir())
	fake.ProbeErr = errors.New("podman is not usable")
	var logs bytes.Buffer

	if code := startup(cfg, slog.New(slog.NewTextHandler(&logs, nil)), fake); code != 1 {
		t.Fatalf("startup = %d, want 1\n%s", code, logs.String())
	}
	if !strings.Contains(logs.String(), "podman is not usable") {
		t.Fatalf("the probe error is not reported:\n%s", logs.String())
	}
	if ops := fake.OpsSnapshot(); len(ops) != 1 || ops[0] != "probe" {
		t.Fatalf("ops = %v, want only the probe", ops)
	}
	notStarted(t, cfg)
}

// prepareSpawnRoot creates spawn_root owner-only and then vets its
// filesystem. A native directory passes; a bridged one cannot be mounted in a
// unit test, so the refusal itself is covered by the refrunner classifier
// tests, and serve's use of this function by the reap-ordering test below.
func TestPrepareSpawnRootCreatesAnOwnerOnlyDirOnANativeFS(t *testing.T) {
	root := filepath.Join(t.TempDir(), "a", "children")
	if err := prepareSpawnRoot(root); err != nil {
		t.Fatalf("prepareSpawnRoot on a native directory: %v", err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("spawn_root = %v, want a 0700 directory", fi.Mode())
	}
}

// The Seatbelt backend refuses a Launch or CreateStore name that is not a
// legal store name, so every name the supervisor mints must be one: a run id
// and an agent name are both admitted only as nameRE, and the prefix starts
// with a letter.
func TestMintedNamesAreValidStoreNames(t *testing.T) {
	s := newSupervisor(testConfig(t, map[string]string{"a.b_c-d": "/ok"}), nil, confinertest.New(t.TempDir()))
	for _, id := range []string{"r-0a0b0c0d", "r-6e7bc558e35e3553", "A", "9", "x.y_z-1"} {
		set := s.newSet(id, []string{"a.b_c-d"}, map[string]string{"a.b_c-d": "/ok"})
		for _, name := range []string{set.store, compartmentName(id, "a.b_c-d")} {
			if !confiner.ValidStoreName(name) {
				t.Errorf("minted name %q is not a legal store name", name)
			}
		}
	}
}

// The tier the config names reaches the factory with the keys as decoded; a
// backend that does not consume one is refused there, not ignored here.
func TestSelectConfinerHandsConfigToFactory(t *testing.T) {
	cfg := startupConfig(t, map[string]string{"worker": "/ok/program"})
	cfg.Confiner = confiner.TierPodman
	cfg.Keys = confiner.Keys{Image: "example.test/exec:1", StoreRoot: "/s"}
	if _, err := selectConfiner(cfg, slog.New(slog.DiscardHandler)); !errors.Is(err, confiner.ErrUnconsumedKeys) {
		t.Fatalf("a Seatbelt key under podman: err = %v, want ErrUnconsumedKeys", err)
	}
}
