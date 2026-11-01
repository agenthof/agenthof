package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

// fileConfig is the YAML shape. Pointers distinguish an OMITTED key from an
// empty one: a missing env_allow is rejected, never read as "nothing". The
// backend keys (image, workspace.path, store_root, pid_dir, deny_read,
// shared_host_scratch) are all optional here; which of them the selected
// confiner consumes is the confiner factory's decision, not this file's.
type fileConfig struct {
	Socket    string `yaml:"socket"`
	Confiner  string `yaml:"confiner"`
	Image     string `yaml:"image"`
	Workspace *struct {
		Store string `yaml:"store"`
		Path  string `yaml:"path"`
	} `yaml:"workspace"`
	StoreRoot         string    `yaml:"store_root"`
	PIDDir            string    `yaml:"pid_dir"`
	DenyRead          *[]string `yaml:"deny_read"`
	SharedHostScratch bool      `yaml:"shared_host_scratch"`
	Timeout           string    `yaml:"timeout"`
	Limits            *struct {
		Memory string `yaml:"memory"`
		CPUs   string `yaml:"cpus"`
		PIDs   int    `yaml:"pids"`
	} `yaml:"limits"`
	Compartments *struct {
		Max int `yaml:"max"`
	} `yaml:"compartments"`
	EnvAllow *[]string `yaml:"env_allow"`
}

// execConfig is the validated configuration refexec runs on. EnvAllow is
// never nil after a successful parse.
type execConfig struct {
	Socket          string          // absolute Unix socket path; its directory is the access gate
	Confiner        confiner.Tier   // the confinement backend; "" selects the OS default
	Store           string          // the workspace store shared with the agent's compartment (workspace.store)
	Keys            confiner.Keys   // the backend-specific keys, handed to the factory as decoded
	Limits          confiner.Limits // per-compartment memory / cpus / pids caps
	Timeout         time.Duration   // the per-compartment deadline; set it to the agents' exec.timeout
	MaxCompartments int             // concurrent compartments; a request past the cap is refused, never queued
	EnvAllow        []string        // the ONLY variable names passed to the command, from refexec's own environment
}

var (
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	imageRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)
	memoryRE  = regexp.MustCompile(`^[0-9]+[bkmg]?$`)
	cpusRE    = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

func loadConfig(path string) (execConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return execConfig{}, fmt.Errorf("refexec config: %w", err)
	}
	return parseConfig(data)
}

// parseConfig decodes and validates for the host OS. See parseConfigOn.
func parseConfig(data []byte) (execConfig, error) { return parseConfigOn(data, runtime.GOOS) }

// parseConfigOn decodes and validates for goos. The checks are backend-neutral:
// which keys the selected confiner consumes is the factory's job (Select
// refuses a key it does not consume). Unknown keys are rejected, so a typo
// cannot silently widen anything. All problems are reported together; no
// error echoes a rejected value.
func parseConfigOn(data []byte, goos string) (execConfig, error) {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return execConfig{}, fmt.Errorf("refexec config: %w", err)
	}

	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	cfg := execConfig{
		Socket: fc.Socket, Confiner: confiner.Tier(fc.Confiner),
		Keys: confiner.Keys{Image: fc.Image, StoreRoot: fc.StoreRoot, PIDDir: fc.PIDDir, SharedHostScratch: fc.SharedHostScratch},
	}

	if fc.Confiner != "" && !confiner.ValidToken(fc.Confiner) {
		fail("confiner must be a lowercase backend name")
	}

	if !filepath.IsAbs(fc.Socket) {
		fail("socket must be an absolute Unix socket path")
	} else if err := confiner.CheckSunPath(fc.Socket, goos); err != nil {
		fail("socket: %v", err)
	}
	if fc.StoreRoot != "" {
		// The Seatbelt backend binds a socket under <store_root>/.scratch/refexec-<16 hex>.
		if err := confiner.CheckSunPath(fc.StoreRoot+"/.scratch/refexec-"+strings.Repeat("x", 16), goos); err != nil {
			fail("store_root: %v", err)
		}
	}
	if fc.Image != "" && !imageRE.MatchString(fc.Image) {
		fail("image must be an image reference (registry/name:tag or @digest), nothing else")
	}
	if fc.Workspace == nil {
		fail("workspace is required (store)")
	} else {
		if !confiner.ValidStoreName(fc.Workspace.Store) {
			fail("workspace.store is required and must be a workspace store name")
		}
		cfg.Store = fc.Workspace.Store
		if fc.Workspace.Path != "" && !filepath.IsAbs(fc.Workspace.Path) {
			fail("workspace.path must be an absolute path inside the compartment")
		}
		cfg.Keys.WorkspacePath = fc.Workspace.Path
	}
	if fc.DenyRead != nil {
		cfg.Keys.DenyRead = *fc.DenyRead
	}
	cfg.Timeout = parseDuration("timeout", fc.Timeout, fail)
	if fc.Limits == nil {
		fail("limits is required (memory, cpus, pids)")
	} else {
		if !memoryRE.MatchString(fc.Limits.Memory) {
			fail("limits.memory must be a memory limit such as 256m")
		}
		if !cpusRE.MatchString(fc.Limits.CPUs) {
			fail("limits.cpus must be a number such as 1 or 0.5")
		}
		if fc.Limits.PIDs <= 0 {
			fail("limits.pids must be a positive pid cap")
		}
		cfg.Limits = confiner.Limits{Memory: fc.Limits.Memory, CPUs: fc.Limits.CPUs, PIDs: fc.Limits.PIDs}
	}
	if fc.Compartments == nil {
		fail("compartments is required (max)")
	} else {
		if fc.Compartments.Max <= 0 {
			fail("compartments.max must be a positive concurrency cap")
		}
		cfg.MaxCompartments = fc.Compartments.Max
	}
	if fc.EnvAllow == nil {
		fail("env_allow is required; [] passes nothing through (the command never inherits refexec's environment)")
	} else {
		cfg.EnvAllow = []string{}
		for i, name := range *fc.EnvAllow {
			if !envNameRE.MatchString(name) {
				fail("env_allow[%d] is not an environment variable name", i)
				continue
			}
			cfg.EnvAllow = append(cfg.EnvAllow, name)
		}
	}
	if len(errs) > 0 {
		return execConfig{}, fmt.Errorf("refexec config: %w", errors.Join(errs...))
	}
	return cfg, nil
}

func parseDuration(key, raw string, fail func(string, ...any)) time.Duration {
	if raw == "" {
		fail("%s is required (a duration such as 2m)", key)
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < time.Second {
		fail("%s must be a positive duration of at least 1s, such as 2m", key)
		return 0
	}
	return d
}

// checkLines is what `refexec -check` prints for the launcher, which reads it
// instead of parsing YAML. The shape follows the backend's Tier, never how the
// Confiner was built: podman names its volume and guest mount point; every
// other backend is host-shaped, so the launcher is told the host directory the
// store lives at.
func checkLines(cfg execConfig, c confiner.Confiner) string {
	if c.Tier() == confiner.TierPodman {
		return fmt.Sprintf("socket=%s\nworkspace=%s:%s\n", cfg.Socket, cfg.Store, c.StorePath(cfg.Store))
	}
	return fmt.Sprintf("socket=%s\nworkspace=%s\nstore_path=%s\n", cfg.Socket, cfg.Store, c.StorePath(cfg.Store))
}
