package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// fileConfig is the YAML shape. Pointers distinguish an OMITTED key from an
// empty one: a missing env_allow is rejected, never read as "nothing".
type fileConfig struct {
	Socket    string `yaml:"socket"`
	Image     string `yaml:"image"`
	Workspace *struct {
		Volume string `yaml:"volume"`
		Path   string `yaml:"path"`
	} `yaml:"workspace"`
	Timeout string `yaml:"timeout"`
	Limits  *struct {
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
	Socket          string        // absolute Unix socket path; its directory is the access gate
	Image           string        // the image every compartment runs; pulled by the operator, never at run time
	WorkspaceVolume string        // the podman volume shared with the agent's compartment
	WorkspacePath   string        // where it is mounted, rw, in every compartment (and the working directory)
	Timeout         time.Duration // podman --timeout backstop; set it to the agents' exec.timeout
	Memory          string        // podman --memory
	CPUs            string        // podman --cpus
	PIDs            int           // podman --pids-limit
	MaxCompartments int           // concurrent compartments; a request past the cap is refused, never queued
	EnvAllow        []string      // the ONLY variable names passed to the command, from refexec's own environment
}

var (
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	imageRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)
	volumeRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
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

// parseConfig decodes and validates. Every key is required and unknown keys
// are rejected, so a typo cannot silently widen anything. All problems are
// reported together; no error echoes a rejected value.
func parseConfig(data []byte) (execConfig, error) {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return execConfig{}, fmt.Errorf("refexec config: %w", err)
	}

	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	cfg := execConfig{Socket: fc.Socket, Image: fc.Image}

	if !filepath.IsAbs(fc.Socket) {
		fail("socket must be an absolute Unix socket path")
	}
	switch {
	case fc.Image == "":
		fail("image is required: the image every compartment runs")
	case !imageRE.MatchString(fc.Image):
		fail("image must be an image reference (registry/name:tag or @digest), nothing else")
	}
	if fc.Workspace == nil {
		fail("workspace is required (volume + path)")
	} else {
		if !volumeRE.MatchString(fc.Workspace.Volume) {
			fail("workspace.volume must be a podman volume name")
		}
		if !filepath.IsAbs(fc.Workspace.Path) {
			fail("workspace.path must be an absolute path inside the compartment")
		}
		cfg.WorkspaceVolume, cfg.WorkspacePath = fc.Workspace.Volume, fc.Workspace.Path
	}
	cfg.Timeout = parseDuration("timeout", fc.Timeout, fail)
	if fc.Limits == nil {
		fail("limits is required (memory, cpus, pids)")
	} else {
		if !memoryRE.MatchString(fc.Limits.Memory) {
			fail("limits.memory must be a podman memory limit such as 256m")
		}
		if !cpusRE.MatchString(fc.Limits.CPUs) {
			fail("limits.cpus must be a number such as 1 or 0.5")
		}
		if fc.Limits.PIDs <= 0 {
			fail("limits.pids must be a positive pid cap")
		}
		cfg.Memory, cfg.CPUs, cfg.PIDs = fc.Limits.Memory, fc.Limits.CPUs, fc.Limits.PIDs
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

// checkLines is what `refexec -check` prints: the launcher reads the socket
// (to prepare its 0700 directory) and the workspace (to create the volume)
// without parsing YAML itself.
func (c execConfig) checkLines() string {
	return fmt.Sprintf("socket=%s\nworkspace=%s:%s\n", c.Socket, c.WorkspaceVolume, c.WorkspacePath)
}
