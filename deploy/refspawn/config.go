package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// fileConfig is the YAML shape. Pointers distinguish an OMITTED block from
// an empty one: a missing env_allow is rejected, never read as "nothing".
type fileConfig struct {
	Socket          string            `yaml:"socket"`
	SpawnRoot       string            `yaml:"spawn_root"`
	Images          map[string]string `yaml:"images"`
	Timeout         string            `yaml:"timeout"`
	ReadyTimeout    string            `yaml:"ready_timeout"`
	Limits          *fileLimits       `yaml:"limits"`
	MaxCompartments int               `yaml:"max_compartments"`
	Refexec         *struct {
		Command         []string    `yaml:"command"`
		Image           string      `yaml:"image"`
		Timeout         string      `yaml:"timeout"`
		Limits          *fileLimits `yaml:"limits"`
		MaxCompartments int         `yaml:"max_compartments"`
		EnvAllow        *[]string   `yaml:"env_allow"`
	} `yaml:"refexec"`
}

type fileLimits struct {
	Memory string `yaml:"memory"`
	CPUs   string `yaml:"cpus"`
	PIDs   int    `yaml:"pids"`
}

// limits are podman's cgroup caps for one compartment.
type limits struct {
	Memory string // podman --memory
	CPUs   string // podman --cpus
	PIDs   int    // podman --pids-limit
}

// refexecConfig is what refspawn renders into each child's refexec config:
// the per-child socket and volume are added at provision time.
type refexecConfig struct {
	Command         []string      // argv prefix of the refexec host process; "-config <file>" is appended
	Image           string        // the image every exec compartment runs
	Timeout         time.Duration // refexec's podman --timeout backstop
	Limits          limits
	MaxCompartments int      // the child's concurrent exec compartments (refexec's compartments.max)
	EnvAllow        []string // never nil after a successful parse
}

// spawnConfig is the validated configuration refspawn runs on.
type spawnConfig struct {
	Socket          string            // absolute Unix socket path; its directory is the access gate
	SpawnRoot       string            // per-child directories live here: <root>/<id> (mounted) and <root>/<id>-exec (never mounted)
	Images          map[string]string // agent name -> the image its compartment runs; an agent not listed cannot be spawned
	Timeout         time.Duration     // podman --timeout for every agent compartment; size it at or above agenthof's step_timeout
	ReadyTimeout    time.Duration     // how long a child's sockets may take to become dialable before the set is torn down
	Limits          limits
	MaxCompartments int // agent compartments across every live child; a set that will not fit is refused whole, never queued
	Refexec         refexecConfig
}

var (
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)     // a podman container / volume name, and so an agent name and a child run id
	imageRE   = regexp.MustCompile(`^[A-Za-z0-9/][A-Za-z0-9._/:@-]*$`) // an image reference; a leading / lets the test stub name a program
	memoryRE  = regexp.MustCompile(`^[0-9]+[bkmg]?$`)
	cpusRE    = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

func loadConfig(path string) (spawnConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return spawnConfig{}, fmt.Errorf("refspawn config: %w", err)
	}
	return parseConfig(data)
}

// parseConfig decodes and validates. Every key is required and unknown keys
// are rejected, so a typo cannot silently widen anything. All problems are
// reported together; no error echoes a rejected value.
func parseConfig(data []byte) (spawnConfig, error) {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return spawnConfig{}, fmt.Errorf("refspawn config: %w", err)
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	cfg := spawnConfig{Socket: fc.Socket, SpawnRoot: fc.SpawnRoot, Images: map[string]string{}}

	if !filepath.IsAbs(fc.Socket) {
		fail("socket must be an absolute Unix socket path")
	}
	if !filepath.IsAbs(fc.SpawnRoot) {
		fail("spawn_root must be an absolute directory path")
	} else if filepath.IsAbs(fc.Socket) && insideDir(filepath.Dir(fc.Socket), fc.SpawnRoot) {
		fail("socket must not be under spawn_root: child directories there are mounted into compartments")
	}
	if len(fc.Images) == 0 {
		fail("images is required: a map of agent name to the image its compartment runs")
	}
	for agent, image := range fc.Images {
		switch {
		case !nameRE.MatchString(agent):
			fail("images key is not an agent name usable as a container name")
		case !imageRE.MatchString(image):
			fail("images value for one agent is not an image reference")
		default:
			cfg.Images[agent] = image
		}
	}
	cfg.Timeout = parseDuration("timeout", fc.Timeout, fail)
	cfg.ReadyTimeout = parseDuration("ready_timeout", fc.ReadyTimeout, fail)
	cfg.Limits = parseLimits("limits", fc.Limits, fail)
	if fc.MaxCompartments <= 0 {
		fail("max_compartments must be a positive cap on agent compartments across children")
	}
	cfg.MaxCompartments = fc.MaxCompartments
	if fc.Refexec == nil {
		fail("refexec is required (command, image, timeout, limits, max_compartments, env_allow)")
	} else {
		rx := fc.Refexec
		if len(rx.Command) == 0 || rx.Command[0] == "" {
			fail("refexec.command is required: the refexec program (an argv prefix; -config is appended)")
		}
		switch {
		case rx.Image == "":
			fail("refexec.image is required: the image every exec compartment runs")
		case !imageRE.MatchString(rx.Image):
			fail("refexec.image must be an image reference (registry/name:tag or @digest), nothing else")
		}
		cfg.Refexec = refexecConfig{Command: rx.Command, Image: rx.Image,
			Timeout: parseDuration("refexec.timeout", rx.Timeout, fail), Limits: parseLimits("refexec.limits", rx.Limits, fail)}
		if rx.MaxCompartments <= 0 {
			fail("refexec.max_compartments must be a positive concurrency cap")
		}
		cfg.Refexec.MaxCompartments = rx.MaxCompartments
		if rx.EnvAllow == nil {
			fail("refexec.env_allow is required; [] passes nothing through")
		} else {
			cfg.Refexec.EnvAllow = []string{}
			for i, name := range *rx.EnvAllow {
				if !envNameRE.MatchString(name) {
					fail("env_allow[%d] is not an environment variable name", i)
					continue
				}
				cfg.Refexec.EnvAllow = append(cfg.Refexec.EnvAllow, name)
			}
		}
	}
	if len(errs) > 0 {
		return spawnConfig{}, fmt.Errorf("refspawn config: %w", errors.Join(errs...))
	}
	return cfg, nil
}

func parseDuration(key, raw string, fail func(string, ...any)) time.Duration {
	if raw == "" {
		fail("%s is required (a duration such as 10m)", key)
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < time.Second {
		fail("%s must be a positive duration of at least 1s, such as 10m", key)
		return 0
	}
	return d
}

func parseLimits(key string, fl *fileLimits, fail func(string, ...any)) limits {
	if fl == nil {
		fail("%s is required (memory, cpus, pids)", key)
		return limits{}
	}
	if !memoryRE.MatchString(fl.Memory) {
		fail("%s.memory must be a podman memory limit such as 256m", key)
	}
	if !cpusRE.MatchString(fl.CPUs) {
		fail("%s.cpus must be a number such as 1 or 0.5", key)
	}
	if fl.PIDs <= 0 {
		fail("%s.pids must be a positive pid cap", key)
	}
	return limits{Memory: fl.Memory, CPUs: fl.CPUs, PIDs: fl.PIDs}
}

// insideDir reports whether dir is parent itself or anywhere below it.
func insideDir(dir, parent string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(dir))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// checkLines is what `refspawn -check` prints: the socket (so a launcher
// can prepare its 0700 directory) and the spawn root.
func (c spawnConfig) checkLines() string {
	return fmt.Sprintf("socket=%s\nspawn_root=%s\n", c.Socket, c.SpawnRoot)
}
