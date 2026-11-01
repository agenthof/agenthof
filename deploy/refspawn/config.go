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

// fileConfig is the YAML shape. Pointers distinguish an OMITTED block from
// an empty one: a missing env_allow is rejected, never read as "nothing".
// The backend keys (confiner, store_root, pid_dir, deny_read,
// shared_host_scratch, refexec.image) are all optional here; which of them
// the selected confiner consumes is the confiner factory's decision, not
// this file's.
type fileConfig struct {
	Socket            string            `yaml:"socket"`
	SpawnRoot         string            `yaml:"spawn_root"`
	Confiner          string            `yaml:"confiner"`
	StoreRoot         string            `yaml:"store_root"`
	PIDDir            string            `yaml:"pid_dir"`
	DenyRead          *[]string         `yaml:"deny_read"`
	SharedHostScratch bool              `yaml:"shared_host_scratch"`
	Images            map[string]string `yaml:"images"`
	Timeout           string            `yaml:"timeout"`
	ReadyTimeout      string            `yaml:"ready_timeout"`
	Limits            *fileLimits       `yaml:"limits"`
	MaxCompartments   int               `yaml:"max_compartments"`
	Refexec           *struct {
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

// limits are the resource caps for one compartment, in the confiner's format;
// whether a backend enforces them is per tier.
type limits struct {
	Memory string // a memory cap such as 256m
	CPUs   string // a cpu count such as 1 or 0.5
	PIDs   int    // a pid cap
}

// refexecConfig is what refspawn renders into each child's refexec config:
// the per-child socket and workspace store, and the backend keys (spawnConfig.Keys),
// are added at provision time.
type refexecConfig struct {
	Command         []string      // argv prefix of the refexec host process; "-config <file>" is appended
	Image           string        // the image every exec compartment runs; podman's key, empty under a backend that has none
	Timeout         time.Duration // refexec's per-compartment deadline, the backstop to the gateway's own
	Limits          limits
	MaxCompartments int      // the child's concurrent exec compartments (refexec's compartments.max)
	EnvAllow        []string // never nil after a successful parse
}

// spawnConfig is the validated configuration refspawn runs on.
type spawnConfig struct {
	Socket          string            // absolute Unix socket path; its directory is the access gate
	SpawnRoot       string            // per-child directories live here: <root>/<id> (mounted) and <root>/<id>-exec (never mounted)
	Confiner        confiner.Tier     // the confinement backend; "" selects the OS default
	Keys            confiner.Keys     // the backend-specific keys, handed to the factory as decoded
	Images          map[string]string // agent name -> the program its compartment runs (podman: an image); an agent not listed cannot be spawned
	Timeout         time.Duration     // the deadline for every agent compartment; size it at or above agenthof's step_timeout
	ReadyTimeout    time.Duration     // how long a child's sockets may take to become dialable before the set is torn down
	Limits          limits
	MaxCompartments int // agent compartments across every live child; a set that will not fit is refused whole, never queued
	Refexec         refexecConfig
}

const (
	// runIDLen is the length of a gateway-minted child run id.
	runIDLen = 18
	// gatewaySockLen is the length of the socket name the child's gateway
	// binds under <spawn_root>/<run id>/: gw-<run id>-<16 hex>.sock.
	gatewaySockLen = len("gw-") + runIDLen + len("-") + 16 + len(".sock")
)

var (
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)     // a compartment / store name (confiner.ValidStoreName's shape), and so an agent name and a child run id
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

// parseConfig decodes and validates for the host OS. See parseConfigOn.
func parseConfig(data []byte) (spawnConfig, error) { return parseConfigOn(data, runtime.GOOS) }

// parseConfigOn decodes and validates for goos. The checks are
// backend-neutral: which keys the selected confiner consumes, and whether it
// can run each images value, is the factory's job (Select and
// ValidateProgram, run after this in main). Every other key is required and
// unknown keys are rejected, so a typo cannot silently widen anything. All
// problems are reported together; no error echoes a rejected value.
func parseConfigOn(data []byte, goos string) (spawnConfig, error) {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return spawnConfig{}, fmt.Errorf("refspawn config: %w", err)
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	cfg := spawnConfig{
		Socket: fc.Socket, SpawnRoot: fc.SpawnRoot, Images: map[string]string{}, Confiner: confiner.Tier(fc.Confiner),
		Keys: confiner.Keys{StoreRoot: fc.StoreRoot, PIDDir: fc.PIDDir, SharedHostScratch: fc.SharedHostScratch},
	}
	if fc.DenyRead != nil {
		cfg.Keys.DenyRead = *fc.DenyRead
	}
	if fc.Refexec != nil {
		cfg.Keys.Image = fc.Refexec.Image
	}
	if fc.Confiner != "" && !confiner.ValidToken(fc.Confiner) {
		fail("confiner must be a lowercase backend name")
	}

	if !filepath.IsAbs(fc.Socket) {
		fail("socket must be an absolute Unix socket path")
	} else if err := confiner.CheckSunPath(fc.Socket, goos); err != nil {
		fail("socket: %v", err)
	}
	if !filepath.IsAbs(fc.SpawnRoot) {
		fail("spawn_root must be an absolute directory path")
	} else if filepath.IsAbs(fc.Socket) && insideDir(filepath.Dir(fc.Socket), fc.SpawnRoot) {
		fail("socket must not be under spawn_root: child directories there are mounted into compartments")
	}
	if len(fc.Images) == 0 {
		fail("images is required: a map of agent name to the image its compartment runs")
	}
	longestAgent := ""
	for agent, program := range fc.Images {
		switch {
		case !nameRE.MatchString(agent):
			fail("images key is not an agent name usable as a container name")
		case program == "":
			fail("images value for one agent is empty")
		default:
			cfg.Images[agent] = program
			if len(agent) > len(longestAgent) {
				longestAgent = agent
			}
		}
	}
	// The sockets refspawn derives for a child live under
	// <spawn_root>/<run id>/: <agent>.sock for each agent and the gateway's
	// gw-<run id>-<16 hex>.sock. Check the longer of the two now so a root
	// that cannot bind them fails here, not at the first provision. The check
	// assumes a gateway-minted (runIDLen-char) id: a hand-sent longer
	// child_run_id fails at the agent's bind and is recorded as a provision
	// failure.
	if filepath.IsAbs(fc.SpawnRoot) {
		derived := max(len(longestAgent)+len(".sock"), gatewaySockLen)
		path := fc.SpawnRoot + "/" + strings.Repeat("i", runIDLen) + "/" + strings.Repeat("s", derived)
		if err := confiner.CheckSunPath(path, goos); err != nil {
			fail("spawn_root: a child's socket path would not fit: %v", err)
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
		fail("refexec is required (command, timeout, limits, max_compartments, env_allow)")
	} else {
		rx := fc.Refexec
		if len(rx.Command) == 0 || rx.Command[0] == "" {
			fail("refexec.command is required: the refexec program (an argv prefix; -config is appended)")
		}
		// Optional: it is podman's key. The factory refuses a podman config
		// without it and a Seatbelt config with it.
		if rx.Image != "" && !imageRE.MatchString(rx.Image) {
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
		fail("%s.memory must be a memory limit such as 256m", key)
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
