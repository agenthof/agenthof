package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Credential materialization modes (spec: config is law; omission rejected).
const (
	matEnvAtSpawn        = "env-at-spawn"        // static credential: set at spawn, held for the session
	matRespawnOnRotation = "respawn-on-rotation" // rotating credential: respawn at the next call boundary when the bearer changes
	matEgressBroker      = "egress-broker"       // reserved: refbridge would relay the token outbound itself
)

// fileConfig is the YAML shape. Pointers distinguish an OMITTED key from an
// empty one: a missing allowlist is rejected, never read as "everything" or
// "nothing".
type fileConfig struct {
	Socket     string   `yaml:"socket"`
	Command    []string `yaml:"command"`
	Credential *struct {
		Env             string `yaml:"env"`
		Materialization string `yaml:"materialization"`
	} `yaml:"credential"`
	EnvPassthrough *[]string `yaml:"env_passthrough"`
	Egress         *struct {
		Allow *[]string `yaml:"allow"`
	} `yaml:"egress"`
	Sessions *struct {
		Max         int    `yaml:"max"`
		IdleTimeout string `yaml:"idle_timeout"`
		MaxLifetime string `yaml:"max_lifetime"`
	} `yaml:"sessions"`
}

// bridgeConfig is the validated configuration the bridge runs on. Slices are
// never nil after a successful parse.
type bridgeConfig struct {
	Socket          string        // absolute Unix socket path; its directory is the access gate
	Command         []string      // the stdio MCP server's argv
	CredentialEnv   string        // the variable the per-call credential is materialized into
	Materialization string        // matEnvAtSpawn | matRespawnOnRotation
	EnvPassthrough  []string      // the ONLY variables copied from refbridge's own environment
	EgressAllow     []string      // hosts the payload may reach; empty = no network at all
	MaxSessions     int           // concurrent MCP sessions (= subprocesses) this bridge will hold
	IdleTimeout     time.Duration // a session with no request for this long is ended (the orphan reaper); must exceed Agenthof's step timeout
	MaxLifetime     time.Duration // a session is ended after this long regardless
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func loadConfig(path string) (bridgeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bridgeConfig{}, fmt.Errorf("refbridge config: %w", err)
	}
	return parseConfig(data)
}

// parseConfig decodes and validates. Every key is required and unknown keys
// are rejected, so a typo cannot silently widen anything. All problems are
// reported together.
func parseConfig(data []byte) (bridgeConfig, error) {
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return bridgeConfig{}, fmt.Errorf("refbridge config: %w", err)
	}

	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	cfg := bridgeConfig{Socket: fc.Socket, Command: fc.Command}

	if !filepath.IsAbs(fc.Socket) {
		fail("socket must be an absolute Unix socket path")
	}
	if len(fc.Command) == 0 || fc.Command[0] == "" {
		fail("command must name the stdio MCP server to run (argv, non-empty)")
	}
	if fc.Credential == nil {
		fail("credential is required (env + materialization)")
	} else {
		if !envNameRE.MatchString(fc.Credential.Env) {
			fail("credential.env must name the environment variable to materialize the credential into")
		}
		switch fc.Credential.Materialization {
		case matEnvAtSpawn, matRespawnOnRotation:
		case "":
			fail("credential.materialization is required: %s or %s", matEnvAtSpawn, matRespawnOnRotation)
		case matEgressBroker:
			fail("credential.materialization %s is reserved and not implemented", matEgressBroker)
		default:
			fail("credential.materialization %q is not one of %s, %s", fc.Credential.Materialization, matEnvAtSpawn, matRespawnOnRotation)
		}
		cfg.CredentialEnv = fc.Credential.Env
		cfg.Materialization = fc.Credential.Materialization
	}
	if fc.EnvPassthrough == nil {
		fail("env_passthrough is required; [] passes nothing through (the subprocess never inherits refbridge's environment)")
	} else {
		cfg.EnvPassthrough = []string{}
		for i, name := range *fc.EnvPassthrough {
			if name == "inherit" {
				fail(`env_passthrough takes an explicit list; "inherit" is not supported`)
				continue
			}
			if !envNameRE.MatchString(name) {
				fail("env_passthrough[%d] is not an environment variable name", i)
				continue
			}
			if fc.Credential != nil && name == fc.Credential.Env {
				fail("credential.env %s must not also be in env_passthrough", name)
				continue
			}
			cfg.EnvPassthrough = append(cfg.EnvPassthrough, name)
		}
	}
	if fc.Egress == nil || fc.Egress.Allow == nil {
		fail("egress.allow is required; [] means no network at all")
	} else {
		cfg.EgressAllow = []string{}
		for i, host := range *fc.Egress.Allow {
			if !validEgressEntry(host) {
				fail("egress.allow[%d] must be a host or host:port", i)
				continue
			}
			cfg.EgressAllow = append(cfg.EgressAllow, host)
		}
	}
	if fc.Sessions == nil {
		fail("sessions is required (max, idle_timeout, max_lifetime)")
	} else {
		if fc.Sessions.Max <= 0 {
			fail("sessions.max must be a positive concurrency cap")
		}
		cfg.MaxSessions = fc.Sessions.Max
		cfg.IdleTimeout = parseDuration("sessions.idle_timeout", fc.Sessions.IdleTimeout, fail)
		cfg.MaxLifetime = parseDuration("sessions.max_lifetime", fc.Sessions.MaxLifetime, fail)
	}
	if len(errs) > 0 {
		return bridgeConfig{}, fmt.Errorf("refbridge config: %w", errors.Join(errs...))
	}
	return cfg, nil
}

// validEgressEntry accepts a bare host or host:port. Commas are rejected
// because egressLine joins entries with them; @ and = are credential shapes.
func validEgressEntry(entry string) bool {
	if entry == "" || strings.ContainsAny(entry, " \t/,@=") {
		return false
	}
	if !strings.Contains(entry, ":") {
		return true
	}
	host, port, err := net.SplitHostPort(entry)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0
}

func parseDuration(key, raw string, fail func(string, ...any)) time.Duration {
	if raw == "" {
		fail("%s is required (a duration such as 10m)", key)
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		fail("%s must be a positive duration such as 10m, got %q", key, raw)
		return 0
	}
	return d
}

// egressLine is what `refbridge -check` prints: the run recipe reads it to
// choose the compartment's network mode without parsing YAML itself.
func (c bridgeConfig) egressLine() string {
	if len(c.EgressAllow) == 0 {
		return "egress=none"
	}
	return "egress=" + strings.Join(c.EgressAllow, ",")
}
