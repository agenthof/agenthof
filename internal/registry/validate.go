package registry

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/agenthof/agenthof/internal/config"
)

type ValidationError struct{ File, Entity, Code, Msg string }

func (e ValidationError) Error() string { return fmt.Sprintf("%s: %s: %s", e.File, e.Entity, e.Msg) }

func Validate(cfg config.Config) []ValidationError {
	var errs []ValidationError
	add := func(file, entity, code, msg string) {
		errs = append(errs, ValidationError{File: file, Entity: entity, Code: code, Msg: msg})
	}

	agents := map[string]config.AgentDef{}
	for _, a := range cfg.Agents {
		if a.Name == "" {
			add(a.SourceFile, "(agent)", "missing-name", "agent has no name")
			continue
		}
		if _, dup := agents[a.Name]; dup {
			add(a.SourceFile, a.Name, "duplicate-name", "agent name already defined")
			continue
		}
		agents[a.Name] = a

		// Validate execution tier and endpoint. "contained" is rejected: the
		// tier was removed, and every agent is fronted.
		if a.Execution == "contained" {
			add(a.SourceFile, a.Name, "bad-execution",
				"execution \"contained\" was removed; set execution: fronted and an endpoint")
		} else if a.Execution != "" && a.Execution != "fronted" {
			add(a.SourceFile, a.Name, "bad-execution",
				fmt.Sprintf("execution %q must be \"fronted\"", a.Execution))
		}

		effectiveExec := a.EffectiveExecution()
		if a.Endpoint == "" {
			msg := "fronted agents must have an endpoint"
			if a.Execution == "" {
				msg = "agents are fronted and must declare an endpoint (the contained tier was removed)"
			}
			add(a.SourceFile, a.Name, "fronted-needs-endpoint", msg)
		} else if !validAgentEndpoint(a.Endpoint) {
			add(a.SourceFile, a.Name, "bad-endpoint",
				"endpoint must be https, loopback http, or unix:// socket")
		}

		// Tools are gateway tool-resource ids. Each must be a declared
		// gateway.tools resource.
		for _, t := range a.Tools {
			if _, ok := cfg.Gateway.Tools[t]; !ok {
				add(a.SourceFile, a.Name, "unknown-tool",
					fmt.Sprintf("agent references tool %q, which is not a declared gateway tool resource", t))
			}
		}

		if a.Exec.Declared() {
			if effectiveExec != "fronted" {
				add(a.SourceFile, a.Name, "bad-exec-config", "exec is only valid on fronted agents")
			}
			if a.Exec.Mode != "attested" {
				add(a.SourceFile, a.Name, "bad-exec-config",
					fmt.Sprintf("exec.mode %q is not implemented (only attested)", a.Exec.Mode))
			}
			if len(a.Exec.Allow) == 0 {
				add(a.SourceFile, a.Name, "bad-exec-config", "exec.mode is set but exec.allow is empty")
			}
			for _, e := range a.Exec.Allow {
				if e.Exe == "" {
					add(a.SourceFile, a.Name, "bad-exec-config", "exec.allow entry has an empty exe")
				}
			}
		}
	}

	for id, r := range cfg.Gateway.Tools {
		if r.Kind != "mcp" {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q must set kind: mcp", id))
		}
		if !validSecureEndpoint(r.URL) {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: url must be set and https (or loopback http)", id))
		}
		if r.CredentialSource != "static_env" {
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: credential_source %q is not implemented (only static_env)", id, r.CredentialSource))
		}
		switch r.GrantType {
		case "":
			if r.TokenEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: token_env is required for the direct-bearer grant", id))
			}
		case "client_credentials":
			if r.ClientAuth != "client_secret_basic" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_auth %q is not implemented (only client_secret_basic)", id, r.ClientAuth))
			}
			if r.Issuer == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: issuer is required for client_credentials", id))
			}
			if r.ClientIDEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_id_env is required for client_credentials", id))
			}
			if r.ClientSecretEnv == "" {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: client_secret_env is required for client_credentials", id))
			}
			if !validSecureEndpoint(r.TokenEndpoint) {
				add("gateway.yaml", id, "bad-tool-resource",
					fmt.Sprintf("tool resource %q: token_endpoint must be set and https (or loopback http)", id))
			}
		default:
			add("gateway.yaml", id, "bad-tool-resource",
				fmt.Sprintf("tool resource %q: grant_type %q is not implemented (only client_credentials)", id, r.GrantType))
		}
	}

	workflows := map[string]config.WorkflowDef{}
	for _, w := range cfg.Workflows {
		if w.Name == "" {
			add(w.SourceFile, "(workflow)", "missing-name", "workflow has no name")
			continue
		}
		if _, dup := workflows[w.Name]; dup {
			add(w.SourceFile, w.Name, "duplicate-name", "workflow name already defined")
			continue
		}
		workflows[w.Name] = w
		if len(w.Steps) == 0 {
			add(w.SourceFile, w.Name, "no-steps", "workflow has no steps")
			continue
		}
		index := map[string]int{}
		for i, s := range w.Steps {
			index[s.Name] = i
		}
		for i, s := range w.Steps {
			if a, ok := agents[s.Agent]; !ok {
				add(w.SourceFile, w.Name, "dangling-agent-ref",
					fmt.Sprintf("step %q references agent %q, which does not exist", s.Name, s.Agent))
			} else if !a.IsEnabled() {
				add(w.SourceFile, w.Name, "disabled-agent-ref",
					fmt.Sprintf("workflow %q depends on agent %q, which is disabled in the registry", w.Name, s.Agent))
			}
			if s.MaxBounces < 0 || s.MaxBounces > 10 {
				add(w.SourceFile, w.Name, "bad-bounces",
					fmt.Sprintf("step %q: max_bounces must be between 0 and 10", s.Name))
			}
			if s.OnSuccess != "" {
				last := i == len(w.Steps)-1
				if !last || s.OnSuccess != "finish" {
					j, ok := index[s.OnSuccess]
					if !ok || j != i+1 {
						add(w.SourceFile, w.Name, "bad-graph",
							fmt.Sprintf("step %q: on_success must be the next step (or \"finish\" on the last step); branching is not yet supported", s.Name))
					}
				}
			}
			if s.OnFailure != "" {
				j, ok := index[s.OnFailure]
				if !ok || j >= i {
					add(w.SourceFile, w.Name, "bad-graph",
						fmt.Sprintf("step %q: on_failure must name an earlier step; forward or unknown targets are not supported", s.Name))
				}
			}
		}
	}

	roleNames := map[string]bool{}
	for _, r := range cfg.Roles {
		if r.Name == "" {
			add(r.SourceFile, "(role)", "missing-name", "role has no name")
			continue
		}
		if roleNames[r.Name] {
			add(r.SourceFile, r.Name, "duplicate-name", "role name already defined")
			continue
		}
		roleNames[r.Name] = true
		if len(r.Workflows) == 0 {
			add(r.SourceFile, r.Name, "no-workflows", "role owns no workflows")
		}
		if len(r.AllowedGroups) == 0 {
			add(r.SourceFile, r.Name, "no-access-floor",
				`role has no allowed_groups; list real groups or ["*"] to declare it public`)
		}
		for _, wf := range r.Workflows {
			if _, ok := workflows[wf]; !ok {
				add(r.SourceFile, r.Name, "dangling-workflow-ref",
					fmt.Sprintf("role references workflow %q, which does not exist", wf))
			}
		}
	}
	return errs
}

// validSecureEndpoint requires an https URL, or http only to a loopback host
// (for tests and local development). It guards any endpoint that receives a
// gateway-injected credential — both a client_credentials token endpoint and
// a tool resource's upstream url. A credential over plaintext http to a
// remote host is exactly the leak Article I guards against, so it is
// rejected at apply time.
func validSecureEndpoint(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// validAgentEndpoint is validSecureEndpoint plus a unix:// socket form, for the
// fronted agent endpoint only. A refbox agent is reached over a bind-mounted
// Unix socket (no network); tool/token endpoints keep the stricter
// validSecureEndpoint rule since they receive a remote credential.
func validAgentEndpoint(raw string) bool {
	if path, ok := strings.CutPrefix(raw, config.UnixScheme); ok {
		// The wire contract pins unix://<absolute-socket-path>. A relative path
		// would resolve against the process working directory at dial time —
		// silently not the socket the operator meant — so reject it here
		// (config is law). IsAbs also rejects the empty path.
		return filepath.IsAbs(path)
	}
	return validSecureEndpoint(raw)
}
